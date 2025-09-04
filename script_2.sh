#!/bin/bash

# Проверка root
if [ "$(id -u)" != "0" ]; then
    echo "Этот скрипт должен быть запущен от имени root" 1>&2
    exit 1
fi

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Функция проверки ошибок
check_error() {
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ОШИБКА] $1${NC}"
        exit 1
    else
        echo -e "${GREEN}[OK] $1${NC}"
    fi
}

echo -e "${YELLOW}=== ПРИМЕНЕНИЕ ДОПОЛНИТЕЛЬНЫХ НАСТРОЕК БЕЗОПАСНОСТИ ===${NC}"

# 1. Ужесточение правил iptables 
echo -e "${YELLOW}1. Настройка строгого firewall...${NC}"

# Очищаем текущие правила
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Базовые правила
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Разрешение SSH для всех
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Разрешение HTTP/HTTPS для всех
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 8083 -j ACCEPT

# Разрешение Cloudflare IPs
echo -e "${BLUE}Добавление правил для Cloudflare...${NC}"
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
    iptables -A INPUT -p tcp -s "$ip" --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp -s "$ip" --dport 443 -j ACCEPT
done

echo -e "${BLUE}Ограничение доступа к сервисным портам (кроме 22 и 8083)...${NC}"
ALL_SERVICE_PORTS="3000 9090 9100 3100 9080 9191 9091 3306 5432 8080 25 465 587 993 995 143 110 53"
for port in $ALL_SERVICE_PORTS; do
    # Разрешаем доступ с VPN и сервера статистики
    iptables -A INPUT -p tcp -s 188.68.219.28 --dport $port -j ACCEPT
    iptables -A INPUT -p tcp -s 172.235.190.62 --dport $port -j ACCEPT
    # Запрещаем доступ для всех остальных
    iptables -A INPUT -p tcp --dport $port -j DROP
done

# Разрешение DNS UDP только для локальных запросов
iptables -A INPUT -p udp -s 127.0.0.1 --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j DROP

# Защита от атак (повторяем, так как старые правила сброшены)
iptables -N SYN_FLOOD
iptables -A INPUT -p tcp --syn -j SYN_FLOOD
iptables -A SYN_FLOOD -m limit --limit 10/s --limit-burst 25 -j RETURN
iptables -A SYN_FLOOD -j DROP

iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

iptables -N PORT_SCAN
iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j PORT_SCAN
iptables -A PORT_SCAN -m limit --limit 1/s -j RETURN
iptables -A PORT_SCAN -j DROP

# Сохраняем правила
netfilter-persistent save
check_error "Настройка строгого firewall"

# 2. Добавляем недостающие параметры в конфиг Loki для стабильности
echo -e "${YELLOW}2. Улучшение конфигурации Loki...${NC}"

LOKI_CONFIG="/etc/loki/loki-config.yaml"

# Проверяем, есть ли уже эти настройки, чтобы не дублировать
if ! grep -q "http_server_read_timeout" $LOKI_CONFIG; then
    # Вставляем блок с таймаутами после 'grpc_listen_port'
    sed -i '/grpc_listen_port: 9096/a \  http_server_read_timeout: 5m\n  http_server_write_timeout: 5m\n  grpc_server_max_recv_msg_size: 104857600\n  grpc_server_max_send_msg_size: 104857600' $LOKI_CONFIG
fi

if ! grep -q "query_timeout" $LOKI_CONFIG; then
    # Вставляем блок с лимитами в limits_config
    sed -i '/reject_old_samples_max_age: 168h/a \  query_timeout: 5m\n  max_query_length: 168h\n  max_query_parallelism: 32\n  max_streams_matchers_per_query: 1000\n  max_concurrent_tail_requests: 10\n  max_entries_limit_per_query: 5000\n  max_chunks_per_query: 2000000\n  max_query_series: 500' $LOKI_CONFIG
fi

# Перезапускаем Loki для применения изменений
systemctl restart loki
check_error "Обновление конфигурации Loki"

# 3. Обновляем версию Grafana до актуальной (12.0.2)
echo -e "${YELLOW}3. Обновление Grafana до актуальной версии...${NC}"
{
    systemctl stop grafana-server
    wget https://dl.grafana.com/oss/release/grafana_12.0.2_amd64.deb -O /tmp/grafana_new.deb
    dpkg -i /tmp/grafana_new.deb
    rm -f /tmp/grafana_new.deb
    systemctl daemon-reload
    systemctl start grafana-server
} > /dev/null 2>&1
check_error "Обновление Grafana до 12.0.2"

# 4. Настройка шаблона Nginx для TC Nginx+Apache
echo -e "${YELLOW}4. Настройка шаблона Nginx для TC Nginx+Apache...${NC}"
{
    cat > /usr/local/hestia/data/templates/web/nginx/php-fpm/default.tpl <<'EOF'
#
# TC Nginx+Apache
# v 1.01
#

server {
	listen      %ip%:%proxy_ssl_port% ssl;
	server_name %domain_idn% %alias_idn%;
	error_log   /var/log/%web_system%/domains/%domain%.error.log error;

	ssl_certificate     %ssl_pem%;
	ssl_certificate_key %ssl_key%;
	ssl_stapling        on;
	ssl_stapling_verify on;

	# TLS 1.3 0-RTT anti-replay
	if ($anti_replay = 307) { return 307 https://$host$request_uri; }
	if ($anti_replay = 425) { return 425; }

	include %home%/%user%/conf/web/%domain%/nginx.hsts.conf*;

	location = /favicon.ico {
		log_not_found off;
		access_log off;
	}

	location ~ /\.(?!well-known\/|file) {
		deny all;
		return 404;
	}

	location ~ ^/wp-content/cache { deny all; }

	location / {
		proxy_pass https://%ip%:%web_ssl_port%;

		location ~* ^.+\.(ogg|ogv|svg|svgz|swf|eot|otf|woff|woff2|mov|mp3|mp4|webm|flv|ttf|rss|atom|jpg|jpeg|gif|png|webp|ico|bmp|mid|midi|wav|rtf|css|js|jar|json|cur|3gp|av1|avi|doc|docx|pdf|txt|xls|xlsx|apk)$ {
			try_files $uri =404;

			root       %sdocroot%;
			access_log /var/log/nginx/domains/%domain%.log combined;
			access_log /var/log/nginx/domains/%domain%.bytes bytes;

			expires    max;
		}

		location ~* /(?:uploads|files)/.*.php$ {
			deny all;
			return 404;
		}

	}

	location /error/ {
		alias %home%/%user%/web/%domain%/document_errors/;
	}

	location ~* (debug\.log|readme\.html|license\.txt|xmlrpc\.php|nginx\.conf)$ {
		return 404;
	}

	location /wthme/ {
		rewrite ^/wthme/(.*)$ /wp-content/plugins/hb_waf/themes/$1 last;
	}

	proxy_hide_header Upgrade;

	include %home%/%user%/conf/web/%domain%/nginx.ssl.conf_*;
	include %sdocroot%/ngin*.conf;
}
EOF

    echo -e "${GREEN}Шаблон Nginx для TC Nginx+Apache успешно обновлен${NC}"
} > /dev/null 2>&1
check_error "Настройка шаблона Nginx для TC Nginx+Apache"

# 5. Дополнительные настройки безопасности Nginx
echo -e "${YELLOW}5. Применение дополнительных настроек безопасности Nginx...${NC}"
{
    # Создаем глобальный конфиг безопасности для Nginx
    cat > /etc/nginx/conf.d/security.conf <<'EOF'
# Basic Security Headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

# Hide server version
server_tokens off;

# File upload limits
client_max_body_size 64M;
client_body_timeout 30s;
client_header_timeout 30s;

# Rate limiting
limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
limit_req zone=one burst=20 nodelay;

# SSL settings
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
ssl_ecdh_curve secp384r1;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
EOF

    # Перезагружаем Nginx для применения изменений
    systemctl reload nginx
} > /dev/null 2>&1
check_error "Применение дополнительных настроек безопасности Nginx"

echo -e "${YELLOW}=== НАСТРОЙКА ЗАВЕРШЕНА ===${NC}"
echo -e "  • ${GREEN}Лимиты Loki изменены, правки сделаны, доступ к портам ограничен доверенными IP (кроме 22 и 8083).${NC}"
echo -e "  • ${GREEN}Шаблон Nginx для TC Nginx+Apache успешно применен.${NC}"
echo -e "  • ${GREEN}Дополнительные настройки безопасности Nginx добавлены.${NC}"
