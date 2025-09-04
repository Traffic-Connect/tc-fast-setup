#!/bin/bash
set -e

# --- Конфигурация ---
LOKI_VERSION="2.9.2"
GEOIP_DB_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
LOG_DIR="/var/log/apache2/domains"

# --- Цвета ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Функция проверки ошибок ---
check_error() {
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ОШИБКА] $1${NC}"
        exit 1
    else
        echo -e "${GREEN}[OK] $1${NC}"
    fi
}

# --- Проверка root ---
echo -e "${YELLOW}=== Проверка прав root ===${NC}"
[ "$(id -u)" != "0" ] && { echo -e "${RED}Требуется root${NC}" >&2; exit 1; }
check_error "Проверка прав root"

# 1. Подготовка
echo -e "${YELLOW}=== Подготовка системы ===${NC}"
{
    apt update && apt install -y wget unzip jq libmaxminddb-dev
    systemctl stop promtail 2>/dev/null || true
    rm -f /tmp/positions.yaml
    mkdir -p /etc/promtail/geoip
} > /dev/null 2>&1
check_error "Подготовка системы"

# 2. Установка Promtail
echo -e "${YELLOW}=== Установка Promtail ===${NC}"
{
    wget -q "https://github.com/grafana/loki/releases/download/v${LOKI_VERSION}/promtail-linux-amd64.zip" -O /tmp/promtail.zip
    unzip -q /tmp/promtail.zip -d /tmp/
    mv /tmp/promtail-linux-amd64 /usr/local/bin/promtail
    chmod +x /usr/local/bin/promtail
    rm -f /tmp/promtail.zip

    id -u promtail >/dev/null 2>&1 || useradd --no-create-home --shell /bin/false promtail
    chown promtail:promtail /usr/local/bin/promtail
} > /dev/null 2>&1
check_error "Установка Promtail"

# 3. Настройка GeoIP
echo -e "${YELLOW}=== Настройка GeoIP ===${NC}"
{
    wget -q "$GEOIP_DB_URL" -O /etc/promtail/geoip/GeoLite2-City.mmdb
    chown -R promtail:promtail /etc/promtail
} > /dev/null 2>&1
check_error "Настройка GeoIP"

# 4. Конфигурация с исправленными путями и улучшенным парсингом
echo -e "${YELLOW}=== Создание конфигурации ===${NC}"
cat > /etc/promtail/promtail-config.yaml <<EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:
- job_name: nginx
  static_configs:
  - targets: [localhost]
    labels:
      job: nginx
      __path__: "/var/log/apache2/domains/*.log"
  pipeline_stages:
    - regex:
        expression: '^(?P<remote_addr>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<bytes>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    - labels:
        method:
        status:
        path:
        protocol:
        remote_addr:
        user_agent:
        referer:
    - timestamp:
        source: timestamp
        format: "02/Jan/2006:15:04:05 -0700"
    - geoip:
        db: "/etc/promtail/geoip/GeoLite2-City.mmdb"
        db_type: "city"
        source: "remote_addr"
        target: "geoip"
    - output:
        source: user_agent
    - output:
        source: remote_addr
EOF
check_error "Создание конфигурации"

# 5. Настройка прав
echo -e "${YELLOW}=== Настройка прав доступа ===${NC}"
{
    chown -R root:adm "$LOG_DIR"
    chmod -R 750 "$LOG_DIR"
    setfacl -Rm u:promtail:rx "$LOG_DIR"
    setfacl -dm u:promtail:rx "$LOG_DIR"

    # Проверка доступа
    if ! sudo -u promtail head -n 1 "$LOG_DIR"/*.log >/dev/null 2>&1; then
        echo -e "${RED}ОШИБКА: Promtail не может читать логи${NC}"
        echo "Проблемные файлы:"
        sudo -u promtail ls -la "$LOG_DIR"/*.log
        exit 1
    fi
} > /dev/null 2>&1
check_error "Настройка прав доступа"

# 6. Systemd сервис
echo -e "${YELLOW}=== Настройка сервиса ===${NC}"
cat > /etc/systemd/system/promtail.service <<EOF
[Unit]
Description=Promtail service
After=network.target

[Service]
User=promtail
Group=promtail
ExecStart=/usr/local/bin/promtail \\
    -config.file=/etc/promtail/promtail-config.yaml \\
    -config.expand-env=true
Restart=always
RestartSec=5s
LimitNOFILE=65536
Environment="LOG_DIR=$LOG_DIR"

[Install]
WantedBy=multi-user.target
EOF
check_error "Настройка сервиса"

# 7. Запуск и проверка
echo -e "${YELLOW}=== Запуск Promtail ===${NC}"
{
    systemctl daemon-reload
    systemctl enable promtail
    systemctl restart promtail
    sleep 5

    if ! systemctl is-active --quiet promtail; then
        echo -e "${RED}ОШИБКА: Promtail не запустился${NC}"
        journalctl -u promtail -n 20 --no-pager
        exit 1
    fi
} > /dev/null 2>&1
check_error "Запуск Promtail"

# 8. Проверка сбора логов
echo -e "${YELLOW}=== Проверка работы ===${NC}"
echo -e "${BLUE}Ожидание 20 секунд для сбора логов...${NC}"
sleep 20

{
    # Проверка извлечения полей
    LOG_CHECK=$(curl -s -G "http://localhost:3100/loki/api/v1/query" --data-urlencode 'query={job="nginx"} | logfmt | line_format "{{.remote_addr}} {{.user_agent}}"' | jq -r '.data.result[0].values[0][1]')

    if [ -n "$LOG_CHECK" ]; then
        echo -e "${GREEN}✓ Логи успешно собираются${NC}"
        echo "Пример извлеченных данных:"
        echo "$LOG_CHECK"
        
        # Проверка GeoIP
        GEOIP_CHECK=$(curl -s -G "http://localhost:3100/loki/api/v1/query" \
            --data-urlencode 'query={job="nginx"} | logfmt | remote_addr!="" | geoip_country_name!=""' \
            | jq -r '.data.result[0].values[0][1]')
        
        if [ -n "$GEOIP_CHECK" ]; then
            echo -e "${GREEN}✓ GeoIP работает! Пример данных:${NC}"
            echo "$GEOIP_CHECK"
        else
            echo -e "${YELLOW}⚠ GeoIP не возвращает данные. Проверьте IP в логах${NC}"
        fi
    else
        echo -e "${RED}ОШИБКА: Логи не поступают в Loki или поля не извлекаются${NC}"
        echo "Дополнительная диагностика:"
        echo "1. Проверьте файл позиций: cat /tmp/positions.yaml"
        echo "2. Проверьте логи Promtail: journalctl -u promtail -n 20 --no-pager"
        echo "3. Проверьте подключение к Loki: curl -v http://localhost:3100/ready"
        exit 1
    fi
} > /dev/null 2>&1
check_error "Проверка работы"

# 9. Замена nginx конфига
echo -e "${YELLOW}=== Замена nginx конфига ===${NC}"
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
check_error "Замена nginx конфига"

echo -e "\n${GREEN}=== Настройка успешно завершена! ===${NC}"
