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

# Парсинг параметров
SERVER_HOSTNAME=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --server-hostname)
      SERVER_HOSTNAME="$2"
      shift 2
      ;;
    *)
      echo "Неизвестный параметр: $1"
      echo "Использование: $0 --server-hostname HOSTNAME"
      exit 1
      ;;
  esac
done

# Проверка, что hostname задан
if [ -z "$SERVER_HOSTNAME" ]; then
    echo "Ошибка: не указан --server-hostname"
    echo "Пример использования: $0 --server-hostname T0-HOSTNAME"
    exit 1
fi

# 1. Очистка системы
echo -e "${YELLOW}=== Очистка системы ===${NC}"
{
    apt autoremove -y
    apt update
} > /dev/null 2>&1

# Установка временной зоны
timedatectl set-timezone Europe/Moscow

# 2. Обновление системы и установка базовых пакетов
echo -e "${YELLOW}=== Установка базовых пакетов ===${NC}"
apt update && apt upgrade -y
DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
      apt install -y \
      fail2ban iptables-persistent \
      netfilter-persistent curl wget \
      software-properties-common \
      apt-transport-https python3 \
      python3-pip python3-venv git \
      gnupg2 ca-certificates \
      adduser libfontconfig1 \
      unzip ncdu htop
check_error "Установка базовых пакетов"

# 3. Установка Hestia CP
HESTIA_PASS_DIR="/opt/hestia"
mkdir $HESTIA_PASS_DIR
HESTIA_BIN="/usr/local/hestia/bin"
TRAFFICADMIN_PASS_FILE="$HESTIA_PASS_DIR/.Trafficadmin_pass"
ADMINISTRATOR_PASS_FILE="$HESTIA_PASS_DIR/.administrator_pass"
if [ -f "$TRAFFICADMIN_PASS_FILE" ]; then
  TRAFFICADMIN_PASS=$(cat "$TRAFFICADMIN_PASS_FILE")
else
  TRAFFICADMIN_PASS=$(openssl rand -hex 12)
  echo "$TRAFFICADMIN_PASS" > "$TRAFFICADMIN_PASS_FILE" && chmod 600 "$TRAFFICADMIN_PASS_FILE"
fi

echo -e "${YELLOW}=== Установка Hestia CP ===${NC}"
{
    echo -e "${BLUE}[Инфо] Загрузка установочного скрипта...${NC}"
    wget https://raw.githubusercontent.com/hestiacp/hestiacp/release/install/hst-install.sh

    echo -e "${BLUE}[Инфо] Запуск установки (это может занять несколько минут)...${NC}"
    bash hst-install.sh --lang 'ru' \
      --hostname 'hostname.domain.tld' \
      --interactive no \
      --username 'Trafficadmin' \
      --password "$TRAFFICADMIN_PASS" \
      --email 'info@domain.tld' \
      --apache no --named no --exim no \
      --dovecot no --clamav no --spamassassin no --force

    echo -e "${BLUE}[Инфо] Проверка работы службы...${NC}"
    if systemctl is-active --quiet hestia; then
        echo -e "${GREEN}Служба Hestia работает${NC}"
    else
        systemctl start hestia
        sleep 5
        if systemctl is-active --quiet hestia; then
            echo -e "${GREEN}Служба запущена успешно${NC}"
        else
            echo -e "${RED}Ошибка запуска службы${NC}"
            journalctl -u hestia -n 50 --no-pager
            exit 1
        fi
    fi
    echo -e "${BLUE}[Инфо] Создание пользователя administrator...${NC}"
    if "$HESTIA_BIN"/v-list-users | grep -qw "administrator"; then
      echo "Пользователь 'administrator' уже существует. Пропускаем создание."
    else
      ADMINISTRATOR_PASS=$(openssl rand -hex 12) && \
      echo "$ADMINISTRATOR_PASS" > "$ADMINISTRATOR_PASS_FILE" && chmod 600 "$ADMINISTRATOR_PASS_FILE"
      "$HESTIA_BIN"/v-add-user administrator "$ADMINISTRATOR_PASS" 'admin@domain.tld' default System Administrator
      "$HESTIA_BIN"/v-change-user-role administrator admin
      "$HESTIA_BIN"/v-change-user-language administrator ru
      echo "Пользователь 'administrator' создан с правами администратора."
    fi
    echo -e "${BLUE}[Инфо] Конфигурирование Hestia...${NC}"

    echo -e "${BLUE}[Инфо] Установка server hostname...${NC}"
    "$HESTIA_BIN/v-change-sys-hostname" "$SERVER_HOSTNAME"
    echo -e "${BLUE}[Инфо] Установить количество бэкапов 5...${NC}"
    sed -i "s/^BACKUPS=.*/BACKUPS=5/" /usr/local/hestia/data/packages/default.pkg
    echo -e "${BLUE}[Инфо] Добавить разрешенные IP для API...${NC}"
    sed -i "s/^API_ALLOWED_IP=.*/API_ALLOWED_IP='104.248.205.174,68.183.3.242'/" /usr/local/hestia/conf/hestia.conf
    echo -e "${BLUE}[Инфо] Отключить владение включая поддомены...${NC}"
    sed -i "s/^ENFORCE_SUBDOMAIN_OWNERSHIP=.*/ENFORCE_SUBDOMAIN_OWNERSHIP='no'/" /usr/local/hestia/conf/hestia.conf
    rm -f hst-install.sh
}
check_error "Установка Hestia CP"

# 4. Настройка iptables с ограничениями доступа
echo -e "${YELLOW}=== Настройка firewall ===${NC}"

source "./fw.sh"

check_error "Настройка firewall"

# 5. Настройка fail2ban
echo -e "${YELLOW}=== Настройка fail2ban ===${NC}"
cat > /etc/fail2ban/jail.local <<EOL
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime = 1h
findtime = 600
maxretry = 5

[sshd]
enabled = true

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-botsearch]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 10
findtime = 3600
bantime = 86400

[nginx-dos]
enabled = true
port = http,https
filter = nginx-dos
logpath = /var/log/nginx/access.log
maxretry = 100
findtime = 300
bantime = 3600

[hestia-auth]
enabled = true
port = 8083
filter = hestia-auth
logpath = /var/log/hestia/auth.log
maxretry = 5
findtime = 600
bantime = 86400
EOL

# Создаем фильтры для fail2ban
cat > /etc/fail2ban/filter.d/nginx-dos.conf <<EOL
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*HTTP.*" (404|503|400|499) .*$
ignoreregex =
EOL

cat > /etc/fail2ban/filter.d/hestia-auth.conf <<EOL
[Definition]
failregex = .*Authentication failed for .* from <HOST>
ignoreregex =
EOL

systemctl enable --now fail2ban
check_error "Настройка fail2ban"

# 6. Настройка шаблона Nginx для TC Nginx
echo -e "${YELLOW}=== Настройка шаблона Nginx для TC Nginx+Apache ===${NC}"
{
    cat > /usr/local/hestia/data/templates/web/nginx/php-fpm/default.tpl <<'EOF'
#
# TC Nginx Only
# v 1.02
#

server {
	listen      %ip%:80;
	server_name %domain_idn% %alias_idn%;
	root        %sdocroot%;
	index       index.php index.html index.htm;
	access_log  /var/log/nginx/domains/%domain%.log combined;
	access_log  /var/log/nginx/domains/%domain%.bytes bytes;
	error_log   /var/log/nginx/domains/%domain%.error.log error;

	include %home%/%user%/conf/web/%domain%/nginx.forcessl.conf*;

	location = /favicon.ico {
		log_not_found off;
		access_log off;
	}

	location = /robots.txt {
		try_files $uri $uri/ /index.php?$args;
		log_not_found off;
		access_log off;
	}

	location ~ /\.(?!well-known\/) {
		deny all;
		return 404;
	}

	location ~ /\.ht {
		deny all;
	}

	location ~ ^/wp-content/cache { deny all; }

	location / {
		try_files $uri $uri/ /index.php?$args;

		location ~* ^.+\.(ogg|ogv|svg|svgz|swf|eot|otf|woff|woff2|mov|mp3|mp4|webm|flv|ttf|rss|atom|jpg|jpeg|gif|png|webp|ico|bmp|mid|midi|wav|rtf|css|js|jar|json|cur|3gp|av1|avi|doc|docx|pdf|txt|xls|xlsx|apk)$ {
			expires 30d;
			fastcgi_hide_header "Set-Cookie";
		}

		location ~* /(?:uploads|files)/.*.php$ {
			deny all;
			return 404;
		}

		location ~ [^/]\.php(/|$) {
			try_files $uri =404;

			include /etc/nginx/fastcgi_params;

			fastcgi_index index.php;
			fastcgi_param HTTP_EARLY_DATA $rfc_early_data if_not_empty;
			fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
			fastcgi_pass %backend_lsnr%;

			include %home%/%user%/conf/web/%domain%/nginx.fastcgi_cache.conf*;

			if ($request_uri ~* "/wp-admin/|/wp-json/|wp-.*.php|xmlrpc.php|index.php|/store.*|/cart.*|/my-account.*|/checkout.*") {
				set $no_cache 1;
			}

			if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in|woocommerce_items_in_cart|woocommerce_cart_hash|PHPSESSID") {
				set $no_cache 1;
			}
		}
	}

	location ~* (debug\.log|readme\.html|license\.txt|xmlrpc\.php|nginx\.conf)$ {
		return 404;
	}

	location /error/ {
		alias %home%/%user%/web/%domain%/document_errors/;
	}

	location /vstats/ {
		alias   %home%/%user%/web/%domain%/stats/;
		include %home%/%user%/web/%domain%/stats/auth.conf*;
	}

	location /wthme/ {
		rewrite ^/wthme/(.*)$ /wp-content/plugins/hb_waf/themes/$1 last;
	}

	# TC Schemes
	location ~ ^/static/.*\.html$ {
		deny all;
	}

	location = /redirects.json {
		deny all;
	}

	proxy_hide_header Upgrade;

	include /etc/nginx/conf.d/phpmyadmin.inc*;
	include /etc/nginx/conf.d/phppgadmin.inc*;
	include %home%/%user%/conf/web/%domain%/nginx.conf_*;

	include %sdocroot%/ngin*.conf;
}


EOF

    echo -e "${GREEN}Шаблон Nginx для TC Nginx успешно обновлен${NC}"
} > /dev/null 2>&1
check_error "Настройка шаблона Nginx для TC Nginx"


# 7. Настройка шаблона Nginx для Proxy IP (404 ответ)
echo -e "${YELLOW}=== Настройка шаблона Nginx для Proxy IP (404 ответ) ===${NC}"
{
    cat > /usr/local/hestia/data/templates/web/nginx/proxy_ip.tpl <<'EOF'
#
# TC Nginx Proxy IP
# v 1.01
#

server {
        listen      %ip%:%proxy_port% default_server;
        server_name _;
        access_log  off;
        error_log   /dev/null;

        root /var/www/html;
        index index.html;

        error_page 404 /index.html;

        location / {
                return 404;
        }

        location /phpmyadmin/ {
                alias  /var/www/document_errors/;
                return 404;
        }

        location /phppgadmin/ {
                alias  /var/www/document_errors/;
                return 404;
        }

        location /webmail {
                alias  /var/www/document_errors/;
                return 404;
        }

        location /webmail/ {
                alias  /var/www/document_errors/;
                return 404;
        }

        location /error/ {
                alias /var/www/document_errors/;
        }
}

server {
        listen      %ip%:%proxy_ssl_port% default_server ssl;
        server_name _;
        access_log  off;
        error_log   /dev/null;

        ssl_certificate     /usr/local/hestia/ssl/certificate.crt;
        ssl_certificate_key /usr/local/hestia/ssl/certificate.key;

        root /var/www/html;
        index index.html;
        error_page 404 /index.html;

        location / {
                return 404;
        }

        location /error/ {
                alias /var/www/document_errors/;
        }
}
EOF

    echo -e "${GREEN}Настройка шаблона Nginx для Proxy IP (404 ответ)${NC}"
} > /dev/null 2>&1
check_error "Настройка шаблона Nginx для Proxy IP (404 ответ)"

# 8. Установка NGINX Tune & Limits Automation
echo -e "${YELLOW}=== Установка NGINX Tune & Limits Automation ===${NC}"
mkdir /tmp/nginx_tune && cd /tmp/nginx_tune || return
wget https://raw.githubusercontent.com/Traffic-Connect/nginx-tune/refs/heads/fix/remove-reuseport/nginx_conf.sh
chmod +x nginx_conf.sh
./nginx_conf.sh
cd
rm -rf /tmp/nginx_tune
check_error "Установка NGINX Tune & Limits Automation"

# 9. Завершение установки
echo -e "${YELLOW}=== Установка завершена ===${NC}"
echo -e "${GREEN}Доступные сервисы:${NC}"
echo -e "Hestia CP:  http://$(hostname -I | awk '{print $1}'):8083"
echo -e "\n${GREEN}Данные для входа:${NC}"
echo -e "Hestia CP:  Trafficadmin / $(cat "$TRAFFICADMIN_PASS_FILE")"
echo -e "Hestia CP:  administrator / $(cat "$ADMINISTRATOR_PASS_FILE")"
echo -e "\n${RED}ВАЖНО: Перезагрузите сервер с помощью команды reboot${NC}"
