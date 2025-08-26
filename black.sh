#!/bin/bash

# Проверка root
if [ "$(id -u)" != "0" ]; then
    echo -e "\033[31mЭтот скрипт должен быть запущен от имени root\033[0m" >&2
    exit 1
fi

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

BBE_VERSION="0.24.0"
CONFIG_DIR="/etc/blackbox_exporter"
CONFIG_FILE="$CONFIG_DIR/config.yml"
SERVICE_FILE="/etc/systemd/system/blackbox_exporter.service"
LOG_DIR="/var/log/apache2/domains"  # Или /var/log/nginx/

# Определяем расположение prometheus.yml
PROMETHEUS_CONFIG=""
for loc in "/etc/prometheus/prometheus.yml" "/usr/local/etc/prometheus/prometheus.yml"; do
    if [ -f "$loc" ]; then
        PROMETHEUS_CONFIG="$loc"
        break
    fi
done

if [ -z "$PROMETHEUS_CONFIG" ]; then
    echo -e "${RED}[!] Файл prometheus.yml не найден в стандартных расположениях${NC}"
    read -p "Введите полный путь к prometheus.yml: " PROMETHEUS_CONFIG
    if [ ! -f "$PROMETHEUS_CONFIG" ]; then
        echo -e "${RED}[!] Указанный файл не существует${NC}"
        exit 1
    fi
fi

TARGETS_FILE="$CONFIG_DIR/targets.yml"
PROMETHEUS_BACKUP="${PROMETHEUS_CONFIG}.bak"

echo -e "${YELLOW}=== Установка и настройка blackbox_exporter ===${NC}"
echo -e "${BLUE}Используемый файл Prometheus: $PROMETHEUS_CONFIG${NC}"

# 1. Проверка директории логов
if [ ! -d "$LOG_DIR" ]; then
    echo -e "${RED}[!] Директория $LOG_DIR не существует${NC}"
    exit 1
fi

# 2. Создание пользователя
if ! id blackbox_exporter &>/dev/null; then
    useradd --no-create-home --shell /bin/false blackbox_exporter
    echo -e "${GREEN}[+] Создан пользователь blackbox_exporter${NC}"
fi

# 3. Установка blackbox_exporter
echo -e "${YELLOW}Загрузка blackbox_exporter v${BBE_VERSION}...${NC}"
wget -q --show-progress "https://github.com/prometheus/blackbox_exporter/releases/download/v${BBE_VERSION}/blackbox_exporter-${BBE_VERSION}.linux-amd64.tar.gz" -O /tmp/blackbox_exporter.tar.gz
tar xf /tmp/blackbox_exporter.tar.gz -C /tmp/
mv /tmp/blackbox_exporter-${BBE_VERSION}.linux-amd64/blackbox_exporter /usr/local/bin/
chown blackbox_exporter:blackbox_exporter /usr/local/bin/blackbox_exporter

# 4. Извлечение доменов из логов
DOMAINS=()
for log_file in "$LOG_DIR"/*.log; do
    filename=$(basename "$log_file" .log)
    if [[ "$filename" =~ [Tt][Ee][Ss][Tt] ]] || [[ "$filename" =~ [Ee][Rr][Rr][Oo][Rr] ]]; then
        echo -e "${YELLOW}[!] Пропущен файл: $filename (содержит test/error)${NC}"
        continue
    fi
    DOMAINS+=("$filename")
done

if [ ${#DOMAINS[@]} -eq 0 ]; then
    echo -e "${RED}[!] Не найдено валидных доменов для мониторинга в $LOG_DIR${NC}"
    exit 1
fi

# 5. Генерация конфигурации blackbox_exporter
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_FILE" <<EOF
modules:
  http_2xx:
    prober: http
    timeout: 10s
    http:
      valid_http_versions: ["HTTP/1.1", "HTTP/2.0"]
      method: GET
      preferred_ip_protocol: "ip4"
      no_follow_redirects: false
      tls_config:
        insecure_skip_verify: true
      valid_status_codes: [200, 301, 302]
EOF

# 6. Создание файла целей
cat > "$TARGETS_FILE" <<EOF
- targets:
EOF

for domain in "${DOMAINS[@]}"; do
    echo "  - \"https://$domain\"" >> "$TARGETS_FILE"
    echo -e "${BLUE}[+] Добавлен домен: $domain${NC}"
done

cat >> "$TARGETS_FILE" <<EOF
  labels:
    job: blackbox-http
EOF

# 7. Настройка systemd
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Blackbox Exporter
After=network.target

[Service]
User=blackbox_exporter
Group=blackbox_exporter
Type=simple
ExecStart=/usr/local/bin/blackbox_exporter \\
    --config.file=$CONFIG_FILE \\
    --web.listen-address=:9115
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 8. Запуск сервиса
systemctl daemon-reload
systemctl enable --now blackbox_exporter

# 9. Добавление конфига в Prometheus
if ! grep -q "blackbox-http" "$PROMETHEUS_CONFIG"; then
    echo -e "${YELLOW}Добавляем конфигурацию в $PROMETHEUS_CONFIG...${NC}"
    
    # Создаем резервную копию
    cp "$PROMETHEUS_CONFIG" "$PROMETHEUS_BACKUP"
    
    # Подготовка новой конфигурации
    BLACKBOX_CONFIG='  - job_name: "blackbox-http"
    metrics_path: /probe
    params:
      module: [http_2xx]
    file_sd_configs:
      - files:
        - "'"$TARGETS_FILE"'"
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9115'

    # Создаем временный файл
    TMP_FILE=$(mktemp)
    
    # Если секция scrape_configs существует
    if grep -q "scrape_configs:" "$PROMETHEUS_CONFIG"; then
        # Вставляем нашу конфигурацию после строки scrape_configs:
        awk -v config="$BLACKBOX_CONFIG" '
            /scrape_configs:/ {print; print config; inserted=1; next}
            {print}
        ' "$PROMETHEUS_CONFIG" > "$TMP_FILE"
    else
        # Если секции нет, создаем ее
        cat "$PROMETHEUS_CONFIG" > "$TMP_FILE"
        echo "scrape_configs:" >> "$TMP_FILE"
        echo "$BLACKBOX_CONFIG" >> "$TMP_FILE"
    fi
    
    # Заменяем оригинальный файл
    mv "$TMP_FILE" "$PROMETHEUS_CONFIG"
    chown prometheus:prometheus "$PROMETHEUS_CONFIG"
    chmod 644 "$PROMETHEUS_CONFIG"
    
    # Проверяем синтаксис
    if command -v promtool &>/dev/null; then
        if ! promtool check config "$PROMETHEUS_CONFIG"; then
            echo -e "${RED}Ошибка в конфигурации Prometheus! Восстанавливаем backup...${NC}"
            mv "$PROMETHEUS_BACKUP" "$PROMETHEUS_CONFIG"
            exit 1
        fi
    fi
    
    systemctl restart prometheus
    echo -e "${GREEN}[+] Конфигурация добавлена в Prometheus${NC}"
else
    echo -e "${YELLOW}[!] Конфигурация blackbox уже существует в $PROMETHEUS_CONFIG${NC}"
fi

# 10. Проверка работы
echo -e "${YELLOW}\nПроверка работы...${NC}"
FIRST_DOMAIN="${DOMAINS[0]}"
METRICS=$(curl -s "http://localhost:9115/probe?target=https://${FIRST_DOMAIN}&module=http_2xx")
if echo "$METRICS" | grep -q "probe_success"; then
    echo -e "${GREEN}✓ blackbox_exporter работает корректно${NC}"
    echo -e "Метрики для ${FIRST_DOMAIN}:"
    echo "$METRICS" | grep -E 'probe_success|probe_http_status_code|probe_duration_seconds'
else
    echo -e "${RED}Ошибка при проверке домена ${FIRST_DOMAIN}${NC}"
    journalctl -u blackbox_exporter -n 10 --no-pager
fi

echo -e "\n${GREEN}=== Установка завершена успешно! ===${NC}"
echo -e "Найдено доменов: ${#DOMAINS[@]}"
echo -e "Blackbox Exporter доступен на: ${YELLOW}http://localhost:9115${NC}"
echo -e "Конфигурационный файл: ${YELLOW}${CONFIG_FILE}${NC}"
echo -e "Файл целей: ${YELLOW}${TARGETS_FILE}${NC}"
