#!/bin/sh
set -e

# --- Проверка root ---
[ "$(id -u)" != "0" ] && { echo "\033[31mТребуется root\033[0m" >&2; exit 1; }

# --- Цвета ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Проверка установки Grafana ---
if ! command -v grafana-cli >/dev/null 2>&1; then
    echo "${RED}ОШИБКА: Grafana не установлена${NC}"
    echo "Установите Grafana перед выполнением этого скрипта"
    exit 1
fi

# --- Запрос учетных данных Grafana ---
echo "${YELLOW}Введите учетные данные Grafana${NC}"
printf "Логин администратора Grafana: "
read GRAFANA_USER
stty -echo
printf "Пароль: "
read GRAFANA_PASS
stty echo
echo

GRAFANA_URL="http://localhost:3000"

# --- Функция добавления Data Source ---
add_data_source() {
    name=$1
    type=$2
    url=$3
    
    payload=$(cat <<EOF
{
    "name": "$name",
    "type": "$type",
    "url": "$url",
    "access": "proxy",
    "basicAuth": false,
    "isDefault": false
}
EOF
    )

    response=$(curl -s -X POST \
        -u "$GRAFANA_USER:$GRAFANA_PASS" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "$GRAFANA_URL/api/datasources")

    # Проверяем успешность по наличию id в ответе
    if echo "$response" | jq -e '.id' >/dev/null 2>&1; then
        echo "${GREEN}✓ Успешно добавлен $name${NC}"
    elif echo "$response" | jq -e '.message' >/dev/null 2>&1; then
        echo "${RED}Ошибка при добавлении $name: $(echo "$response" | jq -r '.message')${NC}"
    else
        echo "${RED}Неизвестная ошибка при добавлении $name${NC}"
        echo "Ответ сервера: $response"
    fi
}

# --- Основной цикл ---
echo "${YELLOW}Добавление Data Sources в Grafana${NC}"
echo "${YELLOW}Введите IP-адреса серверов (по одному, пустая строка для завершения):${NC}"

while true; do
    printf "IP-адрес: "
    read ip
    
    # Проверка на пустую строку для завершения
    if [ -z "$ip" ]; then
        break
    fi
    
    # Проверка валидности IP
    case $ip in
        *[!0-9.]*)
            echo "${RED}Некорректный IP-адрес: $ip${NC}"
            continue
            ;;
        *)
            ;;
    esac

    echo "${YELLOW}Добавление Data Sources для $ip${NC}"
    
    # Добавление Loki
    add_data_source "Loki-$ip" "loki" "http://$ip:3100"
    
    # Добавление Prometheus
    add_data_source "Prometheus-$ip" "prometheus" "http://$ip:9090"
done

echo "\n${GREEN}=== Операция завершена ===${NC}"
