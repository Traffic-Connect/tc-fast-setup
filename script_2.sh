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

echo -e "${YELLOW}=== НАСТРОЙКА ЗАВЕРШЕНА ===${NC}"
echo -e "  • ${GREEN}Лимиты Loki изменены, правки сделаны, доступ к портам ограничен доверенными IP (кроме 22 и 8083).${NC}"
