#!/bin/sh
# Сброс и базовая настройка правил
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Разрешаем локальный интерфейс и установленные соединения
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Защита от SYN-флуда и порт-сканирования
iptables -N SYN_FLOOD
iptables -A SYN_FLOOD -m limit --limit 10/second --limit-burst 25 -j RETURN
iptables -A SYN_FLOOD -j DROP
iptables -A INPUT -p tcp --syn -j SYN_FLOOD

iptables -N PORT_SCAN
iptables -A PORT_SCAN -m limit --limit 1/s -j RETURN
iptables -A PORT_SCAN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j PORT_SCAN

# Ограничение ICMP
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Защита SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Блокировка плохих User-Agent'ов (Cloudflare и другие)
BAD_AGENTS_URLS=(
    "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list"
    "https://github.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/blob/master/_generator_lists/bad-user-agents.list"
)

# Создаем временный файл
BAD_AGENTS_FILE=$(mktemp)

# Скачиваем и объединяем списки
for url in "${BAD_AGENTS_URLS[@]}"; do
    curl -s "$url" >> "$BAD_AGENTS_FILE"
done

# Добавляем правила для HTTP/HTTPS
if [ -s "$BAD_AGENTS_FILE" ]; then
    echo "Добавляем блокировку плохих User-Agent'ов..."
    while read -r agent; do
        [ -z "$agent" ] && continue  # Пропускаем пустые строки
        iptables -A INPUT -p tcp --dport 80 -m string --string "$agent" --algo bm -j DROP
        iptables -A INPUT -p tcp --dport 443 -m string --string "$agent" --algo bm -j DROP
    done < "$BAD_AGENTS_FILE"
    echo "Добавлено $(wc -l < "$BAD_AGENTS_FILE") правил для User-Agent'ов"
else
    echo "Не удалось загрузить списки User-Agent'ов" >&2
fi

# Ограничение скорости для HTTP/HTTPS
iptables -N HTTP_LIMIT
iptables -N HTTPS_LIMIT
iptables -A HTTP_LIMIT -m limit --limit 100/sec --limit-burst 150 -j ACCEPT
iptables -A HTTP_LIMIT -j DROP
iptables -A INPUT -p tcp --dport 80 -j HTTP_LIMIT
iptables -A HTTPS_LIMIT -m limit --limit 100/sec --limit-burst 150 -j ACCEPT
iptables -A HTTPS_LIMIT -j DROP
iptables -A INPUT -p tcp --dport 443 -j HTTPS_LIMIT

# Разрешаем IP-адреса Cloudflare
echo "Разрешаем IP-адреса Cloudflare..."
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
    iptables -A INPUT -p tcp -s "$ip" --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp -s "$ip" --dport 443 -j ACCEPT
    echo "Разрешён IP Cloudflare: $ip"
done

for ip in $(curl -s https://www.cloudflare.com/ips-v6); do
    ip6tables -A INPUT -p tcp -s "$ip" --dport 80 -j ACCEPT
    ip6tables -A INPUT -p tcp -s "$ip" --dport 443 -j ACCEPT
done

# Разрешаем IP-адреса Google и их ботов для индексации
echo "Разрешаем IP-адреса Google и их ботов..."
GOOGLE_IP_URLS=(
    "https://www.gstatic.com/ipranges/goog.json"
    "https://developers.google.com/search/apis/ipranges/googlebot.json"
)

# Создаем временный файл
GOOGLE_IPS_FILE=$(mktemp)

# Скачиваем и объединяем списки IP-адресов Google
for url in "${GOOGLE_IP_URLS[@]}"; do
    curl -s "$url" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' >> "$GOOGLE_IPS_FILE"
done

# Добавляем правила для IP-адресов Google
if [ -s "$GOOGLE_IPS_FILE" ]; then
    echo "Добавляем разрешения для IP-адресов Google..."
    while read -r ip; do
        [ -z "$ip" ] && continue  # Пропускаем пустые строки
        iptables -A INPUT -p tcp -s "$ip" --dport 80 -j ACCEPT
        iptables -A INPUT -p tcp -s "$ip" --dport 443 -j ACCEPT
        echo "Разрешён IP Google: $ip"
    done < "$GOOGLE_IPS_FILE"
    echo "Добавлено $(wc -l < "$GOOGLE_IPS_FILE") правил для IP-адресов Google"
else
    echo "Не удалось загрузить списки IP-адресов Google" >&2
fi

# Открываем необходимые порты
SERVICE_PORTS="8083 8080 25 465 587 993 995 143 110 53 3000 9090 9100 3100 9080 9191 9091 9200"
for port in $SERVICE_PORTS; do
    iptables -A INPUT -p tcp --dport $port -j ACCEPT
    echo "Открыт порт: $port/tcp"
done

# Разрешаем DNS и локальные БД
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 5432 -s 127.0.0.1 -j ACCEPT

# Сохраняем правила
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save
    netfilter-persistent reload
    systemctl enable netfilter-persistent >/dev/null 2>&1
fi

# Очистка временных файлов
[ -f "$BAD_AGENTS_FILE" ] && rm -f "$BAD_AGENTS_FILE"
[ -f "$GOOGLE_IPS_FILE" ] && rm -f "$GOOGLE_IPS_FILE"

# Вывод текущих правил
iptables -L -n -v