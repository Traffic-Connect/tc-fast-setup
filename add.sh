#!/bin/bash

# Конфигурация
CONFIG_FILE="/etc/prometheus/prometheus.yml"
BACKUP_FILE="/etc/prometheus/prometheus.yml.bak"
PORT="9100"  # Порт node_exporter по умолчанию
SERVICE_NAME="prometheus"  # Имя сервиса Prometheus
CONFIG_OWNER="prometheus:prometheus"  # Владелец файла конфигурации
CONFIG_PERMS="644"  # Права доступа к файлу конфигурации

# Проверка прав администратора
if [ "$(id -u)" -ne 0 ]; then
  echo "Ошибка: этот скрипт должен запускаться с правами root (sudo)."
  exit 1
fi

# Проверка наличия файла конфигурации
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Ошибка: файл конфигурации $CONFIG_FILE не найден!"
  exit 1
fi

# Запрос данных у пользователя
echo "Добавление нового target в Prometheus (секция job_name: 'node')"
read -p "Введите IP-адрес сервера (например, 93.123.72.162): " IP_ADDRESS
read -p "Введите dashboard_uid (например, grfew): " DASHBOARD_UID

# Проверка формата IP-адреса
if ! [[ $IP_ADDRESS =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Ошибка: неверный формат IP-адреса!"
  exit 1
fi

# Проверка на дубликат IP в секции job_name: 'node'
NODE_SECTION_START=$(grep -n "job_name: 'node'" "$CONFIG_FILE" | cut -d: -f1 | head -1)
if [ -z "$NODE_SECTION_START" ]; then
  echo "Ошибка: секция job_name: 'node' не найдена в конфигурационном файле!"
  exit 1
fi
NODE_SECTION_END=$(awk -v start="$NODE_SECTION_START" 'NR > start && /job_name:/ {print NR-1; exit} END {print NR}' "$CONFIG_FILE" | head -1)
if grep -A $((NODE_SECTION_END - NODE_SECTION_START)) "job_name: 'node'" "$CONFIG_FILE" | grep -q "$IP_ADDRESS:$PORT"; then
  echo "Ошибка: IP-адрес $IP_ADDRESS уже существует в секции job_name: 'node'!"
  exit 1
fi

# Проверка на дубликат dashboard_uid
if grep -q "dashboard_uid: '$DASHBOARD_UID'" "$CONFIG_FILE"; then
  read -p "Предупреждение: dashboard_uid '$DASHBOARD_UID' уже существует. Продолжить? (y/n): " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

# Создаём резервную копию конфигурации
echo "Создаётся резервная копия конфигурации..."
cp "$CONFIG_FILE" "$BACKUP_FILE" || {
  echo "Ошибка при создании резервной копии!"
  exit 1
}

# Сохраняем текущие права и владельца файла конфигурации
ORIGINAL_PERMS=$(stat -c %a "$CONFIG_FILE")
ORIGINAL_OWNER=$(stat -c %U:%G "$CONFIG_FILE")

# Находим строку начала static_configs в секции job_name: 'node'
STATIC_CONFIGS_LINE=$(awk -v start="$NODE_SECTION_START" 'NR >= start && /static_configs:/ {print NR; exit}' "$CONFIG_FILE" | head -1)
if [ -z "$STATIC_CONFIGS_LINE" ]; then
  echo "Ошибка: блок static_configs не найден в секции job_name: 'node'!"
  exit 1
fi

# Находим строку relabel_configs или конец секции node
RELABEL_CONFIGS_LINE=$(awk -v start="$NODE_SECTION_START" 'NR >= start && /relabel_configs:/ {print NR; exit}' "$CONFIG_FILE" | head -1)
if [ -z "$RELABEL_CONFIGS_LINE" ]; then
  RELABEL_CONFIGS_LINE=$NODE_SECTION_END
fi

# Находим последнюю строку с targets в static_configs
LAST_TARGET_LINE=$(awk -v start="$STATIC_CONFIGS_LINE" -v end="$RELABEL_CONFIGS_LINE" 'NR >= start && NR <= end && /^ *- targets:/ {last=NR} END {print last}' "$CONFIG_FILE" | head -1)
if [ -z "$LAST_TARGET_LINE" ]; then
  LAST_TARGET_LINE=$((STATIC_CONFIGS_LINE))
else
  LAST_TARGET_LINE=$(awk -v start="$LAST_TARGET_LINE" -v end="$RELABEL_CONFIGS_LINE" 'NR >= start && NR <= end && /^ *[^-]/ {last=NR-1; exit} END {if (last) print last; else print start}' "$CONFIG_FILE" | head -1)
fi

# Определяем строку для вставки
INSERT_LINE=$((LAST_TARGET_LINE))

# Временный файл для новой конфигурации
TMP_FILE=$(mktemp) || {
  echo "Ошибка при создании временного файла!"
  exit 1
}

# Вставляем новый target в нужное место
awk -v line="$INSERT_LINE" -v ip="$IP_ADDRESS" -v port="$PORT" -v uid="$DASHBOARD_UID" '
  NR == line {
    print $0
    print "      - targets: [\x27" ip ":" port "\x27]"
    print "        labels:"
    print "          dashboard_uid: \x27" uid "\x27"
    next
  }
  { print }
' "$CONFIG_FILE" > "$TMP_FILE" || {
  echo "Ошибка при обработке конфигурационного файла!"
  rm -f "$TMP_FILE"
  exit 1
}

# Заменяем оригинальный файл и восстанавливаем права и владельца
mv "$TMP_FILE" "$CONFIG_FILE" || {
  echo "Ошибка при замене конфигурационного файла!"
  rm -f "$TMP_FILE"
  exit 1
}
chown "$CONFIG_OWNER" "$CONFIG_FILE" || {
  echo "Ошибка при установке владельца файла конфигурации!"
  exit 1
}
chmod "$CONFIG_PERMS" "$CONFIG_FILE" || {
  echo "Ошибка при установке прав доступа к файлу конфигурации!"
  exit 1
}

# Проверяем синтаксис новой конфигурации
if ! command -v promtool &> /dev/null; then
  echo "Предупреждение: promtool не установлен, пропускаем проверку конфигурации"
else
  promtool check config "$CONFIG_FILE" >/dev/null 2>&1 || {
    echo "Ошибка: новая конфигурация содержит ошибки! Восстанавливаю backup..."
    mv "$BACKUP_FILE" "$CONFIG_FILE"
    chown "$CONFIG_OWNER" "$CONFIG_FILE"
    chmod "$CONFIG_PERMS" "$CONFIG_FILE"
    exit 1
  }
fi

# Перезапускаем Prometheus
echo "Перезапуск Prometheus для применения изменений..."
systemctl restart "$SERVICE_NAME" || {
  echo "Ошибка при перезапуске Prometheus!"
  echo "Попробуйте перезапустить вручную: systemctl restart prometheus"
  exit 1
}

echo "Успешно:"
echo "1. Добавлен сервер $IP_ADDRESS с dashboard_uid $DASHBOARD_UID в секцию job_name: 'node'"
echo "2. Конфигурация проверена"
echo "3. Права и владелец файла $CONFIG_FILE восстановлены"
echo "4. Prometheus перезапущен"

# Удаляем временный файл
rm -f "$TMP_FILE"
