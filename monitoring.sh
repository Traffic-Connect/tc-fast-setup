#!/usr/bin/env bash
# touch monitoring.sh && chmod +x monitoring.sh && nano monitoring.sh

set -euo pipefail

# === Общие настройки ===
USER="node_exporter"
PROMETHEUS_SERVER="213.21.253.14"
TMPDIR="/tmp/node_exporter_setup"
INSTALL_DIR="/usr/local/bin"
TEXTFILE_DIR="/var/lib/node_exporter/textfile"
PROC_AGG_DIR="/opt/proc-agg-exporter"
HESTIA_RULES_FILE="/usr/local/hestia/data/firewall/rules.conf"

# === NODE EXPORTER ===
echo -e "${BLUE}[Инфо] Проверка работы службы Node exporter...${NC}"
if systemctl list-units --type=service --all | grep -q "node_exporter.service" ; then
  echo -e "${GREEN}Служба Node exporter установлена${NC}"
else
  echo -e "${GREEN}Установка Node exporter${NC}"
  echo "[*] Определение последней версии node_exporter..."
  VER="$(curl -fsSL https://api.github.com/repos/prometheus/node_exporter/releases/latest | jq -r .tag_name | sed 's/^v//')"
  echo "Версия: ${VER}"

  if ! id -u "$USER" &>/dev/null; then
    echo "[*] Создание пользователя $USER..."
    useradd --no-create-home --shell /usr/sbin/nologin "$USER"
  fi

  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "Unsupported arch: $ARCH"; exit 1 ;;
  esac

  echo "[*] Загрузка node_exporter v${VER}..."
  mkdir -p "$TMPDIR"
  cd "$TMPDIR"
  curl -fsSL -o node_exporter.tar.gz \
    "https://github.com/prometheus/node_exporter/releases/download/v${VER}/node_exporter-${VER}.linux-${ARCH}.tar.gz"
  tar -xzf node_exporter.tar.gz
  install -o "$USER" -g "$USER" -m 0755 "node_exporter-${VER}.linux-${ARCH}/node_exporter" \
    "${INSTALL_DIR}/node_exporter-${VER}"
  ln -sfn "${INSTALL_DIR}/node_exporter-${VER}" "${INSTALL_DIR}/node_exporter"

  mkdir -p "$TEXTFILE_DIR"
  chown -R "$USER:$USER" "$TEXTFILE_DIR"

  echo "[*] Создание systemd unit файла node_exporter..."
  tee /etc/systemd/system/node_exporter.service >/dev/null <<'EOF'
[Unit]
Description=Prometheus Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter \
  --web.listen-address=:9100 \
  --collector.systemd \
  --collector.textfile.directory=/var/lib/node_exporter/textfile \
  --collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc|run)($|/) \
  --collector.filesystem.fs-types-exclude=^(autofs|binfmt_misc|cgroup2?|configfs|debugfs|devpts|devtmpfs|fuse.*|hugetlbfs|mqueue|overlay|proc|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tmpfs)$
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now node_exporter
  echo -e "${GREEN}Служба Node exporter установлена${NC}"
fi

echo -e "${BLUE}[Инфо] Проверка работы службы Process exporter...${NC}"
if systemctl list-units --type=service --all | grep -q "proc-agg-exporter.service" ; then
  echo -e "${GREEN}Служба Process exporter установлена${NC}"
else
  mkdir -p "$PROC_AGG_DIR"

  tee "$PROC_AGG_DIR/exporter.py" >/dev/null <<'PY'
#!/usr/bin/env python3
import time, psutil, re, sys, logging, collections
from prometheus_client import start_http_server, Counter, Gauge

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

PATTERNS = {
    "apache2":  r"^apache2$",
    "nginx":    r"^nginx$",
    "hestia":   r"(^|-)hestia($|-)|vesta",
    "mysql":    r"^mysqld$|^mariadbd$",
    "php":      r"^php-fpm(\d+(\.\d+)*)?$",
    "fail2ban": r"^fail2ban-server$",
}

CPU_SEC = Counter(
    "process_agg_cpu_seconds_total",
    "Aggregated CPU seconds by process group",
    ["name"],
)
MEM_RSS = Gauge(
    "process_agg_memory_rss_bytes",
    "Aggregated RSS memory bytes by process group",
    ["name"],
)
PROC_COUNT = Gauge(
    "process_agg_process_count",
    "Number of processes by process group",
    ["name"],
)

def match_group(proc_name: str):
    name = (proc_name or "").lower()
    for group, rx in PATTERNS.items():
        if re.search(rx, name, re.I):
            return group
    return None

def export_loop(port=9109, interval=5):
    start_http_server(port)
    logging.info("proc-agg-exporter started on :%d", port)
    last_cpu_by_pid = {}
    while True:
        rss_by_group = collections.Counter()
        cnt_by_group = collections.Counter()
        inc_by_group = collections.Counter()
        for p in psutil.process_iter(attrs=["pid","name","cpu_times","memory_info"]):
            try:
                grp = match_group(p.info["name"])
                if not grp:
                    continue
                ct = p.info["cpu_times"]
                now = float((getattr(ct, "user", 0.0) or 0.0) + (getattr(ct, "system", 0.0) or 0.0))
                prev = last_cpu_by_pid.get(p.info["pid"], now)
                inc = max(0.0, now - prev)
                last_cpu_by_pid[p.info["pid"]] = now
                inc_by_group[grp] += inc
                rss_by_group[grp] += int(getattr(p.info["memory_info"], "rss", 0) or 0)
                cnt_by_group[grp] += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        for g in PATTERNS.keys():
            if inc_by_group[g] > 0:
                CPU_SEC.labels(g).inc(inc_by_group[g])
            MEM_RSS.labels(g).set(rss_by_group[g])
            PROC_COUNT.labels(g).set(cnt_by_group[g])
        if int(time.time()) % 60 < interval:
            logging.info("counts: %s", {k: v for k, v in cnt_by_group.items() if v > 0})
        time.sleep(interval)

if __name__ == "__main__":
    port = 9109
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except Exception:
            pass
    export_loop(port)
PY

  sudo chmod 755 "$PROC_AGG_DIR/exporter.py"

# === systemd unit для proc-agg-exporter ===
  sudo tee /etc/systemd/system/proc-agg-exporter.service >/dev/null <<'UNIT'
[Unit]
Description=Prometheus Process Aggregator Exporter
After=network.target

[Service]
User=root
ExecStart=/usr/bin/python3 /opt/proc-agg-exporter/exporter.py 9109
Restart=always
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable --now proc-agg-exporter
  echo -e "${GREEN}Служба Process exporter установлена${NC}"
fi

# === NGINX VTS MODULE ===
echo -e "${BLUE}[Инфо] Проверка установки модуля Nginx VTS...${NC}"
if [ -f "/etc/nginx/modules/ngx_http_vhost_traffic_status_module.so" ]; then
  echo -e "${GREEN}nginx VTS модуль уже установлен${NC}"
else
  echo -e "${YELLOW}Установка nginx VTS модуля...${NC}"
  rm -rf /tmp/nginx-vts && mkdir -p /tmp/nginx-vts && cd /tmp/nginx-vts
  NGINX_VERSION=$(nginx -v 2>&1 | awk -F/ '{print $2}')
  wget "http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
  tar -zxvf "nginx-${NGINX_VERSION}.tar.gz"
  git clone https://github.com/vozlt/nginx-module-vts.git

  cd "nginx-${NGINX_VERSION}"
  ./configure --with-compat --add-dynamic-module="../nginx-module-vts" > /dev/null 2>&1
  make > /dev/null 2>&1
  make install > /dev/null 2>&1
  cp objs/ngx_http_vhost_traffic_status_module.so /etc/nginx/modules/

  # === Конфигурация Nginx ===
  grep -qxF 'load_module modules/ngx_http_vhost_traffic_status_module.so;' /etc/nginx/nginx.conf || \
    sed -i '1iload_module modules/ngx_http_vhost_traffic_status_module.so;' /etc/nginx/nginx.conf
  grep -qxF '    vhost_traffic_status_zone;' /etc/nginx/nginx.conf || \
    awk '/http {/ {print; print "    vhost_traffic_status_zone;"; next}1' /etc/nginx/nginx.conf | \
    tee /etc/nginx/nginx.conf.tmp >/dev/null && mv /etc/nginx/nginx.conf.tmp /etc/nginx/nginx.conf

  tee /etc/nginx/conf.d/vts.conf >/dev/null <<EOF
server {
  listen 8088;
  location /status {
    vhost_traffic_status_display;
    vhost_traffic_status_display_format prometheus;
    allow $PROMETHEUS_SERVER;
    deny all;
  }
}
EOF
  nginx -t && systemctl restart nginx
  echo -e "${GREEN}nginx VTS модуль успешно установлен${NC}"
fi

# === Обновление фаервола для Hestia CP ===
# Порты + комментарии
declare -A MONITORING_PORTS=(
    ["8088"]="Nginx_VTS"
    ["9100"]="Node_Exporter"
    ["9109"]="Process_Exporter"
)
# Backup
cp "$HESTIA_RULES_FILE" "$HESTIA_RULES_FILE.bak.$(date +%s)"

echo -e "${BLUE}Добавление правил в Hestia Firewall...${NC}"

for PORT in "${!MONITORING_PORTS[@]}"; do
    COMMENT="${MONITORING_PORTS[$PORT]}"

    RULE="ACTION='ACCEPT' PROTOCOL='TCP' PORT='$PORT' IP='$PROMETHEUS_SERVER' COMMENT='$COMMENT' SUSPENDED='no'"

    # Проверка наличия правила
    if grep -q "PROTOCOL='TCP' PORT='$PORT' IP='$PROMETHEUS_SERVER'" "$HESTIA_RULES_FILE"; then
        echo "Правило уже существует для порта $PORT"
    else
        # Найти последний RULE ID
        LAST_ID=$(grep -o "RULE='[0-9]\+'" "$HESTIA_RULES_FILE" | grep -o "[0-9]\+" | sort -n | tail -1)
        NEW_ID=$((LAST_ID + 1))

        FULL_RULE="RULE='$NEW_ID' $RULE TIME='$(date +%H:%M:%S)' DATE='$(date +%Y-%m-%d)'"

        echo "$FULL_RULE" >> "$HESTIA_RULES_FILE"
        echo "Добавлено: $FULL_RULE"
    fi
done

echo -e "${BLUE}Применение правил...${NC}"
"$HESTIA_BIN"/v-update-firewall

echo -e "${BLUE}Добавление правил в Hestia Firewall успешно завершено${NC}"
