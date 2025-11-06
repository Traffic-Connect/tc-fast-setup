#!/usr/bin/env bash
# bootstrap-tc.sh
# Автоматический скрипт для клонирования и установки репозиториев Traffic-Connect
# Запускать под root: sudo bash ./bootstrap-tc.sh

set -o pipefail
# не выходим при ошибке — аккумулируем статусы и в конце покажем
# но выводим ошибки в лог

# === Цвета ===
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # no color

LOG="/var/log/tc-bootstrap.log"
exec > >(tee -a "$LOG") 2>&1

echo -e "${BOLD}${BLUE}=== START bootstrap: $(date -Iseconds) ===${NC}"

# --- prompt for credentials (for private repos) ---
read -rp "Если нужны приватные репо: введите Git username (оставьте пустым если не нужно): " GIT_USER
if [[ -n "$GIT_USER" ]]; then
  # use -s for silent token input
  read -rsp "Введите Git token / пароль (ввод скрыт): " GIT_TOKEN
  echo
  # create temporary ~/.netrc for github.com
  NETRC_FILE="$HOME/.netrc.tc_tmp"
  cat > "$NETRC_FILE" <<EOF
machine github.com
login $GIT_USER
password $GIT_TOKEN
EOF
  chmod 600 "$NETRC_FILE"
  export GIT_ASKPASS="" # prevent git asking interactively
  export NETRC_USED="$NETRC_FILE"
  echo "Created temporary netrc for github.com -> $NETRC_FILE"
else
  NETRC_USED=""
  echo "No git credentials provided — публичные репо только."
fi

# helper functions
report_errors=()
status_ok()   { echo -e "${GREEN}[ OK ]${NC} $1"; }
status_fail() { echo -e "${RED}[FAIL]${NC} $1"; report_errors+=("$1"); }

run_cmd() {
  local desc="$1"; shift
  echo -e "${BLUE}->${NC} $desc"
  if "$@"; then
    status_ok "$desc"
    return 0
  else
    status_fail "$desc"
    return 1
  fi
}

# clone helper: clone or pull if exists
clone_or_pull() {
  local repo_url="$1"
  local target_dir="$2"
  local use_netrc="$3" # if "yes" will set GIT_TERMINAL_PROMPT=0 and use NETRC via env
  mkdir -p "$target_dir"
  if [[ -d "$target_dir/.git" ]]; then
    echo "Repository already exists in $target_dir — pulling..."
    (cd "$target_dir" && if [[ "$use_netrc" == "yes" && -n "$NETRC_USED" ]]; then GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_SSL_NO_VERIFY= false git pull --rebase; else git pull --rebase; fi)
    return $?
  else
    echo "Cloning $repo_url -> $target_dir"
    if [[ "$use_netrc" == "yes" && -n "$NETRC_USED" ]]; then
      # run git with NETRC override by setting HOME to a temp dir containing .netrc
      TMPHOME=$(mktemp -d)
      cp "$NETRC_USED" "$TMPHOME/.netrc"
      chmod 600 "$TMPHOME/.netrc"
      HOME="$TMPHOME" GIT_TERMINAL_PROMPT=0 git clone "$repo_url" "$target_dir"
      rc=$?
      rm -rf "$TMPHOME"
      return $rc
    else
      git clone "$repo_url" "$target_dir"
      return $?
    fi
  fi
}

# add cron safely (idempotent)
add_cron_entry() {
  local cron_expr="$1"
  local marker="$2" # unique marker to identify our entry
  (crontab -l 2>/dev/null || true) | grep -vF "$marker" > /tmp/crontab.$$ || true
  echo "$cron_expr # $marker" >> /tmp/crontab.$$
  crontab /tmp/crontab.$$
  rm -f /tmp/crontab.$$
  status_ok "Added cron: $cron_expr"
}

# run file if present and executable (or make executable)
run_setup_script() {
  local dir="$1"
  local setup="$2" # setup script name (e.g., setup.sh) and optional args
  if [[ -f "$dir/$setup" || -f "$dir/${setup%% *}" ]]; then
    chmod +x "$dir/${setup%% *}" || true
    (cd "$dir" && ./"${setup%% *}" ${setup#* } )
    return $?
  else
    return 10
  fi
}

# --- Repositories and actions (по порядку) ---
# Для приватных репозиториев устанавливай третьим аргументом "yes" (использовать NETRC)
# Формат: clone_or_pull repo target_dir use_netrc
echo
echo -e "${BOLD}${BLUE}=== 1) tc-nginx-badbot ===${NC}"
REPO=https://github.com/Traffic-Connect/tc-nginx-badbot.git
TARGET=/root/tc-nginx-badbot
if clone_or_pull "$REPO" "$TARGET" "yes"; then
  run_cmd "chmod 0755 $TARGET/badbot.sh" chmod 0755 "$TARGET/badbot.sh" || true
  # Add cron (idempotent)
  add_cron_entry "00 03 * * * $TARGET/badbot.sh" "tc-nginx-badbot-badbot.sh"
  run_cmd "Run badbot script check" "$TARGET/badbot.sh" || status_fail "badbot.sh returned nonzero"
  run_cmd "nginx -t" nginx -t
  if [[ $? -eq 0 ]]; then
    run_cmd "systemctl restart nginx" systemctl restart nginx
  else
    status_fail "nginx config test failed, not restarting nginx"
  fi
else
  status_fail "Clone/pull failed for tc-nginx-badbot"
fi

echo
echo -e "${BOLD}${BLUE}=== 2) tc-link-manager-installer ===${NC}"
REPO=https://github.com/Traffic-Connect/tc-link-manager-installer.git
TARGET=/root/link-manager
mkdir -p "$TARGET"
if clone_or_pull "$REPO" "$TARGET" "yes"; then
  run_cmd "chmod +x $TARGET/setup.sh" chmod +x "$TARGET/setup.sh" || true
  run_cmd "Run link-manager setup" bash -c "cd $TARGET && ./setup.sh"
  # check php script run
  run_cmd "php /root/link-manager/script-link-manager.php" php /root/link-manager/script-link-manager.php || status_fail "link-manager test script failed"
else
  status_fail "Clone/pull failed for tc-link-manager-installer"
fi

echo
echo -e "${BOLD}${BLUE}=== 3) schemes-scripts ===${NC}"
REPO=https://github.com/Traffic-Connect/schemes-scripts.git
TARGET=/root/schemas
mkdir -p "$TARGET"
if clone_or_pull "$REPO" "$TARGET" "yes"; then
  run_cmd "chmod +x $TARGET/setup.sh" chmod +x "$TARGET/setup.sh" || true
  run_cmd "Run schemas setup" bash -c "cd $TARGET && ./setup.sh"
else
  status_fail "Clone/pull failed for schemes-scripts"
fi

echo
echo -e "${BOLD}${BLUE}=== 4) script-google-auth ===${NC}"
REPO=https://github.com/Traffic-Connect/script-google-auth.git
TARGET=/root/google-auth
mkdir -p "$TARGET"
if clone_or_pull "$REPO" "$TARGET" "yes"; then
  run_cmd "chmod +x $TARGET/setup.sh" chmod +x "$TARGET/setup.sh" || true
  run_cmd "Run google-auth setup" bash -c "cd $TARGET && ./setup.sh"
else
  status_fail "Clone/pull failed for script-google-auth"
fi

echo
echo -e "${BOLD}${BLUE}=== 5) script-tc-api-site-details ===${NC}"
REPO=https://github.com/Traffic-Connect/script-tc-api-site-details.git
TARGET=/root/tc-api-site-details
mkdir -p "$TARGET"
if clone_or_pull "$REPO" "$TARGET" "yes"; then
  run_cmd "chmod +x $TARGET/setup.sh" chmod +x "$TARGET/setup.sh" || true
  run_cmd "Run tc-api-site-details setup (-upd)" bash -c "cd $TARGET && ./setup.sh -upd"
else
  status_fail "Clone/pull failed for script-tc-api-site-details"
fi

echo
echo -e "${BOLD}${BLUE}=== 6) Hestia-System-Info ===${NC}"
REPO=https://github.com/Traffic-Connect/Hestia-System-Info.git
TARGET=/root/Hestia-System-Info
if clone_or_pull "$REPO" "$TARGET" "yes"; then
  run_cmd "chmod +x $TARGET/setup.sh" chmod +x "$TARGET/setup.sh" || true
  run_cmd "Install Hestia-System-Info (sudo ./setup.sh)" bash -c "cd $TARGET && sudo ./setup.sh"
else
  status_fail "Clone/pull failed for Hestia-System-Info"
fi

echo
echo -e "${BOLD}${BLUE}=== 7) backups-sites ===${NC}"
REPO=https://github.com/Traffic-Connect/backups-sites.git
TARGET=/root/backups
mkdir -p "$TARGET"
if clone_or_pull "$REPO" "$TARGET" "yes"; then
  run_cmd "chmod +x $TARGET/install.sh" chmod +x "$TARGET/install.sh" || true
  run_cmd "Run backups install" bash -c "cd $TARGET && ./install.sh"
else
  status_fail "Clone/pull failed for backups-sites"
fi

# cleanup temporary netrc
if [[ -n "$NETRC_USED" && -f "$NETRC_USED" ]]; then
  shred -u "$NETRC_USED" 2>/dev/null || rm -f "$NETRC_USED"
  echo "Removed temporary netrc file."
fi

echo
echo -e "${BOLD}${BLUE}=== SUMMARY ===${NC}"
if [[ ${#report_errors[@]} -eq 0 ]]; then
  echo "All steps completed successfully."
  status_ok "Bootstrap finished without errors"
else
  echo -e "${RED}Some steps failed (see lines above and $LOG). Failures:${NC}"
  for e in "${report_errors[@]}"; do
    echo -e " - ${RED}$e${NC}"
  done
  status_fail "Bootstrap finished with errors"
fi

echo -e "${BOLD}${BLUE}=== END bootstrap: $(date -Iseconds) ===${NC}"
