#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/go/bin:$PATH"

# ==================== CAU HINH REPO MAC DINH ====================
GITHUB_REPO="tech-tnitechsolve/Shield_Proxy"
GITHUB_BRANCH="main"
# ================================================================

DASH_PORT="8888"
START_PORT="10001"
INIT_ADMIN_USER="admin"
INIT_ADMIN_PASS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)        GITHUB_REPO="${2:-$GITHUB_REPO}"; shift 2 ;;
    --branch)      GITHUB_BRANCH="${2:-$GITHUB_BRANCH}"; shift 2 ;;
    --dash-port)   DASH_PORT="${2:-8888}"; shift 2 ;;
    --start-port)  START_PORT="${2:-10001}"; shift 2 ;;
    --admin-user)  INIT_ADMIN_USER="${2:-admin}"; shift 2 ;;
    --admin-pass)  INIT_ADMIN_PASS="${2:-}"; shift 2 ;;
    --uninstall)
      echo "[*] Dang go bo ProxyShield Pro..."
      systemctl disable --now proxy-shield 2>/dev/null || true
      rm -f /etc/systemd/system/proxy-shield.service \
            /usr/local/bin/proxy-shield \
            /usr/local/bin/ps-health \
            /usr/local/bin/ps-update \
            /usr/local/bin/ps-firewall.sh \
            /etc/cron.d/proxy-shield-backup \
            /etc/sysctl.d/99-proxyshield.conf
      rm -rf /opt/proxy-shield-src
      systemctl daemon-reload
      echo "[+] Da go bo sach se (cau hinh tai /var/lib/proxy-shield van duoc giu lai)."
      exit 0
      ;;
    *) echo "[!] Tham so khong hop le: $1"; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "[!] Vui long chay bang quyen root: sudo bash ..."; exit 1; }
command -v apt-get >/dev/null 2>&1 || { echo "[!] Script ho tro Ubuntu/Debian (apt-get)."; exit 1; }

SRC_DIR="/opt/proxy-shield-src"
DATA_DIR="/var/lib/proxy-shield"
BIN_PATH="/usr/local/bin/proxy-shield"
SVC_PATH="/etc/systemd/system/proxy-shield.service"
IS_FRESH=0
[[ ! -f "${DATA_DIR}/config.json" ]] && IS_FRESH=1

echo "[*] 1/6. Cai dat goi phu thuoc & cong cu giam sat..."
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=60 update -y -qq
apt-get -o DPkg::Lock::Timeout=60 install -y -qq --no-install-recommends \
  curl ca-certificates tar vnstat tcpdump iproute2 conntrack iptables >/dev/null 2>&1 || true

# Dam bao Go >= 1.18
NEED_GO=0
if ! command -v go >/dev/null 2>&1; then
  NEED_GO=1
else
  GO_MINOR=$(go version | sed -n 's/.*go1\.\([0-9]*\).*/\1/p' || echo 0)
  (( ${GO_MINOR:-0} < 18 )) && NEED_GO=1
fi

if (( NEED_GO == 1 )); then
  apt-get -o DPkg::Lock::Timeout=60 install -y -qq golang-go >/dev/null 2>&1 || true
  GO_MINOR=$(go version 2>/dev/null | sed -n 's/.*go1\.\([0-9]*\).*/\1/p' || echo 0)
  if (( ${GO_MINOR:-0} < 18 )); then
    ARCH=$(uname -m)
    case "$ARCH" in
      x86_64|amd64) GO_ARCH="amd64" ;;
      aarch64|arm64) GO_ARCH="arm64" ;;
      *) echo "[!] Kien truc CPU khong ho tro: $ARCH"; exit 1 ;;
    esac
    GO_VER=$(curl -fsSL "https://go.dev/VERSION?m=text" 2>/dev/null | head -n1 || echo "go1.23.6")
    echo "[*] Dang tai Go chinh thuc (${GO_VER}-${GO_ARCH})..."
    curl -4 -fsSL "https://go.dev/dl/${GO_VER}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz && rm -f /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:$PATH"
  fi
fi

echo "[*] 2/6. Xoa cache & tai ma nguon moi nhat tu GitHub..."
rm -rf "$SRC_DIR" && mkdir -p "$SRC_DIR" "$DATA_DIR"

LOCAL_SCRIPT="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
if [[ -n "$LOCAL_SCRIPT" && -f "$LOCAL_SCRIPT" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "$LOCAL_SCRIPT")" && pwd)"
fi

if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/go.mod" && -f "$SCRIPT_DIR/main.go" && -f "$SCRIPT_DIR/ui.html" ]]; then
  echo "[*] Build tu thu muc local: $SCRIPT_DIR"
  cp -f "$SCRIPT_DIR"/*.go "$SCRIPT_DIR/go.mod" "$SCRIPT_DIR/ui.html" "$SRC_DIR/"
else
  LATEST_SHA=$(curl -4 -fsSL -H "Accept: application/vnd.github.sha" -H "Cache-Control: no-cache" \
    "https://api.github.com/repos/${GITHUB_REPO}/commits/${GITHUB_BRANCH}?t=$(date +%s)" 2>/dev/null || echo "")

  TMP_TAR="/tmp/proxyshield.tar.gz"
  TMP_EXT="/tmp/proxyshield-extract"
  rm -rf "$TMP_TAR" "$TMP_EXT" && mkdir -p "$TMP_EXT"

  if [[ "$LATEST_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    echo "[*] Bat duoc Commit moi nhat: ${LATEST_SHA:0:7} (Bypass cache GitHub thanh cong)"
    TAR_URL="https://github.com/${GITHUB_REPO}/archive/${LATEST_SHA}.tar.gz"
  else
    echo "[*] Tai truc tiep nhanh ${GITHUB_BRANCH} (No-cache query)..."
    TAR_URL="https://github.com/${GITHUB_REPO}/archive/refs/heads/${GITHUB_BRANCH}.tar.gz?t=$(date +%s)"
  fi

  curl -4 -fsSL -H "Cache-Control: no-cache" "$TAR_URL" -o "$TMP_TAR"
  tar -xzf "$TMP_TAR" -C "$TMP_EXT" --strip-components=1
  cp -f "$TMP_EXT"/*.go "$TMP_EXT/go.mod" "$TMP_EXT/ui.html" "$SRC_DIR/"
  rm -rf "$TMP_TAR" "$TMP_EXT"
fi

echo "[*] 3/6. Bien dich sach binary Go native (CGO_ENABLED=0, rebuild -a)..."
(cd "$SRC_DIR" && CGO_ENABLED=0 go build -a -ldflags="-s -w" -o "$BIN_PATH" .)
chmod +x "$BIN_PATH"

echo "[*] 4/6. Toi uu Kernel & Tu dong go rule REJECT cua Oracle Ubuntu..."
END_PORT=$(( START_PORT + 2500 ))
modprobe nf_conntrack 2>/dev/null || true
modprobe tcp_bbr 2>/dev/null || true

cat << EOF > /etc/sysctl.d/99-proxyshield.conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 4
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_local_reserved_ports = ${DASH_PORT},${START_PORT}-${END_PORT}
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 16384
net.netfilter.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
fs.file-max = 2097152
fs.nr_open = 2097152
EOF
sysctl --system >/dev/null 2>&1 || true

# Script firewall chay moi lan khoi dong service de chong Oracle REJECT tro lai sau reboot
cat << EOF > /usr/local/bin/ps-firewall.sh
#!/usr/bin/env bash
if command -v iptables >/dev/null 2>&1; then
  while iptables -C INPUT -j REJECT --reject-with icmp-host-prohibited 2>/dev/null; do
    iptables -D INPUT -j REJECT --reject-with icmp-host-prohibited 2>/dev/null || break
  done
  iptables -C INPUT -p tcp --dport "${DASH_PORT}" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "${DASH_PORT}" -j ACCEPT 2>/dev/null || true
  iptables -C INPUT -p tcp --dport "${START_PORT}:${END_PORT}" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "${START_PORT}:${END_PORT}" -j ACCEPT 2>/dev/null || true
fi
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "${DASH_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${START_PORT}:${END_PORT}/tcp" >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod +x /usr/local/bin/ps-firewall.sh
/usr/local/bin/ps-firewall.sh
if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1 || true; fi

echo "[*] 5/6. Cai dat Auto-Backup, 'ps-health' va 'ps-update'..."
mkdir -p /var/backups/proxy-shield
cat << 'EOF' > /etc/cron.d/proxy-shield-backup
0 3 * * * root cp -f /var/lib/proxy-shield/config.json /var/backups/proxy-shield/config.$(date +\%F).json && find /var/backups/proxy-shield -name "config.*.json" -mtime +7 -delete
EOF
chmod 644 /etc/cron.d/proxy-shield-backup
systemctl enable --now vnstat >/dev/null 2>&1 || true

cat << 'EOF' > /usr/local/bin/ps-health
#!/usr/bin/env bash
echo "================ [PROXYSHIELD ORACLE 1-6 HEALTH] ================"
echo "Service Status : $(systemctl is-active proxy-shield)"
echo "Uptime / Load  : $(uptime)"
echo "RAM Usage      : $(free -m | awk '/Mem:/{printf "%dMB / %dMB (Avail: %dMB)", $3, $2, $7}')"
LISTEN_PORTS=$(ss -tln | awk '{print $4}' | grep -cE ':1[0-9]{4}$|:2[0-9]{4}$' || echo 0)
ESTAB=$(ss -tan state established | grep -vc 'Recv-Q' || echo 0)
CLOSE_W=$(ss -tan state close-wait | grep -vc 'Recv-Q' || echo 0)
TIME_W=$(ss -tan state time-wait | grep -vc 'Recv-Q' || echo 0)
CONN_CUR=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
CONN_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
echo "Listening Ports: ${LISTEN_PORTS} cong proxy"
echo "TCP Sockets    : ESTAB=${ESTAB} | CLOSE_WAIT=${CLOSE_W} | TIME_WAIT=${TIME_W}"
echo "Conntrack      : ${CONN_CUR} / ${CONN_MAX}"
echo "-----------------------------------------------------------------"
echo "Luu luong thang (Gioi han Free Oracle: 10 TB Outbound/thang):"
vnstat -m 2>/dev/null | tail -n 6 || echo "vnstat dang thu thap du lieu..."
echo "================================================================="
EOF
chmod +x /usr/local/bin/ps-health

cat << EOF > /usr/local/bin/ps-update
#!/usr/bin/env bash
set -euo pipefail
[[ \$EUID -eq 0 ]] || { echo "[!] Chay bang quyen root: sudo ps-update"; exit 1; }
SHA=\$(curl -4 -sSL -H "Accept: application/vnd.github.sha" -H "Cache-Control: no-cache" "https://api.github.com/repos/${GITHUB_REPO}/commits/${GITHUB_BRANCH}?t=\$(date +%s)" 2>/dev/null || echo "")
REF="${GITHUB_BRANCH}"
[[ "\$SHA" =~ ^[0-9a-f]{40}\$ ]] && REF="\$SHA"
echo "[*] Dang cap nhat tu commit: \${REF}"
curl -4 -sSL -H "Cache-Control: no-cache" "https://raw.githubusercontent.com/${GITHUB_REPO}/\${REF}/install.sh?t=\$(date +%s)" | tr -d '\r' | bash -s -- --repo "${GITHUB_REPO}" --branch "${GITHUB_BRANCH}" --dash-port "${DASH_PORT}" --start-port "${START_PORT}"
EOF
chmod +x /usr/local/bin/ps-update

echo "[*] 6/6. Kich hoat Systemd Service..."
EXEC_ARGS="--dash-port=${DASH_PORT} --data-dir=${DATA_DIR} --init-admin-user=${INIT_ADMIN_USER} --init-start-port=${START_PORT}"
if [[ -n "$INIT_ADMIN_PASS" ]]; then
  EXEC_ARGS="${EXEC_ARGS} --init-admin-pass=${INIT_ADMIN_PASS}"
fi

cat << EOF > "$SVC_PATH"
[Unit]
Description=ProxyShield v2.0 Pro Gateway & Deep Inspector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/local/bin/ps-firewall.sh
ExecStart=${BIN_PATH} ${EXEC_ARGS}
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now proxy-shield
systemctl restart proxy-shield

PUB_IP=$(curl -4 -s --max-time 3 https://api.ipify.org 2>/dev/null || echo "YOUR_VPS_IP")
echo "=========================================================================="
echo " CAI DAT THANH CONG PROXYSHIELD v2.0 PRO!"
echo "--------------------------------------------------------------------------"
echo "  URL Dashboard : http://${PUB_IP}:${DASH_PORT}"
if (( IS_FRESH == 1 )) && [[ -z "$INIT_ADMIN_PASS" ]]; then
  echo "  Khoi tao Admin: Mo link tren de TAO TAI KHOAN & MAT KHAU truc tiep!"
else
  echo "  Cau hinh      : Da giu nguyen / su dung thong tin Admin da cau hinh."
fi
echo "  Lenh kiem tra : sudo ps-health"
echo "  Lenh cap nhat : sudo ps-update"
echo "=========================================================================="
systemctl status proxy-shield --no-pager