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
            /usr/local/bin/ps-cli \
            /usr/local/bin/ps-firewall.sh \
            /etc/cron.d/proxy-shield-backup \
            /etc/sysctl.d/99-proxyshield.conf \
            /etc/systemd/journald.conf.d/99-proxyshield.conf \
            /etc/security/limits.d/99-proxyshield.conf
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

echo "[*] 1/7. Cai dat goi phu thuoc, Chrony & cong cu giam sat..."
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=60 update -y -qq
apt-get -o DPkg::Lock::Timeout=60 install -y -qq --no-install-recommends \
  curl ca-certificates tar vnstat tcpdump iproute2 conntrack iptables chrony python3 >/dev/null 2>&1 || true

systemctl enable --now chrony >/dev/null 2>&1 || true
systemctl disable --now snapd snapd.socket >/dev/null 2>&1 || true

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

echo "[*] 2/7. Xoa cache & tai ma nguon moi nhat tu GitHub..."
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

echo "[*] 3/7. Bien dich sach binary Go native (CGO_ENABLED=0, rebuild -a)..."
(cd "$SRC_DIR" && CGO_ENABLED=0 go build -a -ldflags="-s -w" -o "$BIN_PATH" .)
chmod +x "$BIN_PATH"

echo "[*] 4/7. Toi uu Kernel, Journald (10M), Nofile Limits (1M)..."
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

mkdir -p /etc/systemd/journald.conf.d /etc/security/limits.d
cat << 'EOF' > /etc/systemd/journald.conf.d/99-proxyshield.conf
[Journal]
SystemMaxUse=10M
RuntimeMaxUse=5M
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
journalctl --vacuum-size=10M >/dev/null 2>&1 || true

cat << 'EOF' > /etc/security/limits.d/99-proxyshield.conf
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

echo "[*] 5/7. Cau hinh Firewall Ubuntu & tu dong go REJECT Oracle..."
cat << EOF > /usr/local/bin/ps-firewall.sh
#!/usr/bin/env bash
if command -v iptables >/dev/null 2>&1; then
  iptables -P INPUT ACCEPT 2>/dev/null || true
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

# Neu VPS co san oci CLI + ~/.oci/config thi tu mo VCN Security List luon
OCI_CFG=""
for p in /root/.oci/config /home/ubuntu/.oci/config; do [[ -f "$p" ]] && OCI_CFG="$p" && break; done
if command -v oci >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 && [[ -n "$OCI_CFG" ]]; then
  echo "[*] Phat hien OCI CLI config -> Tu dong mo port tren Oracle VCN Security List..."
  TENANCY_OCID=$(awk -F= '/^tenancy=/{print $2}' "$OCI_CFG" | tr -d ' \r' | head -n1)
  if [[ -n "$TENANCY_OCID" ]]; then
    NEW_RULES="[{\"source\":\"0.0.0.0/0\",\"source-type\":\"CIDR_BLOCK\",\"protocol\":\"6\",\"is-stateless\":false,\"description\":\"ProxyShield-UI\",\"tcp-options\":{\"destination-port-range\":{\"min\":${DASH_PORT},\"max\":${DASH_PORT}}}},{\"source\":\"0.0.0.0/0\",\"source-type\":\"CIDR_BLOCK\",\"protocol\":\"6\",\"is-stateless\":false,\"description\":\"ProxyShield-Ports\",\"tcp-options\":{\"destination-port-range\":{\"min\":${START_PORT},\"max\":${END_PORT}}}}]"
    for SL_ID in $(OCI_CLI_CONFIG_FILE="$OCI_CFG" oci network security-list list --compartment-id "$TENANCY_OCID" --query 'data[].id' --raw-output 2>/dev/null | jq -r '.[]' 2>/dev/null); do
      CUR=$(OCI_CLI_CONFIG_FILE="$OCI_CFG" oci network security-list get --security-list-id "$SL_ID" --query 'data."ingress-security-rules"' --raw-output 2>/dev/null || echo "[]")
      MERGED=$(jq -c --argjson cur "$CUR" --argjson add "$NEW_RULES" '($cur | map(select(.description != "ProxyShield-UI" and .description != "ProxyShield-Ports"))) + $add')
      OCI_CLI_CONFIG_FILE="$OCI_CFG" oci network security-list update --security-list-id "$SL_ID" --ingress-security-rules "$MERGED" --force >/dev/null 2>&1 || true
    done
  fi
fi

echo "[*] 6/7. Cai dat Auto-Backup, 'ps-health', 'ps-update' va 'ps-cli'..."
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

cat << 'EOF' > /usr/local/bin/ps-cli
#!/usr/bin/env python3
import sys, json, os, secrets, hashlib, subprocess, urllib.request

CFG_PATH = "/var/lib/proxy-shield/config.json"

def load_cfg():
    if not os.path.exists(CFG_PATH):
        sys.exit("Chua thay config.json. Hay chay systemctl start proxy-shield truoc!")
    with open(CFG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_cfg(cfg):
    with open(CFG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(CFG_PATH, 0o600)
    subprocess.run(["systemctl", "restart", "proxy-shield"], check=True)

def pub_ip():
    try:
        return urllib.request.urlopen("https://api.ipify.org", timeout=4).read().decode().strip()
    except Exception:
        return "YOUR_VPS_IP"

def usage():
    print("""Cach dung ps-cli (Dieu khien ProxyShield 100% bang Terminal):
  sudo ps-cli info                            -> Xem thong tin cau hinh & so luong proxy
  sudo ps-cli diag                            -> Chan doan cong 8888 / tuong lua Oracle VCN
  sudo ps-cli set-admin <user> <pass>         -> Dat/doi tai khoan Admin Dashboard
  sudo ps-cli set-auth <user> <pass>          -> Dat/doi Username:Password cho Proxy
  sudo ps-cli load <file_proxies.txt> [proto] -> Nap list proxy Webshare (proto: socks5|http)
  sudo ps-cli export [socks5|http]            -> Xuat toan bo list proxy da boc ra man hinh
  sudo ps-cli test [port]                     -> Test ket noi qua cong (mac dinh 10001)""")

if len(sys.argv) < 2:
    usage(); sys.exit(0)

cmd = sys.argv[1]
if cmd == "diag":
    ip = pub_ip()
    print("=== CHAN DOAN KET NOI DASHBOARD & PROXY ===")
    try:
        res = urllib.request.urlopen("http://127.0.0.1:8888/api/auth/status", timeout=3).read().decode()
        print(f"[OK] Web Dashboard noi bo (127.0.0.1:8888): DANG CHAY ({res.strip()})")
    except Exception as e:
        print(f"[XX] Web Dashboard noi bo KHONG phan hoi: {e}")
    print("[*] Kiem tra cong lang nghe (ss -tln):")
    subprocess.run("ss -tln | grep -E ':8888|:10001'", shell=True)
    print("\n[*] Neu vao http://" + ip + ":8888 bi ERR_CONNECTION_TIMED_OUT:")
    print("    1) Dung SSH Tunnel ngay khong can mo Oracle: ssh -N -L 8888:127.0.0.1:8888 ubuntu@" + ip)
    print("    2) Hoac mo VCN trong OCI Cloud Shell (>_) bang 1 lenh tu dong.")
    sys.exit(0)

cfg = load_cfg()

if cmd == "info":
    lines = [l.strip() for l in cfg.get("proxies_raw", "").splitlines() if l.strip() and not l.strip().startswith("#")]
    print(f"Oracle Public IP : {pub_ip()}")
    print(f"Admin User       : {cfg.get('admin_user') or '(Chua tao)'}")
    print(f"Proxy Auth       : {cfg.get('proxy_user')}:{cfg.get('proxy_pass')}")
    print(f"Start Port       : {cfg.get('start_port', 10001)}")
    print(f"So Proxy Nguon   : {len(lines)}")
    print(f"Tu khoa DoH      : {', '.join(cfg.get('sanitize_keywords', []))}")

elif cmd == "set-admin":
    if len(sys.argv) < 4: sys.exit("Thieu tham so: sudo ps-cli set-admin <user> <pass>")
    u, p = sys.argv[2].strip(), sys.argv[3].strip()
    salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}:{p}".encode()).hexdigest()
    cfg["admin_user"] = u
    cfg["admin_salt"] = salt
    cfg["admin_pass_hash"] = h
    save_cfg(cfg)
    print(f"[OK] Da cap nhat Admin: {u}")

elif cmd == "set-auth":
    if len(sys.argv) < 4: sys.exit("Thieu tham so: sudo ps-cli set-auth <user> <pass>")
    cfg["proxy_user"] = sys.argv[2].strip()
    cfg["proxy_pass"] = sys.argv[3].strip()
    save_cfg(cfg)
    print(f"[OK] Da doi Proxy Auth thanh: {cfg['proxy_user']}:{cfg['proxy_pass']}")

elif cmd == "load":
    if len(sys.argv) < 3: sys.exit("Thieu tham so: sudo ps-cli load /root/proxies.txt [socks5|http]")
    fpath = sys.argv[2]
    proto = sys.argv[3] if len(sys.argv) > 3 else cfg.get("default_up_proto", "socks5")
    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()
    cfg["proxies_raw"] = raw
    cfg["default_up_proto"] = "http" if proto == "http" else "socks5"
    save_cfg(cfg)
    cnt = len([l for l in raw.splitlines() if l.strip() and not l.strip().startswith("#")])
    print(f"[OK] Da nap {cnt} proxy tu {fpath} ({cfg['default_up_proto']}). List tai /root/wrapped_proxies_socks5.txt")

elif cmd == "export":
    scheme = "http" if (len(sys.argv) > 2 and sys.argv[2] == "http") else "socks5"
    ip = pub_ip()
    sp = int(cfg.get("start_port", 10001))
    u, p = cfg.get("proxy_user"), cfg.get("proxy_pass")
    lines = [l.strip() for l in cfg.get("proxies_raw", "").splitlines() if l.strip() and not l.strip().startswith("#")]
    for i in range(len(lines)):
        print(f"{scheme}://{u}:{p}@{ip}:{sp+i}")

elif cmd == "test":
    port = int(sys.argv[2]) if len(sys.argv) > 2 else int(cfg.get("start_port", 10001))
    u, p = cfg.get("proxy_user"), cfg.get("proxy_pass")
    out = subprocess.check_output(["curl", "-4", "-s", "--max-time", "8", "-x", f"socks5://{u}:{p}@127.0.0.1:{port}", "https://api.ipify.org"]).decode().strip()
    print(f"[OK] Cong :{port} thong tuyen -> Exit IP: {out}")

else:
    usage()
EOF
chmod +x /usr/local/bin/ps-cli

echo "[*] 7/7. Kich hoat Systemd Service..."
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
echo "  SSH Tunnel    : ssh -N -L ${DASH_PORT}:127.0.0.1:${DASH_PORT} ubuntu@${PUB_IP}"
if (( IS_FRESH == 1 )) && [[ -z "$INIT_ADMIN_PASS" ]]; then
  echo "  Khoi tao Admin: Mo link tren de TAO TAI KHOAN & MAT KHAU truc tiep!"
else
  echo "  Cau hinh      : Da giu nguyen / su dung thong tin Admin da cau hinh."
fi
echo "  Lenh Terminal : sudo ps-cli  |  sudo ps-health  |  sudo ps-update"
echo "=========================================================================="
systemctl status proxy-shield --no-pager