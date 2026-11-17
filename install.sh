#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/go/bin:$PATH"

# ==================== CAU HINH REPO MAC DINH ====================
GITHUB_REPO="tech-tnitechsolve/Shield_Proxy"
GITHUB_BRANCH="main"
GITHUB_COMMIT=""
# ================================================================

DASH_PORT="8888"
START_PORT="10001"
INIT_ADMIN_USER="admin"
INIT_ADMIN_PASS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)        GITHUB_REPO="${2:-$GITHUB_REPO}"; shift 2 ;;
    --branch)      GITHUB_BRANCH="${2:-$GITHUB_BRANCH}"; shift 2 ;;
    --commit)      GITHUB_COMMIT="${2:-}"; shift 2 ;;
    --dash-port)   DASH_PORT="${2:-8888}"; shift 2 ;;
    --start-port)  START_PORT="${2:-10001}"; shift 2 ;;
    --admin-user)  INIT_ADMIN_USER="${2:-admin}"; shift 2 ;;
    --admin-pass)  INIT_ADMIN_PASS="${2:-}"; shift 2 ;;
    --uninstall)
      echo "[*] Dang go bo ProxyShield Pro (giu lai data cau hinh)..."
      systemctl disable --now proxy-shield 2>/dev/null || true
      rm -f /etc/systemd/system/proxy-shield.service \
            /usr/local/bin/proxy-shield /usr/local/bin/proxy-shield.bak /usr/local/bin/proxy-shield.new \
            /usr/local/bin/ps-health /usr/local/bin/ps-update /usr/local/bin/ps-cli /usr/local/bin/ps-firewall.sh \
            /etc/cron.d/proxy-shield-backup /etc/sysctl.d/99-proxyshield.conf \
            /etc/systemd/journald.conf.d/99-proxyshield.conf /etc/security/limits.d/99-proxyshield.conf
      rm -rf /opt/proxy-shield-src
      systemctl daemon-reload
      echo "[+] Da go bo xong (cau hinh tai /var/lib/proxy-shield van duoc giu lai)."
      exit 0
      ;;
    --purge)
      echo "[*] Dang xoa sach 100% ProxyShield & toan bo du lieu..."
      systemctl disable --now proxy-shield 2>/dev/null || true
      rm -rf /etc/systemd/system/proxy-shield.service \
             /usr/local/bin/proxy-shield /usr/local/bin/proxy-shield.bak /usr/local/bin/proxy-shield.new \
             /usr/local/bin/ps-health /usr/local/bin/ps-update /usr/local/bin/ps-cli /usr/local/bin/ps-firewall.sh \
             /etc/cron.d/proxy-shield-backup /etc/sysctl.d/99-proxyshield.conf \
             /etc/systemd/journald.conf.d/99-proxyshield.conf /etc/security/limits.d/99-proxyshield.conf \
             /opt/proxy-shield-src /var/lib/proxy-shield /var/backups/proxy-shield /root/wrapped_proxies*.txt
      systemctl daemon-reload
      sysctl --system >/dev/null 2>&1 || true
      echo "[+] Da xoa sach khong con dau vet!"
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

echo "[*] 1/7. Kiem tra goi phu thuoc, Chrony & Go compiler..."
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=60 update -y -qq
apt-get -o DPkg::Lock::Timeout=60 install -y -qq --no-install-recommends \
  curl ca-certificates tar vnstat tcpdump iproute2 conntrack iptables chrony python3 >/dev/null 2>&1 || true

systemctl enable --now chrony >/dev/null 2>&1 || true
systemctl disable --now snapd snapd.socket >/dev/null 2>&1 || true

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
    GO_VER=$(curl -4 -fsSL --retry 2 "https://go.dev/VERSION?m=text" 2>/dev/null | head -n1 || echo "go1.23.6")
    echo "[*] Dang tai Go chinh thuc (${GO_VER}-${GO_ARCH})..."
    curl -4 -fsSL --retry 3 "https://go.dev/dl/${GO_VER}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz && rm -f /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:$PATH"
  fi
fi

echo "[*] 2/7. Tai ma nguon moi nhat vao vung tam (chua cham vao proxy dang chay)..."
TMP_SRC="/tmp/proxyshield-src-build"
rm -rf "$TMP_SRC" && mkdir -p "$TMP_SRC" "$DATA_DIR" /var/backups/proxy-shield

LOCAL_SCRIPT="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
if [[ -n "$LOCAL_SCRIPT" && -f "$LOCAL_SCRIPT" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "$LOCAL_SCRIPT")" && pwd)"
fi

if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/go.mod" && -f "$SCRIPT_DIR/main.go" && -f "$SCRIPT_DIR/rules.go" && -f "$SCRIPT_DIR/ui.html" && -f "$SCRIPT_DIR/sanitize_domains.txt" && -f "$SCRIPT_DIR/block_domains.txt" ]]; then
  echo "[*] Build tu thu muc local: $SCRIPT_DIR"
  cp -f "$SCRIPT_DIR"/*.go "$SCRIPT_DIR/go.mod" "$SCRIPT_DIR/ui.html" "$SCRIPT_DIR/sanitize_domains.txt" "$SCRIPT_DIR/block_domains.txt" "$TMP_SRC/"
else
  LATEST_SHA="$GITHUB_COMMIT"
  if [[ -z "$LATEST_SHA" ]]; then
    LATEST_SHA=$(curl -4 -fsSL --retry 2 -H "Accept: application/vnd.github.sha" -H "Cache-Control: no-cache" \
      "https://api.github.com/repos/${GITHUB_REPO}/commits/${GITHUB_BRANCH}?t=$(date +%s)" 2>/dev/null || echo "")
  fi

  TMP_TAR="/tmp/proxyshield.tar.gz"
  TMP_EXT="/tmp/proxyshield-extract"
  rm -rf "$TMP_TAR" "$TMP_EXT" && mkdir -p "$TMP_EXT"

  if [[ "$LATEST_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    echo "[*] Bat duoc Commit moi nhat: ${LATEST_SHA:0:7} (Bypass cache GitHub)"
    TAR_URL="https://github.com/${GITHUB_REPO}/archive/${LATEST_SHA}.tar.gz"
  else
    echo "[XX] Khong lay duoc commit SHA hop le; tu choi build tu nhanh co the thay doi."
    exit 1
  fi

  curl -4 -fsSL --retry 3 --retry-delay 2 -H "Cache-Control: no-cache" "$TAR_URL" -o "$TMP_TAR"
  tar -xzf "$TMP_TAR" -C "$TMP_EXT" --strip-components=1

  for req_f in go.mod main.go dns.go proxy.go rules.go web.go ui.html sanitize_domains.txt block_domains.txt; do
    if [[ ! -f "$TMP_EXT/$req_f" ]]; then
      echo "[XX] Thieu file '$req_f' tren GitHub! Huy cap nhat -> Dich vu cu van chay an toan."
      rm -rf "$TMP_TAR" "$TMP_EXT" "$TMP_SRC"
      exit 1
    fi
  done

  cp -f "$TMP_EXT"/*.go "$TMP_EXT/go.mod" "$TMP_EXT/ui.html" "$TMP_EXT/sanitize_domains.txt" "$TMP_EXT/block_domains.txt" "$TMP_SRC/"
  rm -rf "$TMP_TAR" "$TMP_EXT"
fi

echo "[*] 3/7. Bien dich thu sang ${BIN_PATH}.new & kiem tra chong ro ri (--self-test)..."
if ! (cd "$TMP_SRC" && CGO_ENABLED=0 go build -a -ldflags="-s -w" -o "${BIN_PATH}.new" .); then
  echo "[XX] LOI BIEN DICH! Huy cap nhat -> Dich vu proxy cu van dang chay an toan 100%."
  rm -rf "$TMP_SRC" "${BIN_PATH}.new"
  exit 1
fi
chmod +x "${BIN_PATH}.new"

if ! "${BIN_PATH}.new" --self-test --data-dir="${DATA_DIR}"; then
  echo "[XX] SELF-TEST THAT BAI! Huy cap nhat -> Proxy cu van hoat dong binh thuong."
  rm -rf "$TMP_SRC" "${BIN_PATH}.new"
  exit 1
fi
rm -rf "$SRC_DIR" && mv "$TMP_SRC" "$SRC_DIR"

echo "[*] 4/7. Toi uu Kernel, Journald (10M), Limits (1M)..."
ACTIVE_START="$START_PORT"
if [[ -f "${DATA_DIR}/config.json" ]]; then
  CFG_START=$(python3 -c 'import json; print(json.load(open("/var/lib/proxy-shield/config.json")).get("start_port", 10001))' 2>/dev/null || echo "$START_PORT")
  [[ "$CFG_START" =~ ^[0-9]+$ ]] && ACTIVE_START="$CFG_START"
fi
END_PORT=$(( ACTIVE_START + 2500 ))
(( END_PORT > 65000 )) && END_PORT=65000

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
net.ipv4.ip_local_reserved_ports = ${DASH_PORT},${ACTIVE_START}-${END_PORT}
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

echo "[*] 5/7. Cau hinh Firewall dong (tu doc start_port & go REJECT Oracle)..."
cat << EOF > /usr/local/bin/ps-firewall.sh.tmp
#!/usr/bin/env bash
D_PORT="${DASH_PORT}"
S_PORT="${START_PORT}"
if [[ -f "${DATA_DIR}/config.json" ]]; then
  CFG_S=\$(python3 -c 'import json; print(json.load(open("${DATA_DIR}/config.json")).get("start_port", ${START_PORT}))' 2>/dev/null || echo "${START_PORT}")
  [[ "\$CFG_S" =~ ^[0-9]+$ ]] && S_PORT="\$CFG_S"
fi
E_PORT=\$(( S_PORT + 2500 ))
(( E_PORT > 65000 )) && E_PORT=65000

if command -v iptables >/dev/null 2>&1; then
  iptables -P INPUT ACCEPT 2>/dev/null || true
  while iptables -C INPUT -j REJECT --reject-with icmp-host-prohibited 2>/dev/null; do
    iptables -D INPUT -j REJECT --reject-with icmp-host-prohibited 2>/dev/null || break
  done
  iptables -C INPUT -p tcp --dport "\$D_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "\$D_PORT" -j ACCEPT 2>/dev/null || true
  iptables -C INPUT -p tcp --dport "\${S_PORT}:\${E_PORT}" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "\${S_PORT}:\${E_PORT}" -j ACCEPT 2>/dev/null || true
fi
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "\${D_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "\${S_PORT}:\${E_PORT}/tcp" >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod +x /usr/local/bin/ps-firewall.sh.tmp
mv -f /usr/local/bin/ps-firewall.sh.tmp /usr/local/bin/ps-firewall.sh
/usr/local/bin/ps-firewall.sh
if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1 || true; fi

echo "[*] 6/7. Cai dat Auto-Backup, 'ps-health', 'ps-update' va 'ps-cli'..."
cat << 'EOF' > /etc/cron.d/proxy-shield-backup
0 3 * * * root cp -f /var/lib/proxy-shield/config.json /var/backups/proxy-shield/config.$(date +\%F).json && find /var/backups/proxy-shield -name "config.*.json" -mtime +7 -delete
EOF
chmod 644 /etc/cron.d/proxy-shield-backup

if [[ -f /etc/vnstat.conf ]]; then
  grep -q 'ExcludeInterface' /etc/vnstat.conf || echo 'ExcludeInterface "veth* docker0 tun* tap*"' >> /etc/vnstat.conf
fi
systemctl enable --now vnstat >/dev/null 2>&1 || true

cat << EOF > /usr/local/bin/ps-health.tmp
#!/usr/bin/env bash
echo "================ [PROXYSHIELD VPS HEALTH] ================"
echo "Service Status : \$(systemctl is-active proxy-shield 2>/dev/null || echo unknown)"
echo "Uptime / Load  : \$(uptime)"
echo "RAM Usage      : \$(free -m | awk '/Mem:/{printf "%dMB / %dMB (Avail: %dMB)", \$3, \$2, \$7}')"
LISTEN_PORTS=\$(ss -tlnp 2>/dev/null | awk -v dp=":${DASH_PORT}\$" '/"proxy-shield"/ && \$4 !~ dp {c++} END{print c+0}')
ESTAB=\$(ss -tan state established 2>/dev/null | awk 'NR>1{c++} END{print c+0}')
CLOSE_W=\$(ss -tan state close-wait 2>/dev/null | awk 'NR>1{c++} END{print c+0}')
TIME_W=\$(ss -tan state time-wait 2>/dev/null | awk 'NR>1{c++} END{print c+0}')
CONN_CUR=\$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
CONN_MAX=\$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
echo "Listening Ports: \${LISTEN_PORTS} cong proxy"
echo "TCP Sockets    : ESTAB=\${ESTAB} | CLOSE_WAIT=\${CLOSE_W} | TIME_WAIT=\${TIME_W}"
echo "Conntrack      : \${CONN_CUR} / \${CONN_MAX}"
echo "----------------------------------------------------------"
echo "Luu luong thang (Gioi han Free Oracle: 10 TB Outbound/thang):"
vnstat -m 2>/dev/null | tail -n 6 || echo "vnstat dang thu thap du lieu..."
echo "=========================================================="
EOF
chmod +x /usr/local/bin/ps-health.tmp
mv -f /usr/local/bin/ps-health.tmp /usr/local/bin/ps-health

cat << EOF > /usr/local/bin/ps-update.tmp
#!/usr/bin/env bash
set -euo pipefail
{
  [[ \$EUID -eq 0 ]] || { echo "[!] Chay bang quyen root: sudo ps-update"; exit 1; }
  STATUS_FILE="${DATA_DIR}/update-status.json"
  STATUS_TMP="\${STATUS_FILE}.tmp"
  write_status() {
    printf '{"status":"%s","message":"%s","updated_at":"%s"}\n' "\$1" "\$2" "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "\$STATUS_TMP"
    mv -f "\$STATUS_TMP" "\$STATUS_FILE"
  }
  run_update() {
    local SHA SCRIPT_PATH
    write_status "running" "Dang kiem tra phien ban moi..."
    SHA=\$(curl -4 -fsSL --retry 2 -H "Accept: application/vnd.github.sha" -H "Cache-Control: no-cache" "https://api.github.com/repos/${GITHUB_REPO}/commits/${GITHUB_BRANCH}?t=\$(date +%s)") || {
      write_status "failed" "Khong the lay commit SHA tu GitHub."
      return 1
    }
    [[ "\$SHA" =~ ^[0-9a-f]{40}\$ ]] || {
      write_status "failed" "GitHub tra ve commit SHA khong hop le."
      return 1
    }
    write_status "running" "Dang tai va build commit \${SHA:0:7}..."
    SCRIPT_PATH="${DATA_DIR}/install-update.sh"
    curl -4 -fsSL --retry 3 -H "Cache-Control: no-cache" "https://raw.githubusercontent.com/${GITHUB_REPO}/\${SHA}/install.sh" -o "\$SCRIPT_PATH" || {
      write_status "failed" "Khong tai duoc installer tai commit da ghim."
      rm -f "\$SCRIPT_PATH"
      return 1
    }
    if tr -d '\r' < "\$SCRIPT_PATH" | bash -s -- --repo "${GITHUB_REPO}" --branch "${GITHUB_BRANCH}" --commit "\$SHA" --dash-port "${DASH_PORT}" --start-port "${START_PORT}"; then
      local RESULT=0
    else
      local RESULT=\$?
    fi
    rm -f "\$SCRIPT_PATH"
    if (( RESULT == 0 )); then
      write_status "success" "Cap nhat va kiem tra dich vu thanh cong."
    else
      write_status "failed" "Cap nhat that bai; installer da bao toan hoac rollback binary."
      return "\$RESULT"
    fi
  }
  if [[ "\${1:-}" == "--dashboard" ]]; then
    mkdir -p "${DATA_DIR}"
    exec >> "${DATA_DIR}/update.log" 2>&1
  fi
  run_update
  exit 0
}
EOF
chmod +x /usr/local/bin/ps-update.tmp
mv -f /usr/local/bin/ps-update.tmp /usr/local/bin/ps-update

cat << 'EOF' > /usr/local/bin/ps-cli.tmp
#!/usr/bin/env python3
import sys, json, os, secrets, hashlib, subprocess, urllib.request

CFG_PATH = "/var/lib/proxy-shield/config.json"

def load_cfg():
    for p in (CFG_PATH, CFG_PATH + ".bak"):
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
    sys.exit("Chua thay config.json!")

def save_cfg(cfg):
    tmp = CFG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, CFG_PATH)
    subprocess.run(["systemctl", "restart", "proxy-shield"], check=True)

def pub_ip():
    try:
        return urllib.request.urlopen("https://api.ipify.org", timeout=4).read().decode().strip()
    except Exception:
        return "YOUR_VPS_IP"

def usage():
    print("""Cach dung ps-cli:
  sudo ps-cli info                            -> Xem thong tin & so proxy
  sudo ps-cli sync-rules                      -> Dong bo list an & chan tu GitHub vao RAM (0ms rot mang)
  sudo ps-cli diag                            -> Chan doan cong 8888 / tuong lua
  sudo ps-cli set-admin <user> <pass>         -> Dat/doi tai khoan Admin
  sudo ps-cli set-auth <user> <pass>          -> Dat/doi Proxy Auth
  sudo ps-cli load <file_proxies.txt> [proto] -> Nap moi toan bo list proxy nguon
  sudo ps-cli export                          -> Xuat list proxy da boc (1:1 giao thuc)
  sudo ps-cli test [port]                     -> Test ket noi cong (tu nhan dien http/socks5)""")

if len(sys.argv) < 2:
    usage(); sys.exit(0)

cmd = sys.argv[1]
if cmd == "sync-rules":
    subprocess.run(["pkill", "-USR1", "-x", "proxy-shield"], check=True)
    print("[OK] Da kich hoat dong bo sanitize & block rules vao RAM (0ms gian doan proxy)!")
    sys.exit(0)

if cmd == "diag":
    try:
        res = urllib.request.urlopen("http://127.0.0.1:8888/api/auth/status", timeout=3).read().decode()
        print(f"[OK] Dashboard (127.0.0.1:8888): DANG CHAY ({res.strip()})")
    except Exception as e:
        print(f"[XX] Dashboard loi: {e}")
    subprocess.run("ss -tlnp | grep -F '\"proxy-shield\"' | head -n 10", shell=True)
    sys.exit(0)

cfg = load_cfg()
if cmd == "info":
    entries = cfg.get("proxy_entries") or []
    cnt = len(entries) if entries else len([l for l in cfg.get("proxies_raw", "").splitlines() if l.strip() and not l.strip().startswith("#")])
    print(f"VPS Public IP    : {pub_ip()}")
    print(f"Admin User       : {cfg.get('admin_user') or '(Chua tao)'}")
    print(f"Proxy Auth       : {cfg.get('proxy_user')}:{cfg.get('proxy_pass')}")
    print(f"Start Port       : {cfg.get('start_port', 10001)}")
    print(f"So Proxy Nguon   : {cnt}")
elif cmd == "set-admin":
    if len(sys.argv) < 4: sys.exit("Thieu tham so: sudo ps-cli set-admin <user> <pass>")
    u, p = sys.argv[2].strip(), sys.argv[3].strip()
    salt = secrets.token_hex(16)
    cfg["admin_user"] = u
    cfg["admin_salt"] = salt
    cfg["admin_pass_hash"] = hashlib.sha256(f"{salt}:{p}".encode()).hexdigest()
    save_cfg(cfg); print(f"[OK] Da cap nhat Admin: {u}")
elif cmd == "set-auth":
    if len(sys.argv) < 4: sys.exit("Thieu tham so: sudo ps-cli set-auth <user> <pass>")
    cfg["proxy_user"], cfg["proxy_pass"] = sys.argv[2].strip(), sys.argv[3].strip()
    save_cfg(cfg); print("[OK] Da doi Proxy Auth!")
elif cmd == "load":
    if len(sys.argv) < 3: sys.exit("Thieu tham so: sudo ps-cli load /root/proxies.txt [http|socks5]")
    fpath = sys.argv[2]
    proto = sys.argv[3] if len(sys.argv) > 3 else cfg.get("default_up_proto", "http")
    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
        cfg["proxies_raw"] = f.read()
    cfg["proxy_entries"] = []
    cfg["default_up_proto"] = "socks5" if proto == "socks5" else "http"
    save_cfg(cfg); print("[OK] Da nap & dong bo danh sach proxy moi!")
elif cmd == "export":
    if os.path.exists("/root/wrapped_proxies.txt"):
        print(open("/root/wrapped_proxies.txt").read().strip())
elif cmd == "test":
    port = int(sys.argv[2]) if len(sys.argv) > 2 else int(cfg.get("start_port", 10001))
    u, p = cfg.get("proxy_user"), cfg.get("proxy_pass")
    scheme = "http"
    if os.path.exists("/root/wrapped_proxies.txt"):
        for line in open("/root/wrapped_proxies.txt"):
            if line.strip().endswith(f":{port}") and line.startswith("socks5://"):
                scheme = "socks5"; break
    out = subprocess.check_output(["curl", "-4", "-s", "--max-time", "8", "-x", f"{scheme}://{u}:{p}@127.0.0.1:{port}", "https://api.ipify.org"]).decode().strip()
    print(f"[OK] Cong :{port} ({scheme}) -> Exit IP: {out}")
else:
    usage()
EOF
chmod +x /usr/local/bin/ps-cli.tmp
mv -f /usr/local/bin/ps-cli.tmp /usr/local/bin/ps-cli

echo "[*] 7/7. Hoan doi Binary An Toan & Kiem tra Song/Chet (Auto-Rollback)..."
[[ -f "${DATA_DIR}/config.json" ]] && cp -f "${DATA_DIR}/config.json" "/var/backups/proxy-shield/config.pre-update.json"
[[ -f "$BIN_PATH" ]] && cp -f "$BIN_PATH" "${BIN_PATH}.bak"
mv -f "${BIN_PATH}.new" "$BIN_PATH"

TOTAL_MEM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 1024)
GO_MEM_LIMIT=$(( TOTAL_MEM_MB * 70 / 100 ))
(( GO_MEM_LIMIT < 512 )) && GO_MEM_LIMIT=512

EXEC_ARGS="--dash-port=${DASH_PORT} --data-dir=${DATA_DIR} --init-admin-user=${INIT_ADMIN_USER} --init-start-port=${START_PORT}"
[[ -n "$INIT_ADMIN_PASS" ]] && EXEC_ARGS="${EXEC_ARGS} --init-admin-pass=${INIT_ADMIN_PASS}"

cat << EOF > "${SVC_PATH}.tmp"
[Unit]
Description=ProxyShield v3.5 Pro Gateway & Anti-Abuse
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
Environment="GOGC=200"
Environment="GOMEMLIMIT=${GO_MEM_LIMIT}MiB"
ExecStartPre=/usr/local/bin/ps-firewall.sh
ExecStart=${BIN_PATH} ${EXEC_ARGS}
Restart=always
RestartSec=2
LimitNOFILE=1048576
TasksMax=infinity
LimitNPROC=infinity

[Install]
WantedBy=multi-user.target
EOF
mv -f "${SVC_PATH}.tmp" "$SVC_PATH"

systemctl daemon-reload
systemctl enable proxy-shield >/dev/null 2>&1 || true
systemctl restart proxy-shield

HEALTH_OK=0
for _ in 1 2 3 4 5 6; do
  if systemctl is-active --quiet proxy-shield && curl -4 -fsS --max-time 2 "http://127.0.0.1:${DASH_PORT}/api/auth/status" >/dev/null 2>&1; then
    HEALTH_OK=1
    break
  fi
  sleep 1
done

if (( HEALTH_OK == 0 )); then
  echo "[!!] BAN MOI LOI KHOI DONG! Dang tu dong ROLLBACK ve ban cu an toan..."
  if [[ -f "${BIN_PATH}.bak" ]]; then
    mv -f "${BIN_PATH}.bak" "$BIN_PATH"
    systemctl restart proxy-shield || true
  fi
  exit 1
fi

PUB_IP=$(curl -4 -s --max-time 3 https://api.ipify.org 2>/dev/null || echo "YOUR_VPS_IP")
echo "=========================================================================="
echo " CAP NHAT / CAI DAT AN TOAN THANH CONG PROXYSHIELD v3.5 PRO!"
echo "--------------------------------------------------------------------------"
echo "  URL Dashboard : http://${PUB_IP}:${DASH_PORT}"
if (( IS_FRESH == 1 )) && [[ -z "$INIT_ADMIN_PASS" ]]; then
  echo "  Khoi tao Admin: Mo link tren de TAO TAI KHOAN & MAT KHAU truc tiep!"
fi
echo "  Memory Tuning : GOGC=200 | GOMEMLIMIT=${GO_MEM_LIMIT}MiB (VPS ${TOTAL_MEM_MB}MB RAM)"
echo "  Lenh Dong Bo  : sudo ps-cli sync-rules  (Cap nhat list an/chan 0ms rot mang)"
echo "  Lenh Kiem Tra : sudo ps-health"
echo "  Lenh Update   : sudo ps-update"
echo "  Lenh Xoa Sach : sudo bash ... --purge"
echo "=========================================================================="
systemctl status proxy-shield --no-pager