# 1. Lệnh cài đặt an toàn (ghim theo commit SHA)
```
set -o pipefail
SHA=$(curl -4 -fsSL -H "Accept: application/vnd.github.sha" -H "Cache-Control: no-cache" "https://api.github.com/repos/tech-tnitechsolve/Shield_Proxy/commits/main?t=$(date +%s)") || exit 1
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "Không lấy được commit SHA hợp lệ."; exit 1; }
curl -4 -fsSL -H "Cache-Control: no-cache" "https://raw.githubusercontent.com/tech-tnitechsolve/Shield_Proxy/${SHA}/install.sh" | tr -d '\r' | sudo bash
```
# Cập Nhật Lại Bản Mới
Có thể bấm **Cập nhật phiên bản** trên Dashboard sau khi đăng nhập. Tiến trình cập nhật chạy riêng bằng systemd, nên việc khởi động lại ProxyShield không làm dừng updater.
```
sudo ps-update
```
# 2. Lệnh xóa sạch hết 100% (nếu không muốn dùng nữa)
```
sudo bash -c 'systemctl disable --now proxy-shield 2>/dev/null || true; rm -rf /etc/systemd/system/proxy-shield.service /usr/local/bin/proxy-shield /usr/local/bin/ps-health /usr/local/bin/ps-update /usr/local/bin/ps-cli /usr/local/bin/ps-firewall.sh /etc/cron.d/proxy-shield-backup /etc/sysctl.d/99-proxyshield.conf /etc/systemd/journald.conf.d/99-proxyshield.conf /etc/security/limits.d/99-proxyshield.conf /opt/proxy-shield-src /var/lib/proxy-shield /var/backups/proxy-shield /root/wrapped_proxies*.txt; systemctl daemon-reload; sysctl --system >/dev/null 2>&1 || true; echo "[OK] Da xoa sach 100% ProxyShield khoi VPS!"'
```
---------------------------------------------------------------------------
# Nếu Dùng Oracle thì phải mở Shell rồi đẩy code sau:
```
SL_ID="ocid1.securitylist.oc1.ca-toronto-1.aaaaaaaafph42mmfltv7z5thae2n2ul4jo4nz7mkgspifzytjbgqmdi7b6gq"
oci network security-list get --security-list-id "$SL_ID" --query 'data."ingress-security-rules"' > /tmp/cur.json
python3 -c '
import json
cur = json.load(open("/tmp/cur.json"))
cur = [r for r in cur if r.get("description") not in ("ProxyShield-UI", "ProxyShield-Ports")]
cur += [
  {"source":"0.0.0.0/0","source-type":"CIDR_BLOCK","protocol":"6","is-stateless":False,"description":"ProxyShield-UI","tcp-options":{"destination-port-range":{"min":8888,"max":8888}}},
  {"source":"0.0.0.0/0","source-type":"CIDR_BLOCK","protocol":"6","is-stateless":False,"description":"ProxyShield-Ports","tcp-options":{"destination-port-range":{"min":10001,"max":12500}}}
]
json.dump(cur, open("/tmp/new.json", "w"))
'
oci network security-list update --security-list-id "$SL_ID" --ingress-security-rules "$(cat /tmp/new.json)" --force >/dev/null && echo "[OK] DA MO XONG PORT 8888 VA 10001-12500!"
```