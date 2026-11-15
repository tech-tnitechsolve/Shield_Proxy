# Lệnh cài đặt 1 dòng (Xóa sạch cache GitHub ngay khi vừa Push)
```
SHA=$(curl -4 -sSL -H "Accept: application/vnd.github.sha" -H "Cache-Control: no-cache" "https://api.github.com/repos/tech-tnitechsolve/Shield_Proxy/commits/main?t=$(date +%s)" 2>/dev/null) && [[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || SHA="main"; curl -4 -sSL -H "Cache-Control: no-cache" "https://raw.githubusercontent.com/tech-tnitechsolve/Shield_Proxy/${SHA}/install.sh?t=$(date +%s)" | tr -d '\r' | sudo bash
```
# Cập Nhật Lại Bản Mới
```
sudo ps-update
```

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