# Lệnh cài đặt 1 dòng (Xóa sạch cache GitHub ngay khi vừa Push)
```
SHA=$(curl -4 -sSL -H "Accept: application/vnd.github.sha" -H "Cache-Control: no-cache" "https://api.github.com/repos/tech-tnitechsolve/Shield_Proxy/commits/main?t=$(date +%s)" 2>/dev/null) && [[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || SHA="main"; curl -4 -sSL -H "Cache-Control: no-cache" "https://raw.githubusercontent.com/tech-tnitechsolve/Shield_Proxy/${SHA}/install.sh?t=$(date +%s)" | tr -d '\r' | sudo bash
```