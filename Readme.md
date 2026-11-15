proxy-shield/
├── go.mod        # Khai báo module Go (0 thư viện ngoài)
├── dns.go        # Bộ phân giải DoH kép + Singleflight + Cache + Anti-SSRF
├── proxy.go      # Lõi SOCKS5/HTTP Mixed + Splice + TCP_USER_TIMEOUT + Telemetry
├── main.go       # Entry point, Config, Circular Ring Buffer O(1), Hot-Reload
├── web.go        # HTTP API, Session Auth, Async Scanner, Pagination
├── ui.html       # Giao diện Dashboard Pro (nhúng trực tiếp vào binary)
└── install.sh    # 1 lệnh cài từ GitHub lên VPS + tối ưu Oracle + ps-health