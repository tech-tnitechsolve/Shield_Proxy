package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Config struct {
	AdminUser        string   `json:"admin_user"`
	AdminSalt        string   `json:"admin_salt"`
	AdminPassHash    string   `json:"admin_pass_hash"`
	ProxyUser        string   `json:"proxy_user"`
	ProxyPass        string   `json:"proxy_pass"`
	StartPort        int      `json:"start_port"`
	DefaultUpProto   string   `json:"default_up_proto"`
	SanitizeKeywords []string `json:"sanitize_keywords"`
	ProxiesRaw       string   `json:"proxies_raw"`
}

type DomainStat struct {
	Hits       int64
	Sanitized  int64
	Errors     int64
	BytesUp    int64
	BytesDown  int64
	LastSeen   int64
	mu         sync.RWMutex
	Domain     string
	ResolvedIP string
}

type TimePoint struct {
	Time     string  `json:"t"`
	RPS      float64 `json:"rps"`
	KBpsUp   float64 `json:"up_kbps"`
	KBpsDown float64 `json:"dn_kbps"`
	Errors   int64   `json:"err"`
}

type parseStats struct {
	Items   []Upstream
	Dupes   int
	Invalid int
}

const (
	maxHistoryLogs = 3000
	maxDomainStats = 4000
)

var (
	dataDir    string
	configPath string
	pubIP      string
	dashPort   int

	cfgMu  sync.RWMutex
	appCfg Config

	runnersMu sync.RWMutex
	runners   = make(map[int]*PortRunner)

	reqSeq    uint64
	activeMu  sync.RWMutex
	activeMap = make(map[uint64]*RequestRecord)

	// Circular Ring Buffer O(1) - 0 byte dich chuyen
	histMu    sync.RWMutex
	histBuf   [maxHistoryLogs]RequestRecord
	histHead  int
	histCount int

	domMu    sync.RWMutex
	domStats = make(map[string]*DomainStat)

	tsMu      sync.RWMutex
	tsHistory = make([]TimePoint, 0, 60)

	startTime = time.Now()
)

func getProxyCreds() ([]byte, []byte) {
	cfgMu.RLock()
	u, p := appCfg.ProxyUser, appCfg.ProxyPass
	cfgMu.RUnlock()
	return []byte(u), []byte(p)
}

func newReqRecord(port int, clientIP, origTarget, sentTarget, upstream, proto string, sanitized bool) *RequestRecord {
	now := time.Now()
	return &RequestRecord{
		ID:         atomic.AddUint64(&reqSeq, 1),
		TimeStr:    now.Format("2006-01-02 15:04:05"),
		StartUnix:  now.UnixNano(),
		Port:       port,
		ClientIP:   clientIP,
		OrigTarget: origTarget,
		SentTarget: sentTarget,
		Sanitized:  sanitized,
		Upstream:   upstream,
		Protocol:   proto,
		Status:     "LIVE",
	}
}

func addActiveReq(rec *RequestRecord) {
	activeMu.Lock()
	activeMap[rec.ID] = rec
	activeMu.Unlock()
}

func recordDomainStat(domain, resolvedIP string, sanitized bool, bUp, bDown int64, isErr bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return
	}
	domMu.RLock()
	ds, ok := domStats[domain]
	domMu.RUnlock()

	if !ok {
		domMu.Lock()
		ds, ok = domStats[domain]
		if !ok {
			if len(domStats) >= maxDomainStats {
				for k := range domStats {
					delete(domStats, k)
					break
				}
			}
			ds = &DomainStat{Domain: domain}
			domStats[domain] = ds
		}
		domMu.Unlock()
	}

	atomic.AddInt64(&ds.Hits, 1)
	if sanitized {
		atomic.AddInt64(&ds.Sanitized, 1)
	}
	if isErr {
		atomic.AddInt64(&ds.Errors, 1)
	}
	atomic.AddInt64(&ds.BytesUp, bUp)
	atomic.AddInt64(&ds.BytesDown, bDown)
	atomic.StoreInt64(&ds.LastSeen, time.Now().Unix())
	if resolvedIP != "" && resolvedIP != domain {
		ds.mu.Lock()
		ds.ResolvedIP = resolvedIP
		ds.mu.Unlock()
	}
}

func finishReq(rec *RequestRecord, origHost, sentHost string, bUp, bDown int64, status, errMsg string) {
	activeMu.Lock()
	delete(activeMap, rec.ID)
	activeMu.Unlock()

	rec.BytesUp = bUp
	rec.BytesDown = bDown
	rec.DurationMs = time.Since(time.Unix(0, rec.StartUnix)).Milliseconds()
	if rec.DurationMs < 0 {
		rec.DurationMs = 0
	}
	rec.Status = status
	rec.ErrorMsg = errMsg

	recordDomainStat(origHost, sentHost, rec.Sanitized, bUp, bDown, status == "ERR")

	histMu.Lock()
	histBuf[histHead] = *rec
	histHead = (histHead + 1) % maxHistoryLogs
	if histCount < maxHistoryLogs {
		histCount++
	}
	histMu.Unlock()
}

func startTelemetryTicker() {
	var prevReqs, prevUp, prevDn, prevErr int64
	tk := time.NewTicker(2 * time.Second)
	for range tk.C {
		var curReqs, curUp, curDn, curErr int64
		runnersMu.RLock()
		for _, pr := range runners {
			curReqs += atomic.LoadInt64(&pr.TotalReqs)
			curUp += atomic.LoadInt64(&pr.BytesUp)
			curDn += atomic.LoadInt64(&pr.BytesDown)
			curErr += atomic.LoadInt64(&pr.ErrorReqs)
		}
		runnersMu.RUnlock()

		dReqs := curReqs - prevReqs
		dUp := curUp - prevUp
		dDn := curDn - prevDn
		dErr := curErr - prevErr
		if dReqs < 0 {
			dReqs = 0
		}
		if dUp < 0 {
			dUp = 0
		}
		if dDn < 0 {
			dDn = 0
		}
		if dErr < 0 {
			dErr = 0
		}
		prevReqs, prevUp, prevDn, prevErr = curReqs, curUp, curDn, curErr

		pt := TimePoint{
			Time:     time.Now().Format("15:04:05"),
			RPS:      float64(dReqs) / 2.0,
			KBpsUp:   float64(dUp) / 2048.0,
			KBpsDown: float64(dDn) / 2048.0,
			Errors:   dErr,
		}
		tsMu.Lock()
		if len(tsHistory) >= 60 {
			copy(tsHistory, tsHistory[1:])
			tsHistory[len(tsHistory)-1] = pt
		} else {
			tsHistory = append(tsHistory, pt)
		}
		tsMu.Unlock()
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashPassword(salt, plain string) string {
	sum := sha256.Sum256([]byte(salt + ":" + plain))
	return hex.EncodeToString(sum[:])
}

func verifyPassword(salt, hash, plain string) bool {
	computed := hashPassword(salt, plain)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1
}

func parseProxiesFlexible(raw, defaultProto string, dedup bool) parseStats {
	if defaultProto != "http" {
		defaultProto = "socks5"
	}
	res := parseStats{}
	seen := make(map[string]bool)

	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		proto := defaultProto
		body := line
		if idx := strings.Index(line, "://"); idx != -1 {
			scheme := strings.ToLower(line[:idx])
			body = line[idx+3:]
			if strings.HasPrefix(scheme, "http") {
				proto = "http"
			} else {
				proto = "socks5"
			}
		}

		var user, pass, host, portStr string
		if at := strings.LastIndex(body, "@"); at != -1 {
			creds := body[:at]
			hostport := body[at+1:]
			if colon := strings.Index(creds, ":"); colon != -1 {
				user = creds[:colon]
				pass = creds[colon+1:]
			}
			h, p, err := net.SplitHostPort(hostport)
			if err != nil {
				res.Invalid++
				continue
			}
			host, portStr = h, p
		} else if strings.Count(body, ":") == 3 {
			parts := strings.SplitN(body, ":", 4)
			host, portStr, user, pass = parts[0], parts[1], parts[2], parts[3]
		} else {
			h, p, err := net.SplitHostPort(body)
			if err != nil {
				res.Invalid++
				continue
			}
			host, portStr = h, p
		}

		host = strings.TrimSpace(host)
		portStr = strings.TrimSpace(portStr)
		pn, err := strconv.Atoi(portStr)
		if host == "" || err != nil || pn < 1 || pn > 65535 {
			res.Invalid++
			continue
		}

		if dedup {
			key := proto + "|" + host + "|" + portStr + "|" + user + "|" + pass
			if seen[key] {
				res.Dupes++
				continue
			}
			seen[key] = true
		}

		res.Items = append(res.Items, Upstream{
			Proto: proto, Host: host, PortStr: portStr, User: user, Pass: pass,
		})
	}
	return res
}

func formatProxiesRaw(items []Upstream) string {
	var lines []string
	for _, u := range items {
		if u.User != "" || u.Pass != "" {
			lines = append(lines, fmt.Sprintf("%s://%s:%s@%s:%s", u.Proto, u.User, u.Pass, u.Host, u.PortStr))
		} else {
			lines = append(lines, fmt.Sprintf("%s://%s:%s", u.Proto, u.Host, u.PortStr))
		}
	}
	return strings.Join(lines, "\n")
}

func reservePortsSysctl(startPort, count int) {
	endPort := startPort + count + 100
	if endPort > 65000 {
		endPort = 65000
	}
	if endPort < startPort {
		endPort = startPort + 100
	}
	val := fmt.Sprintf("%d,%d-%d", dashPort, startPort, endPort)
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_local_reserved_ports", []byte(val), 0644)
}

func exportDiskFiles(cfg Config, count int) {
	var socksLines, httpLines []string
	for i := 0; i < count; i++ {
		port := cfg.StartPort + i
		socksLines = append(socksLines, fmt.Sprintf("socks5://%s:%s@%s:%d", cfg.ProxyUser, cfg.ProxyPass, pubIP, port))
		httpLines = append(httpLines, fmt.Sprintf("http://%s:%s@%s:%d", cfg.ProxyUser, cfg.ProxyPass, pubIP, port))
	}
	_ = os.WriteFile("/root/wrapped_proxies_socks5.txt", []byte(strings.Join(socksLines, "\n")+"\n"), 0644)
	_ = os.WriteFile("/root/wrapped_proxies_http.txt", []byte(strings.Join(httpLines, "\n")+"\n"), 0644)
}

func applyConfigAndReload(cfg Config) (int, parseStats, error) {
	pStats := parseProxiesFlexible(cfg.ProxiesRaw, cfg.DefaultUpProto, false)
	setSanitizeKeywords(cfg.SanitizeKeywords)
	reservePortsSysctl(cfg.StartPort, len(pStats.Items))

	desired := make(map[int]Upstream, len(pStats.Items))
	for i, u := range pStats.Items {
		desired[cfg.StartPort+i] = u
	}

	runnersMu.Lock()
	for port, pr := range runners {
		if _, keep := desired[port]; !keep {
			atomic.StoreInt32(&pr.closed, 1)
			_ = pr.ln.Close()
			delete(runners, port)
		}
	}

	var failed []string
	var ports []int
	for p := range desired {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	for _, port := range ports {
		up := desired[port]
		if pr, exists := runners[port]; exists {
			pr.SetUpstream(up)
			continue
		}
		ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			failed = append(failed, fmt.Sprintf("%d:%v", port, err))
			continue
		}
		pr := &PortRunner{
			Port:     port,
			upstream: up,
			health:   "untested",
			ln:       ln,
		}
		runners[port] = pr
		go func(runner *PortRunner) {
			for {
				c, err := runner.ln.Accept()
				if err != nil {
					return
				}
				go handleClient(c, runner)
			}
		}(pr)
	}
	activeCount := len(runners)
	runnersMu.Unlock()

	exportDiskFiles(cfg, len(pStats.Items))
	if len(failed) > 0 {
		return activeCount, pStats, fmt.Errorf("cong bi chiem: %s", strings.Join(failed, ", "))
	}
	return activeCount, pStats, nil
}

func saveConfigFile(cfg Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, b, 0600)
}

func loadOrInitConfig(initAdminUser, initAdminPass string, initStartPort int) Config {
	b, err := os.ReadFile(configPath)
	if err == nil {
		var c Config
		if json.Unmarshal(b, &c) == nil && c.AdminUser != "" && c.AdminPassHash != "" {
			if c.StartPort <= 0 {
				c.StartPort = 10001
			}
			if c.DefaultUpProto == "" {
				c.DefaultUpProto = "socks5"
			}
			return c
		}
	}
	salt := randomHex(16)
	c := Config{
		AdminUser:      initAdminUser,
		AdminSalt:      salt,
		AdminPassHash:  hashPassword(salt, initAdminPass),
		ProxyUser:      "blx" + randomHex(3),
		ProxyPass:      randomHex(8),
		StartPort:      initStartPort,
		DefaultUpProto: "socks5",
		SanitizeKeywords: []string{
			"bytelixir", "bylxr", "pawns", "honeygain",
			"earnapp", "packetstream", "packetshare", "traffmonetizer",
			"repocket", "earnfm",
		},
		ProxiesRaw: "",
	}
	_ = saveConfigFile(c)
	return c
}

func detectPublicIP() string {
	c := &http.Client{Timeout: 4 * time.Second}
	for _, url := range []string{"https://api.ipify.org", "https://icanhazip.com"} {
		resp, err := c.Get(url)
		if err == nil {
			b, rErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			ip := strings.TrimSpace(string(b))
			if rErr == nil && net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	return "127.0.0.1"
}

func main() {
	dashFlag := flag.Int("dash-port", 8888, "Web dashboard port")
	dirFlag := flag.String("data-dir", "/var/lib/proxy-shield", "Data directory")
	initUser := flag.String("init-admin-user", "admin", "Initial admin username")
	initPass := flag.String("init-admin-pass", "Admin2026Pro", "Initial admin password")
	initStart := flag.Int("init-start-port", 10001, "Initial proxy start port")
	flag.Parse()

	dashPort = *dashFlag
	dataDir = *dirFlag
	_ = os.MkdirAll(dataDir, 0700)
	configPath = filepath.Join(dataDir, "config.json")
	pubIP = detectPublicIP()

	appCfg = loadOrInitConfig(*initUser, *initPass, *initStart)
	cnt, _, err := applyConfigAndReload(appCfg)
	if err != nil {
		log.Printf("Canh bao reload: %v", err)
	}

	go startTelemetryTicker()
	go startSessionCleaner()
	go startWebDashboard(dashPort)

	log.Printf("ProxyShield v2.0 Pro san sang! Public IP: %s | %d cong proxy | Dashboard: http://%s:%d", pubIP, cnt, pubIP, dashPort)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	runnersMu.Lock()
	for _, pr := range runners {
		atomic.StoreInt32(&pr.closed, 1)
		_ = pr.ln.Close()
	}
	runnersMu.Unlock()
}