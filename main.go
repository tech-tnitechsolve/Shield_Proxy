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
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type ProxyEntry struct {
	Port     int      `json:"port"`
	Group    string   `json:"group"`
	Note     string   `json:"note"`
	Enabled  bool     `json:"enabled"`
	Upstream Upstream `json:"upstream"`
}

type Config struct {
	ConfigVersion       int          `json:"config_version"`
	AdminUser           string       `json:"admin_user"`
	AdminSalt           string       `json:"admin_salt"`
	AdminPassHash       string       `json:"admin_pass_hash"`
	ProxyUser           string       `json:"proxy_user"`
	ProxyPass           string       `json:"proxy_pass"`
	StartPort           int          `json:"start_port"`
	DefaultUpProto      string       `json:"default_up_proto"`
	AutoCheckMin        int          `json:"auto_check_min"`
	BandwidthQuotaTB    float64      `json:"bandwidth_quota_tb"`
	BlockDangerousPorts bool         `json:"block_dangerous_ports"`
	SanitizeKeywords    []string     `json:"sanitize_keywords"`
	BlockKeywords       []string     `json:"block_keywords"`
	ProxyEntries        []ProxyEntry `json:"proxy_entries"`
	ProxiesRaw          string       `json:"proxies_raw"`
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

type BandwidthState struct {
	MonthKey     string `json:"month_key"`
	MonthRxBytes uint64 `json:"month_rx_bytes"`
	MonthTxBytes uint64 `json:"month_tx_bytes"`
}

type VPSSnapshot struct {
	CPUPct        float64 `json:"cpu_pct"`
	CPUCores      int     `json:"cpu_cores"`
	LoadAvg       string  `json:"load_avg"`
	MemTotalMB    uint64  `json:"mem_total_mb"`
	MemUsedMB     uint64  `json:"mem_used_mb"`
	SwapTotalMB   uint64  `json:"swap_total_mb"`
	SwapUsedMB    uint64  `json:"swap_used_mb"`
	DiskTotalGB   float64 `json:"disk_total_gb"`
	DiskUsedGB    float64 `json:"disk_used_gb"`
	VPSUptimeSec  int64   `json:"vps_uptime_sec"`
	OpenFDs       int     `json:"open_fds"`
	ConntrackCur  int64   `json:"conntrack_cur"`
	ConntrackMax  int64   `json:"conntrack_max"`
	NICRxMbps     float64 `json:"nic_rx_mbps"`
	NICTxMbps     float64 `json:"nic_tx_mbps"`
	MonthRxBytes  uint64  `json:"month_rx_bytes"`
	MonthTxBytes  uint64  `json:"month_tx_bytes"`
	ProjectedTxGB float64 `json:"projected_tx_gb"`
}

type portUsageDump struct {
	Upstream string `json:"a"`
	Up       int64  `json:"u"`
	Down     int64  `json:"d"`
	Reqs     int64  `json:"r"`
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
	dataDir       string
	configPath    string
	bwPath        string
	portUsagePath string
	pubIP         string
	dashPort      int

	cfgMu  sync.RWMutex
	appCfg Config

	runnersMu sync.RWMutex
	runners   = make(map[int]*PortRunner)

	reqSeq    uint64
	activeMu  sync.RWMutex
	activeMap = make(map[uint64]*RequestRecord)

	histMu    sync.RWMutex
	histBuf   [maxHistoryLogs]RequestRecord
	histHead  int
	histCount int

	domMu    sync.RWMutex
	domStats = make(map[string]*DomainStat)

	tsMu      sync.RWMutex
	tsHistory = make([]TimePoint, 0, 60)

	vpsMu   sync.RWMutex
	vpsSnap VPSSnapshot

	bwMu    sync.Mutex
	bwState BandwidthState

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
	if resolvedIP != "" && resolvedIP != domain && resolvedIP != "-" {
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

// ==================== Doc thong so phan cung VPS (Toi uu 1 CPU) ====================
func readCPUTimes() (total uint64, idle uint64) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "cpu ") {
			f := strings.Fields(line)
			if len(f) < 5 {
				return 0, 0
			}
			for i := 1; i < len(f) && i <= 8; i++ {
				v, _ := strconv.ParseUint(f[i], 10, 64)
				total += v
				if i == 4 || i == 5 {
					idle += v
				}
			}
			return total, idle
		}
	}
	return 0, 0
}

func readMemInfo() (memTotalMB, memUsedMB, swapTotalMB, swapUsedMB uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	var mTot, mAvail, sTot, sFree uint64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			mTot = val
		case "MemAvailable:":
			mAvail = val
		case "SwapTotal:":
			sTot = val
		case "SwapFree:":
			sFree = val
		}
	}
	memTotalMB = mTot / 1024
	if mTot >= mAvail {
		memUsedMB = (mTot - mAvail) / 1024
	}
	swapTotalMB = sTot / 1024
	if sTot >= sFree {
		swapUsedMB = (sTot - sFree) / 1024
	}
	return
}

func readDiskRoot() (totalGB, usedGB float64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, 0
	}
	totalB := float64(st.Blocks) * float64(st.Bsize)
	freeB := float64(st.Bfree) * float64(st.Bsize)
	totalGB = totalB / 1073741824.0
	usedGB = (totalB - freeB) / 1073741824.0
	return
}

func readProcInt(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return v
}

func readLoadAvg() string {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "-"
	}
	f := strings.Fields(string(b))
	if len(f) >= 3 {
		return f[0] + " " + f[1] + " " + f[2]
	}
	return "-"
}

func readVPSUptime() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return int64(v)
}

func countOpenFDs() int {
	f, err := os.Open("/proc/self/fd")
	if err != nil {
		return 0
	}
	names, _ := f.Readdirnames(-1)
	_ = f.Close()
	return len(names)
}

func readAppMemMB() float64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0
	}
	rssPages, _ := strconv.ParseUint(f[1], 10, 64)
	return float64(rssPages*uint64(os.Getpagesize())) / 1048576.0
}

func readNICBytes() (rxBytes, txBytes uint64) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		idx := strings.Index(line, ":")
		if idx == -1 {
			continue
		}
		iface := strings.TrimSpace(line[:idx])
		if iface == "lo" || strings.HasPrefix(iface, "docker") || strings.HasPrefix(iface, "veth") ||
			strings.HasPrefix(iface, "br-") || strings.HasPrefix(iface, "tun") || strings.HasPrefix(iface, "tap") {
			continue
		}
		f := strings.Fields(line[idx+1:])
		if len(f) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(f[0], 10, 64)
		tx, _ := strconv.ParseUint(f[8], 10, 64)
		rxBytes += rx
		txBytes += tx
	}
	return
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, wErr := f.Write(data)
	sErr := f.Sync()
	cErr := f.Close()
	if wErr != nil {
		return wErr
	}
	if sErr != nil {
		return sErr
	}
	if cErr != nil {
		return cErr
	}
	if _, err := os.Stat(path); err == nil {
		if old, rErr := os.ReadFile(path); rErr == nil && len(old) > 10 {
			_ = os.WriteFile(path+".bak", old, perm)
		}
	}
	return os.Rename(tmp, path)
}

func savePortUsage() {
	if portUsagePath == "" {
		return
	}
	dump := make(map[int]portUsageDump)
	runnersMu.RLock()
	for port, pr := range runners {
		u := atomic.LoadInt64(&pr.BytesUp)
		d := atomic.LoadInt64(&pr.BytesDown)
		r := atomic.LoadInt64(&pr.TotalReqs)
		if u > 0 || d > 0 || r > 0 {
			dump[port] = portUsageDump{Upstream: pr.GetUpstream().Addr(), Up: u, Down: d, Reqs: r}
		}
	}
	runnersMu.RUnlock()
	if b, err := json.Marshal(dump); err == nil {
		_ = atomicWriteFile(portUsagePath, b, 0600)
	}
}

func loadPortUsage() {
	b, err := os.ReadFile(portUsagePath)
	if err != nil {
		b, err = os.ReadFile(portUsagePath + ".bak")
		if err != nil {
			return
		}
	}
	var dump map[int]portUsageDump
	if json.Unmarshal(b, &dump) != nil {
		return
	}
	runnersMu.RLock()
	for port, st := range dump {
		if pr, ok := runners[port]; ok {
			if st.Upstream == "" || st.Upstream == pr.GetUpstream().Addr() {
				atomic.StoreInt64(&pr.BytesUp, st.Up)
				atomic.StoreInt64(&pr.BytesDown, st.Down)
				atomic.StoreInt64(&pr.TotalReqs, st.Reqs)
			}
		}
	}
	runnersMu.RUnlock()
}

func loadBandwidthState() {
	curMonth := time.Now().Format("2006-01")
	bwState = BandwidthState{MonthKey: curMonth}
	for _, p := range []string{bwPath, bwPath + ".bak"} {
		if b, err := os.ReadFile(p); err == nil {
			var st BandwidthState
			if json.Unmarshal(b, &st) == nil && st.MonthKey == curMonth {
				bwState = st
				break
			}
		}
	}
	syncVnstatMonth()
}

func saveBandwidthState() {
	bwMu.Lock()
	b, err := json.MarshalIndent(bwState, "", "  ")
	bwMu.Unlock()
	if err == nil {
		_ = atomicWriteFile(bwPath, b, 0600)
	}
}

func syncVnstatMonth() {
	out, err := exec.Command("vnstat", "--json", "m").Output()
	if err != nil {
		return
	}
	var parsed struct {
		VnstatVersion string `json:"vnstatversion"`
		Interfaces    []struct {
			Traffic struct {
				Month []struct {
					Date struct {
						Year  int `json:"year"`
						Month int `json:"month"`
					} `json:"date"`
					Rx uint64 `json:"rx"`
					Tx uint64 `json:"tx"`
				} `json:"month"`
			} `json:"traffic"`
		} `json:"interfaces"`
	}
	if json.Unmarshal(out, &parsed) != nil {
		return
	}
	mult := uint64(1)
	if strings.HasPrefix(parsed.VnstatVersion, "1.") {
		mult = 1024
	}
	now := time.Now()
	var vnRx, vnTx uint64
	for _, iface := range parsed.Interfaces {
		for _, m := range iface.Traffic.Month {
			if m.Date.Year == now.Year() && m.Date.Month == int(now.Month()) {
				vnRx += m.Rx * mult
				vnTx += m.Tx * mult
			}
		}
	}
	bwMu.Lock()
	if vnRx > bwState.MonthRxBytes {
		bwState.MonthRxBytes = vnRx
	}
	if vnTx > bwState.MonthTxBytes {
		bwState.MonthTxBytes = vnTx
	}
	bwMu.Unlock()
}

func calcProjectedMonthGB(monthTx uint64) float64 {
	now := time.Now()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	nextMonth := monthStart.AddDate(0, 1, 0)
	elapsed := now.Sub(monthStart).Seconds()
	totalSec := nextMonth.Sub(monthStart).Seconds()
	txGB := float64(monthTx) / 1073741824.0
	if elapsed < 3600 {
		return txGB
	}
	return txGB * (totalSec / elapsed)
}

func startTelemetryTicker() {
	loadBandwidthState()
	prevCPUTot, prevCPUIdle := readCPUTimes()
	prevNICRx, prevNICTx := readNICBytes()
	var prevReqs, prevUp, prevDn, prevErr int64

	tickCount := 0
	cachedFDs := countOpenFDs()
	tk := time.NewTicker(3 * time.Second)
	for range tk.C {
		tickCount++

		var curReqs, curUp, curDn, curErr int64
		runnersMu.RLock()
		for _, pr := range runners {
			curReqs += atomic.LoadInt64(&pr.TotalReqs)
			curUp += atomic.LoadInt64(&pr.BytesUp)
			curDn += atomic.LoadInt64(&pr.BytesDown)
			curErr += atomic.LoadInt64(&pr.ErrorReqs)
		}
		runnersMu.RUnlock()

		dReqs, dUp, dDn, dErr := curReqs-prevReqs, curUp-prevUp, curDn-prevDn, curErr-prevErr
		if dReqs < 0 { dReqs = 0 }
		if dUp < 0 { dUp = 0 }
		if dDn < 0 { dDn = 0 }
		if dErr < 0 { dErr = 0 }
		prevReqs, prevUp, prevDn, prevErr = curReqs, curUp, curDn, curErr

		pt := TimePoint{
			Time:     time.Now().Format("15:04:05"),
			RPS:      float64(dReqs) / 3.0,
			KBpsUp:   float64(dUp) / 3072.0,
			KBpsDown: float64(dDn) / 3072.0,
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

		curCPUTot, curCPUIdle := readCPUTimes()
		var cpuPct float64
		if curCPUTot > prevCPUTot {
			dTot := curCPUTot - prevCPUTot
			dIdl := curCPUIdle - prevCPUIdle
			if dTot > 0 && dTot >= dIdl {
				cpuPct = float64(dTot-dIdl) * 100.0 / float64(dTot)
			}
		}
		prevCPUTot, prevCPUIdle = curCPUTot, curCPUIdle

		curNICRx, curNICTx := readNICBytes()
		var dNICRx, dNICTx uint64
		if curNICRx >= prevNICRx { dNICRx = curNICRx - prevNICRx }
		if curNICTx >= prevNICTx { dNICTx = curNICTx - prevNICTx }
		prevNICRx, prevNICTx = curNICRx, curNICTx

		curMonth := time.Now().Format("2006-01")
		bwMu.Lock()
		if bwState.MonthKey != curMonth {
			bwState.MonthKey = curMonth
			bwState.MonthRxBytes = 0
			bwState.MonthTxBytes = 0
		}
		bwState.MonthRxBytes += dNICRx
		bwState.MonthTxBytes += dNICTx
		mRx := bwState.MonthRxBytes
		mTx := bwState.MonthTxBytes
		bwMu.Unlock()

		if tickCount%20 == 0 {
			saveBandwidthState()
			savePortUsage()
		}
		if tickCount%100 == 0 {
			syncVnstatMonth()
		}
		if tickCount%5 == 0 {
			cachedFDs = countOpenFDs()
		}

		mTot, mUsed, sTot, sUsed := readMemInfo()
		dTot, dUsed := readDiskRoot()

		snap := VPSSnapshot{
			CPUPct:        cpuPct,
			CPUCores:      runtime.NumCPU(),
			LoadAvg:       readLoadAvg(),
			MemTotalMB:    mTot,
			MemUsedMB:     mUsed,
			SwapTotalMB:   sTot,
			SwapUsedMB:    sUsed,
			DiskTotalGB:   dTot,
			DiskUsedGB:    dUsed,
			VPSUptimeSec:  readVPSUptime(),
			OpenFDs:       cachedFDs,
			ConntrackCur:  readProcInt("/proc/sys/net/netfilter/nf_conntrack_count"),
			ConntrackMax:  readProcInt("/proc/sys/net/netfilter/nf_conntrack_max"),
			NICRxMbps:     float64(dNICRx) * 8.0 / 3.0 / 1000000.0,
			NICTxMbps:     float64(dNICTx) * 8.0 / 3.0 / 1000000.0,
			MonthRxBytes:  mRx,
			MonthTxBytes:  mTx,
			ProjectedTxGB: calcProjectedMonthGB(mTx),
		}
		vpsMu.Lock()
		vpsSnap = snap
		vpsMu.Unlock()
	}
}

func startAutoCheckLoop() {
	time.Sleep(4 * time.Second)
	for {
		cfgMu.RLock()
		mins := appCfg.AutoCheckMin
		cfgMu.RUnlock()

		if mins > 0 {
			runnersMu.RLock()
			hasRunners := len(runners) > 0
			runnersMu.RUnlock()
			if hasRunners {
				triggerScan("quick", nil)
			}
		} else {
			mins = 1
		}
		time.Sleep(time.Duration(mins) * time.Minute)
	}
}

// ==================== Tien ich Config, ProxyEntries & Reload ====================
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

func upstreamKey(u Upstream) string {
	return u.Proto + "|" + u.Host + "|" + u.PortStr + "|" + u.User + "|" + u.Pass
}

func formatOneUpstream(u Upstream) string {
	if u.User != "" || u.Pass != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%s", u.Proto, u.User, u.Pass, u.Host, u.PortStr)
	}
	return fmt.Sprintf("%s://%s:%s", u.Proto, u.Host, u.PortStr)
}

func parseSingleUpstream(line, defaultProto string) (Upstream, bool) {
	if defaultProto != "http" {
		defaultProto = "socks5"
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Upstream{}, false
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
			return Upstream{}, false
		}
		host, portStr = h, p
	} else if strings.Count(body, ":") == 3 {
		parts := strings.SplitN(body, ":", 4)
		host, portStr, user, pass = parts[0], parts[1], parts[2], parts[3]
	} else {
		h, p, err := net.SplitHostPort(body)
		if err != nil {
			return Upstream{}, false
		}
		host, portStr = h, p
	}

	host = strings.TrimSpace(host)
	portStr = strings.TrimSpace(portStr)
	pn, err := strconv.Atoi(portStr)
	if host == "" || err != nil || pn < 1 || pn > 65535 {
		return Upstream{}, false
	}

	return Upstream{Proto: proto, Host: host, PortStr: portStr, User: user, Pass: pass}, true
}

func parseProxiesFlexible(raw, defaultProto string, dedup bool) parseStats {
	res := parseStats{}
	seen := make(map[string]bool)

	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, ok := parseSingleUpstream(line, defaultProto)
		if !ok {
			res.Invalid++
			continue
		}
		if dedup {
			k := upstreamKey(u)
			if seen[k] {
				res.Dupes++
				continue
			}
			seen[k] = true
		}
		res.Items = append(res.Items, u)
	}
	return res
}

func syncRawFromEntries(cfg *Config) {
	var lines []string
	for _, e := range cfg.ProxyEntries {
		lines = append(lines, formatOneUpstream(e.Upstream))
	}
	cfg.ProxiesRaw = strings.Join(lines, "\n")
}

func reservePortsSysctl(entries []ProxyEntry, startPort int) {
	minP, maxP := startPort, startPort+100
	for _, e := range entries {
		if e.Port < minP {
			minP = e.Port
		}
		if e.Port > maxP {
			maxP = e.Port
		}
	}
	if maxP+50 <= 65000 {
		maxP += 50
	}
	val := fmt.Sprintf("%d,%d-%d", dashPort, minP, maxP)
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_local_reserved_ports", []byte(val), 0644)
}

func exportDiskFiles(cfg Config) {
	var lines []string
	for _, e := range cfg.ProxyEntries {
		if !e.Enabled {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s://%s:%s@%s:%d", e.Upstream.Proto, cfg.ProxyUser, cfg.ProxyPass, pubIP, e.Port))
	}
	_ = os.WriteFile("/root/wrapped_proxies.txt", []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func applyConfigAndReload(cfg Config) (int, error) {
	rebuildAllRules(cfg.SanitizeKeywords, cfg.BlockKeywords, cfg.BlockDangerousPorts)
	reservePortsSysctl(cfg.ProxyEntries, cfg.StartPort)

	desired := make(map[int]ProxyEntry, len(cfg.ProxyEntries))
	for _, e := range cfg.ProxyEntries {
		if !e.Enabled || e.Port < 1024 || e.Port > 65535 {
			continue
		}
		desired[e.Port] = e
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
		ent := desired[port]
		if pr, exists := runners[port]; exists {
			oldUp := pr.GetUpstream()
			pr.SetMeta(ent.Upstream, ent.Group, ent.Note)
			if oldUp.Addr() != ent.Upstream.Addr() || oldUp.Proto != ent.Upstream.Proto {
				atomic.StoreInt64(&pr.BytesUp, 0)
				atomic.StoreInt64(&pr.BytesDown, 0)
				atomic.StoreInt64(&pr.TotalReqs, 0)
				atomic.StoreInt64(&pr.SanitizedReqs, 0)
				atomic.StoreInt64(&pr.BlockedReqs, 0)
				atomic.StoreInt64(&pr.ErrorReqs, 0)
				pr.mu.Lock()
				pr.health = "untested"
				pr.latency = 0
				pr.exitIP = ""
				pr.lastErr = ""
				pr.mu.Unlock()
			}
			continue
		}
		ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			failed = append(failed, fmt.Sprintf("%d:%v", port, err))
			continue
		}
		pr := &PortRunner{
			Port:     port,
			upstream: ent.Upstream,
			group:    ent.Group,
			note:     ent.Note,
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

	exportDiskFiles(cfg)
	if len(failed) > 0 {
		return activeCount, fmt.Errorf("cong bi chiem: %s", strings.Join(failed, ", "))
	}
	return activeCount, nil
}

func saveConfigFile(cfg Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(configPath, b, 0600)
}

func isSetupRequired() bool {
	cfgMu.RLock()
	req := appCfg.AdminUser == "" || appCfg.AdminPassHash == ""
	cfgMu.RUnlock()
	return req
}

func loadOrInitConfig(initAdminUser, initAdminPass string, initStartPort int) Config {
	for _, p := range []string{configPath, configPath + ".bak"} {
		if b, err := os.ReadFile(p); err == nil {
			var c Config
			if json.Unmarshal(b, &c) == nil {
				changed := false
				if c.StartPort <= 0 {
					c.StartPort = 10001
					changed = true
				}
				if c.DefaultUpProto == "" {
					c.DefaultUpProto = "http"
					changed = true
				}
				if c.AutoCheckMin < 0 {
					c.AutoCheckMin = 5
					changed = true
				}
				if c.ConfigVersion < 35 {
					c.ConfigVersion = 35
					c.BlockDangerousPorts = true
					if c.AutoCheckMin == 0 {
						c.AutoCheckMin = 5
					}
					if c.BandwidthQuotaTB == 0 {
						c.BandwidthQuotaTB = 10.0
					}
					changed = true
				}
				// Tu dong chuyen doi ProxiesRaw cu sang ProxyEntries co Port/Group/Enabled
				if len(c.ProxyEntries) == 0 && strings.TrimSpace(c.ProxiesRaw) != "" {
					ps := parseProxiesFlexible(c.ProxiesRaw, c.DefaultUpProto, false)
					for i, u := range ps.Items {
						c.ProxyEntries = append(c.ProxyEntries, ProxyEntry{
							Port: c.StartPort + i, Group: "Mac dinh", Enabled: true, Upstream: u,
						})
					}
					changed = true
				}
				if changed {
					_ = saveConfigFile(c)
				}
				return c
			}
		}
	}

	var aUser, aSalt, aHash string
	if strings.TrimSpace(initAdminPass) != "" {
		aUser = initAdminUser
		aSalt = randomHex(16)
		aHash = hashPassword(aSalt, strings.TrimSpace(initAdminPass))
	}

	c := Config{
		ConfigVersion:       35,
		AdminUser:           aUser,
		AdminSalt:           aSalt,
		AdminPassHash:       aHash,
		ProxyUser:           "blx" + randomHex(3),
		ProxyPass:           randomHex(8),
		StartPort:           initStartPort,
		DefaultUpProto:      "http",
		AutoCheckMin:        5,
		BandwidthQuotaTB:    10.0,
		BlockDangerousPorts: true,
		SanitizeKeywords:    []string{},
		BlockKeywords:       []string{},
		ProxyEntries:        []ProxyEntry{},
		ProxiesRaw:          "",
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

func runSelfTest() int {
	appCfg = loadOrInitConfig("admin", "", 10001)
	initRules()

	sanCnt, blkCnt, _ := getRulesStatus()
	if sanCnt == 0 || blkCnt == 0 {
		fmt.Printf("SELF-TEST FAIL: rules rong (san=%d, blk=%d)\n", sanCnt, blkCnt)
		return 1
	}
	if !needsSanitize("c-4.i.brightnetip.com") || !needsSanitize("api.bytelixir.com") {
		fmt.Println("SELF-TEST FAIL: khong nhan dien duoc domain ByteLixir")
		return 1
	}
	if ok, _ := isBlockedRequest("example.com", 25); !ok {
		fmt.Println("SELF-TEST FAIL: khong chan port 25 SMTP")
		return 1
	}
	if ok, _ := isBlockedRequest("www.paypal.com", 443); !ok {
		fmt.Println("SELF-TEST FAIL: khong chan domain nhay cam paypal.com")
		return 1
	}
	if ok, _ := isBlockedRequest("ipv6.icanhazip.com", 80); !ok {
		fmt.Println("SELF-TEST FAIL: khong chan ipv6 probe")
		return 1
	}
	fmt.Printf("SELF-TEST OK: Sanitize=%d | Block=%d | SavedProxies=%d\n", sanCnt, blkCnt, len(appCfg.ProxyEntries))
	return 0
}

func main() {
	dashFlag := flag.Int("dash-port", 8888, "Web dashboard port")
	dirFlag := flag.String("data-dir", "/var/lib/proxy-shield", "Data directory")
	initUser := flag.String("init-admin-user", "admin", "Initial admin username")
	initPass := flag.String("init-admin-pass", "", "Initial admin password")
	initStart := flag.Int("init-start-port", 10001, "Initial proxy start port")
	selfTest := flag.Bool("self-test", false, "Run pre-update anti-leak self-test")
	flag.Parse()

	dashPort = *dashFlag
	dataDir = *dirFlag
	_ = os.MkdirAll(dataDir, 0700)
	configPath = filepath.Join(dataDir, "config.json")
	bwPath = filepath.Join(dataDir, "bandwidth.json")
	portUsagePath = filepath.Join(dataDir, "port_usage.json")

	if *selfTest {
		os.Exit(runSelfTest())
	}

	pubIP = detectPublicIP()
	appCfg = loadOrInitConfig(*initUser, *initPass, *initStart)

	// BAT BUOC: Nap 100% rules an & chan truoc khi mo bat ky cong proxy nao!
	initRules()

	cnt, err := applyConfigAndReload(appCfg)
	if err != nil {
		log.Printf("Canh bao reload: %v", err)
	}
	loadPortUsage()

	go startTelemetryTicker()
	go startSessionCleaner()
	go startAutoCheckLoop()
	go startRulesSyncLoop()
	go func() {
		usrCh := make(chan os.Signal, 1)
		signal.Notify(usrCh, syscall.SIGUSR1)
		for range usrCh {
			_, _, _ = syncRulesFromGitHub(true)
		}
	}()
	go startWebDashboard(dashPort)

	log.Printf("ProxyShield v3.5 Pro san sang! Public IP: %s | %d cong | Dashboard: http://%s:%d", pubIP, cnt, pubIP, dashPort)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	saveBandwidthState()
	savePortUsage()
	runnersMu.Lock()
	for _, pr := range runners {
		atomic.StoreInt32(&pr.closed, 1)
		_ = pr.ln.Close()
	}
	runnersMu.Unlock()
}
```

---

### File 6: `web.go` (Copy toàn bộ dán đè vào `web.go`)

```go
package main

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed ui.html
var dashboardHTML string

type sessionInfo struct {
	user string
	exp  time.Time
}

var (
	sessMu   sync.RWMutex
	sessions = make(map[string]sessionInfo)

	rlMu      sync.Mutex
	loginFail = make(map[string][]time.Time)
)

func startSessionCleaner() {
	tk := time.NewTicker(10 * time.Minute)
	for range tk.C {
		now := time.Now()
		sessMu.Lock()
		for k, s := range sessions {
			if now.After(s.exp) {
				delete(sessions, k)
			}
		}
		sessMu.Unlock()

		rlMu.Lock()
		for ip, times := range loginFail {
			var keep []time.Time
			for _, t := range times {
				if now.Sub(t) < time.Minute {
					keep = append(keep, t)
				}
			}
			if len(keep) == 0 {
				delete(loginFail, ip)
			} else {
				loginFail[ip] = keep
			}
		}
		rlMu.Unlock()
	}
}

func checkRateLimit(ip string) bool {
	rlMu.Lock()
	defer rlMu.Unlock()
	now := time.Now()
	var recent []time.Time
	for _, t := range loginFail[ip] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	loginFail[ip] = recent
	return len(recent) < 12
}

func recordLoginFail(ip string) {
	rlMu.Lock()
	loginFail[ip] = append(loginFail[ip], time.Now())
	rlMu.Unlock()
}

func getClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie("ps_session")
		if err != nil || ck.Value == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		sessMu.RLock()
		info, ok := sessions[ck.Value]
		sessMu.RUnlock()
		if !ok || time.Now().After(info.exp) {
			http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func apiAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"setup_required": isSetupRequired(),
	})
}

func apiLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := getClientIP(r)
	if !checkRateLimit(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Thu sai qua nhieu lan, doi 1 phut!"})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	u := strings.TrimSpace(body.Username)
	p := strings.TrimSpace(body.Password)

	cfgMu.Lock()
	if appCfg.AdminUser == "" || appCfg.AdminPassHash == "" {
		if len(u) < 3 || len(p) < 4 {
			cfgMu.Unlock()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Username >= 3 ky tu va Mat khau >= 4 ky tu!"})
			return
		}
		salt := randomHex(16)
		appCfg.AdminUser = u
		appCfg.AdminSalt = salt
		appCfg.AdminPassHash = hashPassword(salt, p)
		_ = saveConfigFile(appCfg)
		cfgMu.Unlock()
	} else {
		au, as, ah := appCfg.AdminUser, appCfg.AdminSalt, appCfg.AdminPassHash
		cfgMu.Unlock()
		if u != au || !verifyPassword(as, ah, p) {
			recordLoginFail(ip)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Sai tai khoan hoac mat khau!"})
			return
		}
	}

	tok := randomHex(24)
	sessMu.Lock()
	sessions[tok] = sessionInfo{user: u, exp: time.Now().Add(24 * time.Hour)}
	sessMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name: "ps_session", Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func apiLogout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie("ps_session"); err == nil {
		sessMu.Lock()
		delete(sessions, ck.Value)
		sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "ps_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ==================== Async Background Scanner ====================
var scanState struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	Running int32
	Mode    string
	Total   int64
	Done    int64
	Alive   int64
	Dead    int64
}

func probeRunner(ctx context.Context, pr *PortRunner, mode string) (string, int64, string, string) {
	t0 := time.Now()
	up := pr.GetUpstream()
	targetHost, targetPort := "1.1.1.1", uint16(443)
	if mode == "deep" {
		targetHost, targetPort = "api.ipify.org", uint16(80)
	}

	ctxDial, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := dialUpstreamCtx(ctxDial, up, targetHost, targetPort)
	if err != nil {
		lat := time.Since(t0).Milliseconds()
		pr.SetHealth("dead", lat, "", err.Error())
		return "dead", lat, "", err.Error()
	}
	defer conn.Close()

	exitIP := ""
	if mode == "deep" {
		_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
		_, wErr := conn.Write([]byte("GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n"))
		if wErr != nil {
			lat := time.Since(t0).Milliseconds()
			pr.SetHealth("dead", lat, "", wErr.Error())
			return "dead", lat, "", wErr.Error()
		}
		resp, rErr := http.ReadResponse(bufio.NewReader(conn), nil)
		if rErr != nil {
			lat := time.Since(t0).Milliseconds()
			pr.SetHealth("dead", lat, "", rErr.Error())
			return "dead", lat, "", rErr.Error()
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		ipStr := strings.TrimSpace(string(b))
		if net.ParseIP(ipStr) == nil {
			lat := time.Since(t0).Milliseconds()
			pr.SetHealth("dead", lat, "", "invalid exit ip")
			return "dead", lat, "", "invalid exit ip"
		}
		exitIP = ipStr
	}

	lat := time.Since(t0).Milliseconds()
	pr.SetHealth("alive", lat, exitIP, "")
	return "alive", lat, exitIP, ""
}

func triggerScan(mode string, onlyPorts []int) int {
	if mode != "deep" {
		mode = "quick"
	}
	scanState.mu.Lock()
	if atomic.LoadInt32(&scanState.Running) == 1 {
		scanState.mu.Unlock()
		return 0
	}

	var wantSet map[int]bool
	if len(onlyPorts) > 0 {
		wantSet = make(map[int]bool, len(onlyPorts))
		for _, p := range onlyPorts {
			wantSet[p] = true
		}
	}

	runnersMu.RLock()
	list := make([]*PortRunner, 0, len(runners))
	for p, pr := range runners {
		if wantSet == nil || wantSet[p] {
			list = append(list, pr)
		}
	}
	runnersMu.RUnlock()

	if len(list) == 0 {
		scanState.mu.Unlock()
		return 0
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanState.cancel = cancel
	scanState.Mode = mode
	atomic.StoreInt32(&scanState.Running, 1)
	atomic.StoreInt64(&scanState.Total, int64(len(list)))
	atomic.StoreInt64(&scanState.Done, 0)
	atomic.StoreInt64(&scanState.Alive, 0)
	atomic.StoreInt64(&scanState.Dead, 0)
	scanState.mu.Unlock()

	go func() {
		defer atomic.StoreInt32(&scanState.Running, 0)
		sem := make(chan struct{}, 25)
		var wg sync.WaitGroup
		for _, pr := range list {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func(runner *PortRunner) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
				st, _, _, _ := probeRunner(ctx, runner, mode)
				if st == "alive" {
					atomic.AddInt64(&scanState.Alive, 1)
				} else {
					atomic.AddInt64(&scanState.Dead, 1)
				}
				atomic.AddInt64(&scanState.Done, 1)
			}(pr)
		}
		wg.Wait()
	}()
	return len(list)
}

func apiScanStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		Mode  string `json:"mode"`
		Group string `json:"group"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	var onlyPorts []int
	if body.Group != "" && body.Group != "ALL" {
		cfgMu.RLock()
		for _, e := range appCfg.ProxyEntries {
			if e.Enabled && e.Group == body.Group {
				onlyPorts = append(onlyPorts, e.Port)
			}
		}
		cfgMu.RUnlock()
	}

	total := triggerScan(body.Mode, onlyPorts)
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "started", "total": total})
}

func apiScanStop(w http.ResponseWriter, r *http.Request) {
	scanState.mu.Lock()
	if scanState.cancel != nil {
		scanState.cancel()
	}
	scanState.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
}

func apiTestSinglePort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		Port int    `json:"port"`
		Mode string `json:"mode"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		return
	}
	if body.Mode != "quick" {
		body.Mode = "deep"
	}

	runnersMu.RLock()
	pr, ok := runners[body.Port]
	runnersMu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "cong dang tat hoac khong ton tai"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	st, lat, exitIP, errMsg := probeRunner(ctx, pr, body.Mode)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"port":       body.Port,
		"health":     st,
		"latency_ms": lat,
		"exit_ip":    exitIP,
		"error":      errMsg,
	})
}

func apiResetPortData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		Port int `json:"port"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	runnersMu.RLock()
	if body.Port > 0 {
		if pr, ok := runners[body.Port]; ok {
			atomic.StoreInt64(&pr.BytesUp, 0)
			atomic.StoreInt64(&pr.BytesDown, 0)
			atomic.StoreInt64(&pr.TotalReqs, 0)
			atomic.StoreInt64(&pr.SanitizedReqs, 0)
			atomic.StoreInt64(&pr.BlockedReqs, 0)
			atomic.StoreInt64(&pr.ErrorReqs, 0)
			pr.mu.Lock()
			pr.lastErr = ""
			pr.mu.Unlock()
		}
	} else {
		for _, pr := range runners {
			atomic.StoreInt64(&pr.BytesUp, 0)
			atomic.StoreInt64(&pr.BytesDown, 0)
			atomic.StoreInt64(&pr.TotalReqs, 0)
			atomic.StoreInt64(&pr.SanitizedReqs, 0)
			atomic.StoreInt64(&pr.BlockedReqs, 0)
			atomic.StoreInt64(&pr.ErrorReqs, 0)
			pr.mu.Lock()
			pr.lastErr = ""
			pr.mu.Unlock()
		}
	}
	runnersMu.RUnlock()
	savePortUsage()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ==================== Overview API ====================
func apiOverview(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	pUser := appCfg.ProxyUser
	pPass := appCfg.ProxyPass
	sPort := appCfg.StartPort
	quotaTB := appCfg.BandwidthQuotaTB
	autoMin := appCfg.AutoCheckMin
	totalConfigured := len(appCfg.ProxyEntries)
	groupMap := make(map[string]int)
	disabledCount := 0
	for _, e := range appCfg.ProxyEntries {
		g := e.Group
		if g == "" {
			g = "Mac dinh"
		}
		groupMap[g]++
		if !e.Enabled {
			disabledCount++
		}
	}
	cfgMu.RUnlock()

	var groups []string
	for g := range groupMap {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	var totalConns, totalReqs, totalSanitized, totalBlocked, totalErrors, totalUp, totalDown int64
	var alivePorts, deadPorts, runningPorts int

	runnersMu.RLock()
	runningPorts = len(runners)
	for _, pr := range runners {
		totalConns += atomic.LoadInt64(&pr.ActiveConns)
		totalReqs += atomic.LoadInt64(&pr.TotalReqs)
		totalSanitized += atomic.LoadInt64(&pr.SanitizedReqs)
		totalBlocked += atomic.LoadInt64(&pr.BlockedReqs)
		totalErrors += atomic.LoadInt64(&pr.ErrorReqs)
		totalUp += atomic.LoadInt64(&pr.BytesUp)
		totalDown += atomic.LoadInt64(&pr.BytesDown)

		pr.mu.RLock()
		hl := pr.health
		pr.mu.RUnlock()
		if hl == "alive" {
			alivePorts++
		} else if hl == "dead" {
			deadPorts++
		}
	}
	runnersMu.RUnlock()

	tsMu.RLock()
	tsCopy := make([]TimePoint, len(tsHistory))
	copy(tsCopy, tsHistory)
	tsMu.RUnlock()

	vpsMu.RLock()
	vps := vpsSnap
	vpsMu.RUnlock()

	quotaPct := 0.0
	if quotaTB > 0 {
		quotaBytes := quotaTB * 1099511627776.0
		quotaPct = (float64(vps.MonthTxBytes) / quotaBytes) * 100.0
	}

	sanCnt, blkCnt, rulesSync := getRulesStatus()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"public_ip":          pubIP,
		"uptime_sec":         int64(time.Since(startTime).Seconds()),
		"goroutines":         runtime.NumGoroutine(),
		"app_mem_mb":         readAppMemMB(),
		"dns_cache_cnt":      getDNSCacheCount(),
		"rules_sanitize_cnt": sanCnt,
		"rules_block_cnt":    blkCnt,
		"rules_last_sync":    rulesSync,
		"vps":                vps,
		"quota_tb":           quotaTB,
		"quota_pct":          quotaPct,
		"auto_check_min":     autoMin,
		"proxy_total":        totalConfigured,
		"proxy_count":        runningPorts,
		"disabled_count":     disabledCount,
		"alive_ports":        alivePorts,
		"dead_ports":         deadPorts,
		"groups":             groups,
		"active_conns":       totalConns,
		"total_reqs":         totalReqs,
		"total_sanitized":    totalSanitized,
		"total_blocked":      totalBlocked,
		"total_errors":       totalErrors,
		"total_bytes_up":     totalUp,
		"total_bytes_dn":     totalDown,
		"proxy_user":         pUser,
		"proxy_pass":         pPass,
		"start_port":         sPort,
		"timeseries":         tsCopy,
		"scan": map[string]interface{}{
			"running": atomic.LoadInt32(&scanState.Running) == 1,
			"total":   atomic.LoadInt64(&scanState.Total),
			"done":    atomic.LoadInt64(&scanState.Done),
			"alive":   atomic.LoadInt64(&scanState.Alive),
			"dead":    atomic.LoadInt64(&scanState.Dead),
		},
	})
}

// ==================== Paginated Ports API (Group + Status + Enabled) ====================
func apiPorts(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	filter := r.URL.Query().Get("filter")
	groupFilter := r.URL.Query().Get("group")
	sortBy := r.URL.Query().Get("sort")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}

	cfgMu.RLock()
	entries := make([]ProxyEntry, len(appCfg.ProxyEntries))
	copy(entries, appCfg.ProxyEntries)
	cfgMu.RUnlock()

	type portItem struct {
		Port          int    `json:"port"`
		Group         string `json:"group"`
		Note          string `json:"note"`
		Enabled       bool   `json:"enabled"`
		Upstream      string `json:"upstream"`
		UpstreamFull  string `json:"upstream_full"`
		Proto         string `json:"proto"`
		ActiveConns   int64  `json:"active_conns"`
		TotalReqs     int64  `json:"total_reqs"`
		SanitizedReqs int64  `json:"sanitized_reqs"`
		BlockedReqs   int64  `json:"blocked_reqs"`
		ErrorReqs     int64  `json:"error_reqs"`
		BytesUp       int64  `json:"bytes_up"`
		BytesDown     int64  `json:"bytes_down"`
		Health        string `json:"health"`
		LatencyMs     int64  `json:"latency_ms"`
		ExitIP        string `json:"exit_ip"`
		LastErr       string `json:"last_err"`
	}

	matched := make([]portItem, 0, len(entries))
	runnersMu.RLock()
	for _, ent := range entries {
		grp := ent.Group
		if grp == "" {
			grp = "Mac dinh"
		}
		if groupFilter != "" && groupFilter != "ALL" && grp != groupFilter {
			continue
		}

		item := portItem{
			Port:         ent.Port,
			Group:        grp,
			Note:         ent.Note,
			Enabled:      ent.Enabled,
			Upstream:     ent.Upstream.Addr(),
			UpstreamFull: formatOneUpstream(ent.Upstream),
			Proto:        ent.Upstream.Proto,
			Health:       "disabled",
		}

		if ent.Enabled {
			if pr, ok := runners[ent.Port]; ok {
				item.ActiveConns = atomic.LoadInt64(&pr.ActiveConns)
				item.TotalReqs = atomic.LoadInt64(&pr.TotalReqs)
				item.SanitizedReqs = atomic.LoadInt64(&pr.SanitizedReqs)
				item.BlockedReqs = atomic.LoadInt64(&pr.BlockedReqs)
				item.ErrorReqs = atomic.LoadInt64(&pr.ErrorReqs)
				item.BytesUp = atomic.LoadInt64(&pr.BytesUp)
				item.BytesDown = atomic.LoadInt64(&pr.BytesDown)
				pr.mu.RLock()
				item.Health = pr.health
				item.LatencyMs = pr.latency
				item.ExitIP = pr.exitIP
				item.LastErr = pr.lastErr
				pr.mu.RUnlock()
			} else {
				item.Health = "untested"
			}
		}

		switch filter {
		case "alive":
			if item.Health != "alive" {
				continue
			}
		case "dead":
			if item.Health != "dead" {
				continue
			}
		case "disabled":
			if item.Enabled {
				continue
			}
		case "untested":
			if item.Health != "untested" {
				continue
			}
		case "err":
			if item.ErrorReqs == 0 {
				continue
			}
		case "blocked":
			if item.BlockedReqs == 0 {
				continue
			}
		}

		if q != "" {
			hay := strings.ToLower(fmt.Sprintf("%d %s %s %s %s %s %s", item.Port, item.Upstream, item.ExitIP, item.LastErr, item.Group, item.Note, item.Proto))
			if !strings.Contains(hay, q) {
				continue
			}
		}

		matched = append(matched, item)
	}
	runnersMu.RUnlock()

	sort.Slice(matched, func(i, j int) bool {
		switch sortBy {
		case "traffic":
			return (matched[i].BytesUp + matched[i].BytesDown) > (matched[j].BytesUp + matched[j].BytesDown)
		case "reqs":
			return matched[i].TotalReqs > matched[j].TotalReqs
		case "err":
			return matched[i].ErrorReqs > matched[j].ErrorReqs
		case "latency":
			return matched[i].LatencyMs > matched[j].LatencyMs
		default:
			return matched[i].Port < matched[j].Port
		}
	})

	total := len(matched)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total": total,
		"page":  page,
		"limit": limit,
		"rows":  matched[start:end],
	})
}

// ==================== Rules APIs (Sanitize + Block) ====================
func apiAddRuleKeyword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		Keyword string `json:"keyword"`
		Mode    string `json:"mode"` // "sanitize" or "block"
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		return
	}
	kw := strings.ToLower(strings.TrimSpace(body.Keyword))
	if len(kw) < 2 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tu khoa qua ngan"})
		return
	}

	cfgMu.Lock()
	if body.Mode == "block" {
		exists := false
		for _, k := range appCfg.BlockKeywords {
			if k == kw {
				exists = true
				break
			}
		}
		if !exists {
			appCfg.BlockKeywords = append(appCfg.BlockKeywords, kw)
			_ = saveConfigFile(appCfg)
		}
	} else {
		exists := false
		for _, k := range appCfg.SanitizeKeywords {
			if k == kw {
				exists = true
				break
			}
		}
		if !exists {
			appCfg.SanitizeKeywords = append(appCfg.SanitizeKeywords, kw)
			_ = saveConfigFile(appCfg)
		}
	}
	us := appCfg.SanitizeKeywords
	ub := appCfg.BlockKeywords
	bp := appCfg.BlockDangerousPorts
	cfgMu.Unlock()

	rebuildAllRules(us, ub, bp)
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "keyword": kw})
}

func apiSyncRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	sanCnt, blkCnt, err := syncRulesFromGitHub(true)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Khong tai duoc rules GitHub: " + err.Error()})
		return
	}
	_, _, last := getRulesStatus()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "ok",
		"sanitize_cnt": sanCnt,
		"block_cnt":    blkCnt,
		"last_sync":    last,
	})
}

// ==================== Requests Inspector ====================
func collectFilteredRequests(q, actionFilter, protoFilter, portFilter string, limit int) []RequestRecord {
	q = strings.ToLower(strings.TrimSpace(q))
	portWant := 0
	if portFilter != "" {
		portWant, _ = strconv.Atoi(portFilter)
	}

	nowNano := time.Now().UnixNano()
	var activeSnapshot []RequestRecord
	activeMu.RLock()
	for _, rec := range activeMap {
		cp := *rec
		cp.DurationMs = (nowNano - cp.StartUnix) / 1e6
		activeSnapshot = append(activeSnapshot, cp)
	}
	activeMu.RUnlock()
	sort.Slice(activeSnapshot, func(i, j int) bool { return activeSnapshot[i].ID > activeSnapshot[j].ID })

	match := func(r RequestRecord) bool {
		if portWant > 0 && r.Port != portWant {
			return false
		}
		if protoFilter != "" && protoFilter != "ALL" && !strings.HasPrefix(r.Protocol, protoFilter) {
			return false
		}
		switch actionFilter {
		case "SANITIZED":
			if !r.Sanitized {
				return false
			}
		case "DIRECT":
			if r.Sanitized || r.Status == "BLK" {
				return false
			}
		case "LIVE":
			if r.Status != "LIVE" {
				return false
			}
		case "BLK":
			if r.Status != "BLK" {
				return false
			}
		case "ERR":
			if r.Status != "ERR" {
				return false
			}
		}
		if q != "" {
			hay := strings.ToLower(r.OrigTarget + " " + r.SentTarget + " " + r.Upstream + " " + r.ClientIP + " " + r.ErrorMsg)
			if !strings.Contains(hay, q) {
				return false
			}
		}
		return true
	}

	out := make([]RequestRecord, 0, limit)
	for _, r := range activeSnapshot {
		if match(r) {
			out = append(out, r)
			if len(out) >= limit {
				return out
			}
		}
	}

	histMu.RLock()
	cnt := histCount
	head := histHead
	for i := 0; i < cnt; i++ {
		idx := (head - 1 - i + maxHistoryLogs) % maxHistoryLogs
		r := histBuf[idx]
		if match(r) {
			out = append(out, r)
			if len(out) >= limit {
				break
			}
		}
	}
	histMu.RUnlock()
	return out
}

func apiRequests(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows := collectFilteredRequests(
		r.URL.Query().Get("q"),
		r.URL.Query().Get("action"),
		r.URL.Query().Get("proto"),
		r.URL.Query().Get("port"),
		limit,
	)
	writeJSON(w, http.StatusOK, map[string]interface{}{"rows": rows})
}

func apiExportCSV(w http.ResponseWriter, r *http.Request) {
	rows := collectFilteredRequests(
		r.URL.Query().Get("q"),
		r.URL.Query().Get("action"),
		r.URL.Query().Get("proto"),
		r.URL.Query().Get("port"),
		3000,
	)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="proxyshield_requests.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"Time", "Port", "ClientIP", "OriginalTarget", "SentToUpstream", "Sanitized", "UpstreamProxy", "Protocol", "BytesUp", "BytesDown", "DurationMs", "Status", "Error"})
	for _, row := range rows {
		_ = cw.Write([]string{
			row.TimeStr, strconv.Itoa(row.Port), row.ClientIP, row.OrigTarget, row.SentTarget,
			strconv.FormatBool(row.Sanitized), row.Upstream, row.Protocol,
			strconv.FormatInt(row.BytesUp, 10), strconv.FormatInt(row.BytesDown, 10),
			strconv.FormatInt(row.DurationMs, 10), row.Status, row.ErrorMsg,
		})
	}
	cw.Flush()
}

func apiClearLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	histMu.Lock()
	histHead = 0
	histCount = 0
	histMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ==================== Smart Proxy Manager APIs (Batch Add / Edit / Toggle / Bulk) ====================
func apiGetConfig(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	c := appCfg
	cfgMu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"public_ip":             pubIP,
		"admin_user":            c.AdminUser,
		"proxy_user":            c.ProxyUser,
		"proxy_pass":            c.ProxyPass,
		"start_port":            c.StartPort,
		"default_up_proto":      c.DefaultUpProto,
		"auto_check_min":        c.AutoCheckMin,
		"bandwidth_quota_tb":    c.BandwidthQuotaTB,
		"block_dangerous_ports": c.BlockDangerousPorts,
		"sanitize_keywords":     strings.Join(c.SanitizeKeywords, ", "),
		"block_keywords":        strings.Join(c.BlockKeywords, ", "),
	})
}

func apiAddOrReplaceProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		ProxiesRaw     string `json:"proxies_raw"`
		DefaultUpProto string `json:"default_up_proto"`
		Group          string `json:"group"`
		Note           string `json:"note"`
		Mode           string `json:"mode"` // "append" or "replace"
		Dedup          bool   `json:"dedup"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if body.DefaultUpProto != "socks5" {
		body.DefaultUpProto = "http"
	}
	grp := strings.TrimSpace(body.Group)
	if grp == "" {
		grp = "Mac dinh"
	}
	note := strings.TrimSpace(body.Note)
	pStats := parseProxiesFlexible(body.ProxiesRaw, body.DefaultUpProto, body.Dedup)

	var addedPorts []int
	skippedDupes := pStats.Dupes

	cfgMu.Lock()
	newCfg := appCfg
	newCfg.DefaultUpProto = body.DefaultUpProto

	if body.Mode == "replace" {
		newEntries := make([]ProxyEntry, 0, len(pStats.Items))
		for i, u := range pStats.Items {
			p := newCfg.StartPort + i
			if p > 65535 {
				break
			}
			newEntries = append(newEntries, ProxyEntry{
				Port: p, Group: grp, Note: note, Enabled: true, Upstream: u,
			})
			addedPorts = append(addedPorts, p)
		}
		newCfg.ProxyEntries = newEntries
	} else {
		// Append mode: giu nguyen cac cong cu, chi them con moi vao cong ke tiep
		usedPorts := make(map[int]bool, len(newCfg.ProxyEntries))
		existingKeys := make(map[string]bool, len(newCfg.ProxyEntries))
		maxPort := newCfg.StartPort - 1
		for _, e := range newCfg.ProxyEntries {
			usedPorts[e.Port] = true
			existingKeys[upstreamKey(e.Upstream)] = true
			if e.Port > maxPort {
				maxPort = e.Port
			}
		}
		nextPort := maxPort + 1
		for _, u := range pStats.Items {
			if body.Dedup && existingKeys[upstreamKey(u)] {
				skippedDupes++
				continue
			}
			for usedPorts[nextPort] && nextPort <= 65535 {
				nextPort++
			}
			if nextPort > 65535 {
				break
			}
			usedPorts[nextPort] = true
			existingKeys[upstreamKey(u)] = true
			newCfg.ProxyEntries = append(newCfg.ProxyEntries, ProxyEntry{
				Port: nextPort, Group: grp, Note: note, Enabled: true, Upstream: u,
			})
			addedPorts = append(addedPorts, nextPort)
			nextPort++
		}
	}

	syncRawFromEntries(&newCfg)
	appCfg = newCfg
	_ = saveConfigFile(newCfg)
	cfgMu.Unlock()

	cnt, err := applyConfigAndReload(newCfg)
	if len(addedPorts) > 0 {
		go triggerScan("deep", addedPorts)
	}

	resp := map[string]interface{}{
		"status":       "ok",
		"active_ports": cnt,
		"added":        len(addedPorts),
		"dupes":        skippedDupes,
		"invalid":      pStats.Invalid,
	}
	if err != nil {
		resp["warning"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func apiProxyEntryAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		Port         int    `json:"port"`
		Action       string `json:"action"` // "toggle", "edit", "delete"
		UpstreamLine string `json:"upstream_line"`
		Group        string `json:"group"`
		Note         string `json:"note"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}

	var testPort []int
	found := false

	cfgMu.Lock()
	newCfg := appCfg
	outEntries := make([]ProxyEntry, 0, len(newCfg.ProxyEntries))
	for _, e := range newCfg.ProxyEntries {
		if e.Port != body.Port {
			outEntries = append(outEntries, e)
			continue
		}
		found = true
		switch body.Action {
		case "delete":
			// bo qua khong them vao outEntries
		case "toggle":
			e.Enabled = !e.Enabled
			if e.Enabled {
				testPort = []int{e.Port}
			}
			outEntries = append(outEntries, e)
		case "edit":
			if strings.TrimSpace(body.UpstreamLine) != "" {
				u, ok := parseSingleUpstream(body.UpstreamLine, e.Upstream.Proto)
				if !ok {
					cfgMu.Unlock()
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Dinh dang Proxy nguon khong hop le!"})
					return
				}
				e.Upstream = u
				if e.Enabled {
					testPort = []int{e.Port}
				}
			}
			if strings.TrimSpace(body.Group) != "" {
				e.Group = strings.TrimSpace(body.Group)
			}
			e.Note = strings.TrimSpace(body.Note)
			outEntries = append(outEntries, e)
		default:
			outEntries = append(outEntries, e)
		}
	}
	if !found {
		cfgMu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Khong tim thay cong nay"})
		return
	}
	newCfg.ProxyEntries = outEntries
	syncRawFromEntries(&newCfg)
	appCfg = newCfg
	_ = saveConfigFile(newCfg)
	cfgMu.Unlock()

	cnt, _ := applyConfigAndReload(newCfg)
	if len(testPort) > 0 {
		go triggerScan("deep", testPort)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "active_ports": cnt})
}

func apiProxyBulkAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		Action string `json:"action"` // "enable", "disable", "delete_dead", "delete_selected", "set_group", "reindex"
		Ports  []int  `json:"ports"`
		Group  string `json:"group"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		return
	}

	sel := make(map[int]bool, len(body.Ports))
	for _, p := range body.Ports {
		sel[p] = true
	}

	deadMap := make(map[int]bool)
	if body.Action == "delete_dead" {
		runnersMu.RLock()
		for p, pr := range runners {
			pr.mu.RLock()
			if pr.health == "dead" {
				deadMap[p] = true
			}
			pr.mu.RUnlock()
		}
		runnersMu.RUnlock()
	}

	affected := 0
	cfgMu.Lock()
	newCfg := appCfg
	out := make([]ProxyEntry, 0, len(newCfg.ProxyEntries))

	for i, e := range newCfg.ProxyEntries {
		inTarget := len(sel) == 0 || sel[e.Port]
		switch body.Action {
		case "delete_dead":
			if deadMap[e.Port] {
				affected++
				continue
			}
			out = append(out, e)
		case "delete_selected":
			if sel[e.Port] {
				affected++
				continue
			}
			out = append(out, e)
		case "enable":
			if inTarget && !e.Enabled {
				e.Enabled = true
				affected++
			}
			out = append(out, e)
		case "disable":
			if inTarget && e.Enabled {
				e.Enabled = false
				affected++
			}
			out = append(out, e)
		case "set_group":
			if inTarget && strings.TrimSpace(body.Group) != "" {
				e.Group = strings.TrimSpace(body.Group)
				affected++
			}
			out = append(out, e)
		case "reindex":
			e.Port = newCfg.StartPort + i
			if e.Port <= 65535 {
				out = append(out, e)
				affected++
			}
		default:
			out = append(out, e)
		}
	}

	newCfg.ProxyEntries = out
	syncRawFromEntries(&newCfg)
	appCfg = newCfg
	_ = saveConfigFile(newCfg)
	cfgMu.Unlock()

	cnt, _ := applyConfigAndReload(newCfg)
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "affected": affected, "active_ports": cnt})
}

func apiSaveSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		ProxyUser           string  `json:"proxy_user"`
		ProxyPass           string  `json:"proxy_pass"`
		StartPort           int     `json:"start_port"`
		AutoCheckMin        int     `json:"auto_check_min"`
		BandwidthQuotaTB    float64 `json:"bandwidth_quota_tb"`
		BlockDangerousPorts bool    `json:"block_dangerous_ports"`
		SanitizeKeywords    string  `json:"sanitize_keywords"`
		BlockKeywords       string  `json:"block_keywords"`
		NewAdminUser        string  `json:"new_admin_user"`
		NewAdminPass        string  `json:"new_admin_pass"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if strings.TrimSpace(body.ProxyUser) == "" || strings.TrimSpace(body.ProxyPass) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Username/Password proxy khong duoc de trong!"})
		return
	}
	if body.StartPort < 1024 || body.StartPort > 60000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Start Port phai tu 1024 den 60000!"})
		return
	}
	if body.AutoCheckMin < 0 {
		body.AutoCheckMin = 0
	}
	if body.BandwidthQuotaTB < 0 {
		body.BandwidthQuotaTB = 0
	}

	splitCSV := func(s string) []string {
		var out []string
		for _, k := range strings.Split(s, ",") {
			k = strings.TrimSpace(strings.ToLower(k))
			if k != "" {
				out = append(out, k)
			}
		}
		return out
	}

	cfgMu.Lock()
	newCfg := appCfg
	newCfg.ProxyUser = strings.TrimSpace(body.ProxyUser)
	newCfg.ProxyPass = strings.TrimSpace(body.ProxyPass)
	newCfg.StartPort = body.StartPort
	newCfg.AutoCheckMin = body.AutoCheckMin
	newCfg.BandwidthQuotaTB = body.BandwidthQuotaTB
	newCfg.BlockDangerousPorts = body.BlockDangerousPorts
	newCfg.SanitizeKeywords = splitCSV(body.SanitizeKeywords)
	newCfg.BlockKeywords = splitCSV(body.BlockKeywords)
	if strings.TrimSpace(body.NewAdminUser) != "" {
		newCfg.AdminUser = strings.TrimSpace(body.NewAdminUser)
	}
	if strings.TrimSpace(body.NewAdminPass) != "" {
		salt := randomHex(16)
		newCfg.AdminSalt = salt
		newCfg.AdminPassHash = hashPassword(salt, strings.TrimSpace(body.NewAdminPass))
	}
	appCfg = newCfg
	_ = saveConfigFile(newCfg)
	cfgMu.Unlock()

	cnt, err := applyConfigAndReload(newCfg)
	resp := map[string]interface{}{"status": "ok", "active_ports": cnt}
	if err != nil {
		resp["warning"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func apiExportWrapped(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	groupFilter := r.URL.Query().Get("group")

	cfgMu.RLock()
	c := appCfg
	entries := make([]ProxyEntry, len(appCfg.ProxyEntries))
	copy(entries, appCfg.ProxyEntries)
	cfgMu.RUnlock()

	type exportRow struct {
		port  int
		proto string
	}
	var rows []exportRow
	runnersMu.RLock()
	for _, ent := range entries {
		if !ent.Enabled {
			continue
		}
		grp := ent.Group
		if grp == "" {
			grp = "Mac dinh"
		}
		if groupFilter != "" && groupFilter != "ALL" && grp != groupFilter {
			continue
		}
		hl := "untested"
		if pr, ok := runners[ent.Port]; ok {
			pr.mu.RLock()
			hl = pr.health
			pr.mu.RUnlock()
		}
		if filter == "alive" && hl != "alive" {
			continue
		}
		if filter == "hide_dead" && hl == "dead" {
			continue
		}
		rows = append(rows, exportRow{port: ent.Port, proto: ent.Upstream.Proto})
	}
	runnersMu.RUnlock()

	sort.Slice(rows, func(i, j int) bool { return rows[i].port < rows[j].port })

	var lines []string
	for _, row := range rows {
		lines = append(lines, fmt.Sprintf("%s://%s:%s@%s:%d", row.proto, c.ProxyUser, c.ProxyPass, pubIP, row.port))
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.URL.Query().Get("dl") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="wrapped_proxies.txt"`)
	}
	_, _ = w.Write([]byte(strings.Join(lines, "\n")))
}

func apiBackupConfig(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	c := appCfg
	cfgMu.RUnlock()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="proxyshield-backup.json"`)
	_ = json.NewEncoder(w).Encode(c)
}

func apiRestoreConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var c Config
	if json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&c) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "File backup JSON khong hop le!"})
		return
	}
	if c.ProxyUser == "" || c.ProxyPass == "" || c.StartPort < 1024 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Thieu thong tin proxy/port trong file backup!"})
		return
	}
	if len(c.ProxyEntries) == 0 && strings.TrimSpace(c.ProxiesRaw) != "" {
		ps := parseProxiesFlexible(c.ProxiesRaw, c.DefaultUpProto, false)
		for i, u := range ps.Items {
			c.ProxyEntries = append(c.ProxyEntries, ProxyEntry{
				Port: c.StartPort + i, Group: "Mac dinh", Enabled: true, Upstream: u,
			})
		}
	}

	cfgMu.Lock()
	if c.AdminUser == "" || c.AdminPassHash == "" {
		c.AdminUser = appCfg.AdminUser
		c.AdminSalt = appCfg.AdminSalt
		c.AdminPassHash = appCfg.AdminPassHash
	}
	syncRawFromEntries(&c)
	appCfg = c
	_ = saveConfigFile(c)
	cfgMu.Unlock()

	cnt, _ := applyConfigAndReload(c)
	go triggerScan("deep", nil)
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "active_ports": cnt})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(dashboardHTML))
}

func startWebDashboard(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/auth/status", apiAuthStatus)
	mux.HandleFunc("/api/login", apiLogin)
	mux.HandleFunc("/api/logout", apiLogout)
	mux.HandleFunc("/api/overview", requireAuth(apiOverview))
	mux.HandleFunc("/api/ports", requireAuth(apiPorts))
	mux.HandleFunc("/api/ports/test", requireAuth(apiTestSinglePort))
	mux.HandleFunc("/api/ports/reset", requireAuth(apiResetPortData))
	mux.HandleFunc("/api/rules/add", requireAuth(apiAddRuleKeyword))
	mux.HandleFunc("/api/rules/sync", requireAuth(apiSyncRules))
	mux.HandleFunc("/api/requests", requireAuth(apiRequests))
	mux.HandleFunc("/api/requests/csv", requireAuth(apiExportCSV))
	mux.HandleFunc("/api/requests/clear", requireAuth(apiClearLogs))
	mux.HandleFunc("/api/config", requireAuth(apiGetConfig))
	mux.HandleFunc("/api/proxies/save", requireAuth(apiAddOrReplaceProxies))
	mux.HandleFunc("/api/proxies/entry", requireAuth(apiProxyEntryAction))
	mux.HandleFunc("/api/proxies/bulk", requireAuth(apiProxyBulkAction))
	mux.HandleFunc("/api/scan/start", requireAuth(apiScanStart))
	mux.HandleFunc("/api/scan/stop", requireAuth(apiScanStop))
	mux.HandleFunc("/api/settings/save", requireAuth(apiSaveSettings))
	mux.HandleFunc("/api/export", requireAuth(apiExportWrapped))
	mux.HandleFunc("/api/backup", requireAuth(apiBackupConfig))
	mux.HandleFunc("/api/restore", requireAuth(apiRestoreConfig))

	srv := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}