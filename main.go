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
	User     string   `json:"user"`
	Pass     string   `json:"pass"`
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

type PreviewResult struct {
	TotalLines   int        `json:"total_lines"`
	ValidNew     []Upstream `json:"-"`
	NewCount     int        `json:"new_count"`
	DupBatch     []string   `json:"dup_batch"`
	DupExisting  []string   `json:"dup_existing"`
	InvalidLines []string   `json:"invalid_lines"`
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
	time.Sleep(15 * time.Second)
	for {
		cfgMu.RLock()
		mins := appCfg.AutoCheckMin
		cfgMu.RUnlock()

		if mins > 0 {
			now := time.Now().Unix()
			var needCheck []int
			runnersMu.RLock()
			for port, pr := range runners {
				if atomic.LoadInt64(&pr.ActiveConns) > 0 || (now-atomic.LoadInt64(&pr.LastOKUnix) < 900) {
					continue
				}
				needCheck = append(needCheck, port)
			}
			runnersMu.RUnlock()
			if len(needCheck) > 0 {
				triggerScan("quick", needCheck)
			}
		} else {
			mins = 1
		}
		time.Sleep(time.Duration(mins) * time.Minute)
	}
}

// ==================== Tien ich Random User/Pass & Check Trung Sieu Toc ====================
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomAlphaNum(n int) string {
	const chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	rb := make([]byte, n)
	_, _ = rand.Read(rb)
	for i := 0; i < n; i++ {
		b[i] = chars[int(rb[i])%len(chars)]
	}
	return string(b)
}

// Sinh user:pass ngau nhien doc nhat khong bao gio trung lap
func genUniqueProxyCreds(usedUsers map[string]bool) (string, string) {
	for i := 0; i < 64; i++ {
		u := "px" + randomAlphaNum(8)
		if !usedUsers[u] {
			usedUsers[u] = true
			return u, randomAlphaNum(14)
		}
	}
	u := "px" + randomHex(6)
	usedUsers[u] = true
	return u, randomAlphaNum(14)
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

// Kiem tra trung lap sieu toc (<2ms cho 1000 dong) so voi danh sach dang chay
func previewProxies(raw, defaultProto, mode string, dedup bool, existing []ProxyEntry) PreviewResult {
	res := PreviewResult{
		DupBatch:     []string{},
		DupExisting:  []string{},
		InvalidLines: []string{},
	}

	existingMap := make(map[string]int, len(existing))
	if mode != "replace" {
		for _, e := range existing {
			existingMap[upstreamKey(e.Upstream)] = e.Port
		}
	}
	batchSeen := make(map[string]bool)

	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		res.TotalLines++
		u, ok := parseSingleUpstream(line, defaultProto)
		if !ok {
			res.InvalidLines = append(res.InvalidLines, line)
			continue
		}
		k := upstreamKey(u)
		if dedup {
			if existPort, ok := existingMap[k]; ok {
				res.DupExisting = append(res.DupExisting, fmt.Sprintf("%s (da co o :%d)", u.Addr(), existPort))
				continue
			}
			if batchSeen[k] {
				res.DupBatch = append(res.DupBatch, u.Addr())
				continue
			}
			batchSeen[k] = true
		}
		res.ValidNew = append(res.ValidNew, u)
	}
	res.NewCount = len(res.ValidNew)
	return res
}

func syncRawFromEntries(cfg *Config) {
	var lines []string
	for _, e := range cfg.ProxyEntries {
		lines = append(lines, formatOneUpstream(e.Upstream))
	}
	cfg.ProxiesRaw = strings.Join(lines, "\n")
}

func entryCreds(e ProxyEntry, fallbackUser, fallbackPass string) (string, string) {
	if e.User != "" && e.Pass != "" {
		return e.User, e.Pass
	}
	return fallbackUser, fallbackPass
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
		u, p := entryCreds(e, cfg.ProxyUser, cfg.ProxyPass)
		lines = append(lines, fmt.Sprintf("%s://%s:%s@%s:%d", e.Upstream.Proto, u, p, pubIP, e.Port))
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
		eu, ep := entryCreds(ent, cfg.ProxyUser, cfg.ProxyPass)
		if pr, exists := runners[port]; exists {
			oldUp := pr.GetUpstream()
			pr.SetMeta(ent.Upstream, ent.Group, ent.Note, eu, ep)
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
			Port:      port,
			upstream:  ent.Upstream,
			group:     ent.Group,
			note:      ent.Note,
			proxyUser: eu,
			proxyPass: ep,
			health:    "untested",
			ln:        ln,
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
				if c.ConfigVersion < 40 {
					if c.ConfigVersion < 35 {
						c.BlockDangerousPorts = true
						if c.BandwidthQuotaTB == 0 {
							c.BandwidthQuotaTB = 10.0
						}
					}
					c.ConfigVersion = 40
					changed = true
				}
				if len(c.ProxyEntries) == 0 && strings.TrimSpace(c.ProxiesRaw) != "" {
					ps := parseProxiesFlexible(c.ProxiesRaw, c.DefaultUpProto, false)
					usedU := make(map[string]bool)
					for i, u := range ps.Items {
						pu, pp := genUniqueProxyCreds(usedU)
						c.ProxyEntries = append(c.ProxyEntries, ProxyEntry{
							Port: c.StartPort + i, Group: "Mac dinh", Enabled: true, User: pu, Pass: pp, Upstream: u,
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
		ConfigVersion:       40,
		AdminUser:           aUser,
		AdminSalt:           aSalt,
		AdminPassHash:       aHash,
		ProxyUser:           "px" + randomAlphaNum(6),
		ProxyPass:           randomAlphaNum(14),
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
	used := map[string]bool{}
	u1, p1 := genUniqueProxyCreds(used)
	u2, p2 := genUniqueProxyCreds(used)
	if u1 == "" || p1 == "" || u1 == u2 || p1 == p2 {
		fmt.Println("SELF-TEST FAIL: loi sinh credentials ngau nhien")
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

	log.Printf("ProxyShield v4.0 Pro san sang! Public IP: %s | %d cong | Dashboard: http://%s:%d", pubIP, cnt, pubIP, dashPort)

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