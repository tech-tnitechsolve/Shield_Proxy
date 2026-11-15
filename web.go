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

func triggerScan(mode string) int {
	if mode != "deep" {
		mode = "quick"
	}
	scanState.mu.Lock()
	if atomic.LoadInt32(&scanState.Running) == 1 {
		scanState.mu.Unlock()
		return 0
	}

	runnersMu.RLock()
	list := make([]*PortRunner, 0, len(runners))
	for _, pr := range runners {
		list = append(list, pr)
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
		sem := make(chan struct{}, 50)
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
		Mode string `json:"mode"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	total := triggerScan(body.Mode)
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
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "cong khong ton tai"})
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

func apiOverview(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var totalConns, totalReqs, totalSanitized, totalErrors, totalUp, totalDown int64
	var alivePorts, deadPorts, totalPorts int

	runnersMu.RLock()
	totalPorts = len(runners)
	for _, pr := range runners {
		totalConns += atomic.LoadInt64(&pr.ActiveConns)
		totalReqs += atomic.LoadInt64(&pr.TotalReqs)
		totalSanitized += atomic.LoadInt64(&pr.SanitizedReqs)
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

	cfgMu.RLock()
	pUser, pPass, sPort, quotaTB, autoMin := appCfg.ProxyUser, appCfg.ProxyPass, appCfg.StartPort, appCfg.BandwidthQuotaTB, appCfg.AutoCheckMin
	cfgMu.RUnlock()

	quotaPct := 0.0
	if quotaTB > 0 {
		quotaBytes := quotaTB * 1099511627776.0
		quotaPct = (float64(vps.MonthTxBytes) / quotaBytes) * 100.0
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"public_ip":       pubIP,
		"uptime_sec":      int64(time.Since(startTime).Seconds()),
		"goroutines":      runtime.NumGoroutine(),
		"app_mem_mb":      float64(m.Alloc) / 1048576.0,
		"dns_cache_cnt":   getDNSCacheCount(),
		"vps":             vps,
		"quota_tb":        quotaTB,
		"quota_pct":       quotaPct,
		"auto_check_min":  autoMin,
		"proxy_count":     totalPorts,
		"alive_ports":     alivePorts,
		"dead_ports":      deadPorts,
		"active_conns":    totalConns,
		"total_reqs":      totalReqs,
		"total_sanitized": totalSanitized,
		"total_errors":    totalErrors,
		"total_bytes_up":  totalUp,
		"total_bytes_dn":  totalDown,
		"proxy_user":      pUser,
		"proxy_pass":      pPass,
		"start_port":      sPort,
		"timeseries":      tsCopy,
		"scan": map[string]interface{}{
			"running": atomic.LoadInt32(&scanState.Running) == 1,
			"total":   atomic.LoadInt64(&scanState.Total),
			"done":    atomic.LoadInt64(&scanState.Done),
			"alive":   atomic.LoadInt64(&scanState.Alive),
			"dead":    atomic.LoadInt64(&scanState.Dead),
		},
	})
}

// ==================== Paginated Ports API ====================
func apiPorts(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	filter := r.URL.Query().Get("filter")
	sortBy := r.URL.Query().Get("sort")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}

	type portItem struct {
		Port          int    `json:"port"`
		Upstream      string `json:"upstream"`
		Proto         string `json:"proto"`
		ActiveConns   int64  `json:"active_conns"`
		TotalReqs     int64  `json:"total_reqs"`
		SanitizedReqs int64  `json:"sanitized_reqs"`
		ErrorReqs     int64  `json:"error_reqs"`
		BytesUp       int64  `json:"bytes_up"`
		BytesDown     int64  `json:"bytes_down"`
		Health        string `json:"health"`
		LatencyMs     int64  `json:"latency_ms"`
		ExitIP        string `json:"exit_ip"`
		LastErr       string `json:"last_err"`
	}

	runnersMu.RLock()
	matched := make([]portItem, 0, len(runners))
	for _, pr := range runners {
		ac := atomic.LoadInt64(&pr.ActiveConns)
		tr := atomic.LoadInt64(&pr.TotalReqs)
		sr := atomic.LoadInt64(&pr.SanitizedReqs)
		er := atomic.LoadInt64(&pr.ErrorReqs)
		bu := atomic.LoadInt64(&pr.BytesUp)
		bd := atomic.LoadInt64(&pr.BytesDown)

		pr.mu.RLock()
		up := pr.upstream
		hl := pr.health
		lat := pr.latency
		eip := pr.exitIP
		le := pr.lastErr
		pr.mu.RUnlock()

		switch filter {
		case "alive":
			if hl != "alive" {
				continue
			}
		case "dead":
			if hl != "dead" {
				continue
			}
		case "untested":
			if hl != "untested" {
				continue
			}
		case "active":
			if ac == 0 {
				continue
			}
		case "err":
			if er == 0 {
				continue
			}
		}

		if q != "" {
			hay := strings.ToLower(fmt.Sprintf("%d %s %s %s %s", pr.Port, up.Addr(), eip, le, up.Proto))
			if !strings.Contains(hay, q) {
				continue
			}
		}

		matched = append(matched, portItem{
			Port: pr.Port, Upstream: up.Addr(), Proto: up.Proto,
			ActiveConns: ac, TotalReqs: tr, SanitizedReqs: sr, ErrorReqs: er,
			BytesUp: bu, BytesDown: bd, Health: hl, LatencyMs: lat, ExitIP: eip, LastErr: le,
		})
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

// ==================== Domain Intelligence ====================
func apiDomains(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	filter := r.URL.Query().Get("filter")

	type domRow struct {
		Domain     string `json:"domain"`
		Hits       int64  `json:"hits"`
		Sanitized  int64  `json:"sanitized"`
		Errors     int64  `json:"errors"`
		Bytes      int64  `json:"bytes"`
		ResolvedIP string `json:"resolved_ip"`
		IsTargeted bool   `json:"is_targeted"`
		LastSeen   string `json:"last_seen"`
	}

	domMu.RLock()
	rows := make([]domRow, 0, len(domStats))
	for _, ds := range domStats {
		hits := atomic.LoadInt64(&ds.Hits)
		san := atomic.LoadInt64(&ds.Sanitized)
		errs := atomic.LoadInt64(&ds.Errors)
		b := atomic.LoadInt64(&ds.BytesUp) + atomic.LoadInt64(&ds.BytesDown)
		ls := atomic.LoadInt64(&ds.LastSeen)

		ds.mu.RLock()
		rip := ds.ResolvedIP
		dom := ds.Domain
		ds.mu.RUnlock()

		isT := needsSanitize(dom)
		switch filter {
		case "sanitized":
			if san == 0 && !isT {
				continue
			}
		case "direct":
			if isT {
				continue
			}
		case "err":
			if errs == 0 {
				continue
			}
		}
		if q != "" && !strings.Contains(dom, q) && !strings.Contains(rip, q) {
			continue
		}

		rows = append(rows, domRow{
			Domain: dom, Hits: hits, Sanitized: san, Errors: errs, Bytes: b,
			ResolvedIP: rip, IsTargeted: isT, LastSeen: time.Unix(ls, 0).Format("15:04:05"),
		})
	}
	domMu.RUnlock()

	sort.Slice(rows, func(i, j int) bool { return rows[i].Hits > rows[j].Hits })
	if len(rows) > 150 {
		rows = rows[:150]
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rows": rows})
}

func apiAddSanitizeKeyword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		Keyword string `json:"keyword"`
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
		setSanitizeKeywords(appCfg.SanitizeKeywords)
	}
	cfgMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "keyword": kw})
}

// ==================== Requests Inspector O(1) ====================
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

	histMu.RLock()
	cnt := histCount
	head := histHead
	histSnapshot := make([]RequestRecord, cnt)
	for i := 0; i < cnt; i++ {
		idx := (head - 1 - i + maxHistoryLogs) % maxHistoryLogs
		histSnapshot[i] = histBuf[idx]
	}
	histMu.RUnlock()

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
			if r.Sanitized {
				return false
			}
		case "LIVE":
			if r.Status != "LIVE" {
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
	for _, r := range histSnapshot {
		if match(r) {
			out = append(out, r)
			if len(out) >= limit {
				return out
			}
		}
	}
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

// ==================== Config, Paste Studio & Remove Dead ====================
func apiGetConfig(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	c := appCfg
	cfgMu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"public_ip":          pubIP,
		"admin_user":         c.AdminUser,
		"proxy_user":         c.ProxyUser,
		"proxy_pass":         c.ProxyPass,
		"start_port":         c.StartPort,
		"default_up_proto":   c.DefaultUpProto,
		"auto_check_min":     c.AutoCheckMin,
		"bandwidth_quota_tb": c.BandwidthQuotaTB,
		"sanitize_keywords":  strings.Join(c.SanitizeKeywords, ", "),
		"proxies_raw":        c.ProxiesRaw,
	})
}

func apiSaveProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		ProxiesRaw     string `json:"proxies_raw"`
		DefaultUpProto string `json:"default_up_proto"`
		Dedup          bool   `json:"dedup"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if body.DefaultUpProto != "http" {
		body.DefaultUpProto = "socks5"
	}

	rawToSave := body.ProxiesRaw
	pStats := parseProxiesFlexible(rawToSave, body.DefaultUpProto, body.Dedup)
	if body.Dedup {
		rawToSave = formatProxiesRaw(pStats.Items)
	}

	cfgMu.Lock()
	newCfg := appCfg
	newCfg.ProxiesRaw = rawToSave
	newCfg.DefaultUpProto = body.DefaultUpProto
	appCfg = newCfg
	_ = saveConfigFile(newCfg)
	cfgMu.Unlock()

	cnt, _, err := applyConfigAndReload(newCfg)
	// Tu dong kiem tra song/chet ngay bang IP VPS sau khi luu
	go triggerScan("deep")

	resp := map[string]interface{}{
		"status":       "ok",
		"active_ports": cnt,
		"parsed":       len(pStats.Items),
		"dupes":        pStats.Dupes,
		"invalid":      pStats.Invalid,
		"cleaned_raw":  rawToSave,
	}
	if err != nil {
		resp["warning"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func apiRemoveDeadProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	runnersMu.RLock()
	ports := make([]int, 0, len(runners))
	for p := range runners {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	var keep []Upstream
	removed := 0
	for _, p := range ports {
		pr := runners[p]
		pr.mu.RLock()
		hl := pr.health
		up := pr.upstream
		pr.mu.RUnlock()
		if hl == "dead" {
			removed++
		} else {
			keep = append(keep, up)
		}
	}
	runnersMu.RUnlock()

	cleaned := formatProxiesRaw(keep)
	cfgMu.Lock()
	newCfg := appCfg
	newCfg.ProxiesRaw = cleaned
	appCfg = newCfg
	_ = saveConfigFile(newCfg)
	cfgMu.Unlock()

	cnt, _, _ := applyConfigAndReload(newCfg)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"removed":      removed,
		"active_ports": cnt,
		"cleaned_raw":  cleaned,
	})
}

func apiSaveSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		ProxyUser        string  `json:"proxy_user"`
		ProxyPass        string  `json:"proxy_pass"`
		StartPort        int     `json:"start_port"`
		AutoCheckMin     int     `json:"auto_check_min"`
		BandwidthQuotaTB float64 `json:"bandwidth_quota_tb"`
		SanitizeKeywords string  `json:"sanitize_keywords"`
		NewAdminUser     string  `json:"new_admin_user"`
		NewAdminPass     string  `json:"new_admin_pass"`
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

	var kws []string
	for _, k := range strings.Split(body.SanitizeKeywords, ",") {
		k = strings.TrimSpace(strings.ToLower(k))
		if k != "" {
			kws = append(kws, k)
		}
	}

	cfgMu.Lock()
	newCfg := appCfg
	newCfg.ProxyUser = strings.TrimSpace(body.ProxyUser)
	newCfg.ProxyPass = strings.TrimSpace(body.ProxyPass)
	newCfg.StartPort = body.StartPort
	newCfg.AutoCheckMin = body.AutoCheckMin
	newCfg.BandwidthQuotaTB = body.BandwidthQuotaTB
	newCfg.SanitizeKeywords = kws
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

	cnt, _, err := applyConfigAndReload(newCfg)
	resp := map[string]interface{}{"status": "ok", "active_ports": cnt}
	if err != nil {
		resp["warning"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func apiExportWrapped(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter") // all, alive, hide_dead

	cfgMu.RLock()
	c := appCfg
	cfgMu.RUnlock()

	type exportRow struct {
		port   int
		proto  string
		health string
	}
	runnersMu.RLock()
	rows := make([]exportRow, 0, len(runners))
	for _, pr := range runners {
		pr.mu.RLock()
		hl := pr.health
		proto := pr.upstream.Proto
		pr.mu.RUnlock()

		if filter == "alive" && hl != "alive" {
			continue
		}
		if filter == "hide_dead" && hl == "dead" {
			continue
		}
		rows = append(rows, exportRow{port: pr.Port, proto: proto, health: hl})
	}
	runnersMu.RUnlock()

	sort.Slice(rows, func(i, j int) bool { return rows[i].port < rows[j].port })

	var lines []string
	for _, row := range rows {
		// Dau vao nao -> dau ra dung giao thuc do (1:1)
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
	if json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&c) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "File backup JSON khong hop le!"})
		return
	}
	if c.ProxyUser == "" || c.ProxyPass == "" || c.StartPort < 1024 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Thieu thong tin proxy/port trong file backup!"})
		return
	}

	cfgMu.Lock()
	if c.AdminUser == "" || c.AdminPassHash == "" {
		c.AdminUser = appCfg.AdminUser
		c.AdminSalt = appCfg.AdminSalt
		c.AdminPassHash = appCfg.AdminPassHash
	}
	appCfg = c
	_ = saveConfigFile(c)
	cfgMu.Unlock()

	cnt, _, _ := applyConfigAndReload(c)
	go triggerScan("deep")
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
	mux.HandleFunc("/api/domains", requireAuth(apiDomains))
	mux.HandleFunc("/api/domains/sanitize", requireAuth(apiAddSanitizeKeyword))
	mux.HandleFunc("/api/requests", requireAuth(apiRequests))
	mux.HandleFunc("/api/requests/csv", requireAuth(apiExportCSV))
	mux.HandleFunc("/api/requests/clear", requireAuth(apiClearLogs))
	mux.HandleFunc("/api/config", requireAuth(apiGetConfig))
	mux.HandleFunc("/api/proxies/save", requireAuth(apiSaveProxies))
	mux.HandleFunc("/api/proxies/remove-dead", requireAuth(apiRemoveDeadProxies))
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