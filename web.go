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

// ==================== Async Background Scanner (Stealth & 1-CPU Safe) ====================
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
	if mode == "quick" {
		probes := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
		targetHost = probes[(pr.Port+int(time.Now().Unix()))%len(probes)]
	} else if mode == "deep" {
		targetHost, targetPort = "api.ipify.org", uint16(80)
	}

	ctxDial, cancel := context.WithTimeout(ctx, 12*time.Second)
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
		workers := 25
		if mode == "quick" {
			workers = 5
		}
		sem := make(chan struct{}, workers)
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
				if mode == "quick" {
					time.Sleep(250 * time.Millisecond)
				}
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

	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
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

// ==================== Paginated Ports API ====================
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
	fallbackU := appCfg.ProxyUser
	fallbackP := appCfg.ProxyPass
	entries := make([]ProxyEntry, len(appCfg.ProxyEntries))
	copy(entries, appCfg.ProxyEntries)
	cfgMu.RUnlock()

	type portItem struct {
		Port          int    `json:"port"`
		Group         string `json:"group"`
		Note          string `json:"note"`
		Enabled       bool   `json:"enabled"`
		ProxyUser     string `json:"proxy_user"`
		ProxyPass     string `json:"proxy_pass"`
		WrappedURL    string `json:"wrapped_url"`
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

		eu, ep := entryCreds(ent, fallbackU, fallbackP)
		item := portItem{
			Port:         ent.Port,
			Group:        grp,
			Note:         ent.Note,
			Enabled:      ent.Enabled,
			ProxyUser:    eu,
			ProxyPass:    ep,
			WrappedURL:   fmt.Sprintf("%s://%s:%s@%s:%d", ent.Upstream.Proto, eu, ep, pubIP, ent.Port),
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
			hay := strings.ToLower(fmt.Sprintf("%d %s %s %s %s %s %s %s", item.Port, item.Upstream, item.ExitIP, item.LastErr, item.Group, item.Note, item.Proto, item.ProxyUser))
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

// ==================== Rules APIs ====================
func apiAddRuleKeyword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		Keyword string `json:"keyword"`
		Mode    string `json:"mode"`
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

// ==================== Preview Check Trung + Smart Proxy Manager ====================
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

func apiPreviewProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var body struct {
		ProxiesRaw     string `json:"proxies_raw"`
		DefaultUpProto string `json:"default_up_proto"`
		Mode           string `json:"mode"`
		Dedup          bool   `json:"dedup"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	cfgMu.RLock()
	existing := make([]ProxyEntry, len(appCfg.ProxyEntries))
	copy(existing, appCfg.ProxyEntries)
	cfgMu.RUnlock()

	prev := previewProxies(body.ProxiesRaw, body.DefaultUpProto, body.Mode, body.Dedup, existing)
	writeJSON(w, http.StatusOK, prev)
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
		Mode           string `json:"mode"`
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

	var addedPorts []int
	var prev PreviewResult

	cfgMu.Lock()
	newCfg := appCfg
	newCfg.DefaultUpProto = body.DefaultUpProto
	prev = previewProxies(body.ProxiesRaw, body.DefaultUpProto, body.Mode, body.Dedup, newCfg.ProxyEntries)

	usedUsers := make(map[string]bool)
	if body.Mode == "replace" {
		newEntries := make([]ProxyEntry, 0, len(prev.ValidNew))
		for i, u := range prev.ValidNew {
			p := newCfg.StartPort + i
			if p > 65535 {
				break
			}
			pu, pp := genUniqueProxyCreds(usedUsers)
			newEntries = append(newEntries, ProxyEntry{
				Port: p, Group: grp, Note: note, Enabled: true, User: pu, Pass: pp, Upstream: u,
			})
			addedPorts = append(addedPorts, p)
		}
		newCfg.ProxyEntries = newEntries
	} else {
		usedPorts := make(map[int]bool, len(newCfg.ProxyEntries))
		maxPort := newCfg.StartPort - 1
		for _, e := range newCfg.ProxyEntries {
			usedPorts[e.Port] = true
			if e.User != "" {
				usedUsers[e.User] = true
			}
			if e.Port > maxPort {
				maxPort = e.Port
			}
		}
		nextPort := maxPort + 1
		for _, u := range prev.ValidNew {
			for usedPorts[nextPort] && nextPort <= 65535 {
				nextPort++
			}
			if nextPort > 65535 {
				break
			}
			usedPorts[nextPort] = true
			pu, pp := genUniqueProxyCreds(usedUsers)
			newCfg.ProxyEntries = append(newCfg.ProxyEntries, ProxyEntry{
				Port: nextPort, Group: grp, Note: note, Enabled: true, User: pu, Pass: pp, Upstream: u,
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
		"added_ports":  addedPorts,
		"dup_batch":    len(prev.DupBatch),
		"dup_existing": len(prev.DupExisting),
		"invalid":      len(prev.InvalidLines),
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
		Action       string `json:"action"`
		UpstreamLine string `json:"upstream_line"`
		Group        string `json:"group"`
		Note         string `json:"note"`
		ProxyUser    string `json:"proxy_user"`
		ProxyPass    string `json:"proxy_pass"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}

	var testPort []int
	found := false

	cfgMu.Lock()
	newCfg := appCfg
	usedUsers := make(map[string]bool, len(newCfg.ProxyEntries))
	for _, e := range newCfg.ProxyEntries {
		if e.User != "" {
			usedUsers[e.User] = true
		}
	}

	outEntries := make([]ProxyEntry, 0, len(newCfg.ProxyEntries))
	for _, e := range newCfg.ProxyEntries {
		if e.Port != body.Port {
			outEntries = append(outEntries, e)
			continue
		}
		found = true
		switch body.Action {
		case "delete":
		case "toggle":
			e.Enabled = !e.Enabled
			if e.Enabled {
				testPort = []int{e.Port}
			}
			outEntries = append(outEntries, e)
		case "regen_auth":
			e.User, e.Pass = genUniqueProxyCreds(usedUsers)
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
			if strings.TrimSpace(body.ProxyUser) != "" && strings.TrimSpace(body.ProxyPass) != "" {
				e.User = strings.TrimSpace(body.ProxyUser)
				e.Pass = strings.TrimSpace(body.ProxyPass)
			}
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
		Action string `json:"action"`
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
	usedUsers := make(map[string]bool, len(newCfg.ProxyEntries))
	for _, e := range newCfg.ProxyEntries {
		if e.User != "" {
			usedUsers[e.User] = true
		}
	}
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
		case "regen_auth":
			if inTarget {
				e.User, e.Pass = genUniqueProxyCreds(usedUsers)
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Username/Password mac dinh khong duoc de trong!"})
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
	protoFilter := r.URL.Query().Get("proto")
	format := r.URL.Query().Get("format")
	tmpl := r.URL.Query().Get("tmpl")
	if format == "" {
		format = "match"
	}

	portsParam := strings.TrimSpace(r.URL.Query().Get("ports"))
	var portWhitelist map[int]bool
	if portsParam != "" {
		portWhitelist = make(map[int]bool)
		for _, ps := range strings.Split(portsParam, ",") {
			if pn, err := strconv.Atoi(strings.TrimSpace(ps)); err == nil && pn > 0 {
				portWhitelist[pn] = true
			}
		}
	}

	cfgMu.RLock()
	fallbackU := appCfg.ProxyUser
	fallbackP := appCfg.ProxyPass
	entries := make([]ProxyEntry, len(appCfg.ProxyEntries))
	copy(entries, appCfg.ProxyEntries)
	cfgMu.RUnlock()

	type exportRow struct {
		Port     int    `json:"port"`
		Group    string `json:"group"`
		Proto    string `json:"proto"`
		User     string `json:"user"`
		Pass     string `json:"pass"`
		IP       string `json:"ip"`
		URL      string `json:"url"`
		Upstream string `json:"upstream"`
		ExitIP   string `json:"exit_ip"`
		Health   string `json:"health"`
	}
	var rows []exportRow
	runnersMu.RLock()
	for _, ent := range entries {
		if !ent.Enabled {
			continue
		}
		if portWhitelist != nil && !portWhitelist[ent.Port] {
			continue
		}
		grp := ent.Group
		if grp == "" {
			grp = "Mac dinh"
		}
		if groupFilter != "" && groupFilter != "ALL" && grp != groupFilter {
			continue
		}
		if protoFilter != "" && protoFilter != "ALL" && ent.Upstream.Proto != protoFilter {
			continue
		}
		hl, eip := "untested", ""
		if pr, ok := runners[ent.Port]; ok {
			pr.mu.RLock()
			hl = pr.health
			eip = pr.exitIP
			pr.mu.RUnlock()
		}
		if filter == "alive" && hl != "alive" {
			continue
		}
		if filter == "hide_dead" && hl == "dead" {
			continue
		}
		eu, ep := entryCreds(ent, fallbackU, fallbackP)
		rows = append(rows, exportRow{
			Port:     ent.Port,
			Group:    grp,
			Proto:    ent.Upstream.Proto,
			User:     eu,
			Pass:     ep,
			IP:       pubIP,
			URL:      fmt.Sprintf("%s://%s:%s@%s:%d", ent.Upstream.Proto, eu, ep, pubIP, ent.Port),
			Upstream: ent.Upstream.Addr(),
			ExitIP:   eip,
			Health:   hl,
		})
	}
	runnersMu.RUnlock()

	sort.Slice(rows, func(i, j int) bool { return rows[i].Port < rows[j].Port })

	if format == "json" {
		if r.URL.Query().Get("dl") == "1" {
			w.Header().Set("Content-Disposition", `attachment; filename="wrapped_proxies.json"`)
		}
		writeJSON(w, http.StatusOK, rows)
		return
	}

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		if r.URL.Query().Get("dl") == "1" {
			w.Header().Set("Content-Disposition", `attachment; filename="wrapped_proxies.csv"`)
		}
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"Port", "Group", "Protocol", "ProxyUser", "ProxyPass", "WrappedURL", "Upstream", "ExitIP", "Health"})
		for _, row := range rows {
			_ = cw.Write([]string{
				strconv.Itoa(row.Port), row.Group, row.Proto, row.User, row.Pass,
				row.URL, row.Upstream, row.ExitIP, row.Health,
			})
		}
		cw.Flush()
		return
	}

	var lines []string
	for _, row := range rows {
		switch format {
		case "force_http":
			lines = append(lines, fmt.Sprintf("http://%s:%s@%s:%d", row.User, row.Pass, row.IP, row.Port))
		case "force_socks5":
			lines = append(lines, fmt.Sprintf("socks5://%s:%s@%s:%d", row.User, row.Pass, row.IP, row.Port))
		case "userpass_ipport":
			lines = append(lines, fmt.Sprintf("%s:%s@%s:%d", row.User, row.Pass, row.IP, row.Port))
		case "ipport_userpass":
			lines = append(lines, fmt.Sprintf("%s:%d:%s:%s", row.IP, row.Port, row.User, row.Pass))
		case "ipport":
			lines = append(lines, fmt.Sprintf("%s:%d", row.IP, row.Port))
		case "custom":
			s := tmpl
			if s == "" {
				s = "{proto}://{user}:{pass}@{ip}:{port}"
			}
			s = strings.ReplaceAll(s, "{proto}", row.Proto)
			s = strings.ReplaceAll(s, "{user}", row.User)
			s = strings.ReplaceAll(s, "{pass}", row.Pass)
			s = strings.ReplaceAll(s, "{ip}", row.IP)
			s = strings.ReplaceAll(s, "{port}", strconv.Itoa(row.Port))
			s = strings.ReplaceAll(s, "{group}", row.Group)
			s = strings.ReplaceAll(s, "{upstream}", row.Upstream)
			s = strings.ReplaceAll(s, "{exit_ip}", row.ExitIP)
			lines = append(lines, s)
		default:
			lines = append(lines, row.URL)
		}
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
		usedU := make(map[string]bool)
		for i, u := range ps.Items {
			pu, pp := genUniqueProxyCreds(usedU)
			c.ProxyEntries = append(c.ProxyEntries, ProxyEntry{
				Port: c.StartPort + i, Group: "Mac dinh", Enabled: true, User: pu, Pass: pp, Upstream: u,
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
	mux.HandleFunc("/api/proxies/preview", requireAuth(apiPreviewProxies))
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