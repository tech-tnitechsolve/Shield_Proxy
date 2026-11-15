package main

import (
	_ "embed"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed sanitize_domains.txt
var embeddedRulesRaw string

const rulesRawURL = "https://raw.githubusercontent.com/tech-tnitechsolve/Shield_Proxy/main/sanitize_domains.txt"

var (
	rulesMu        sync.RWMutex
	remoteRules    []string
	rulesETag      string
	rulesLastSync  string
	remoteRulePath string
	rulesClient    = &http.Client{Timeout: 6 * time.Second}
)

func parseRuleLines(raw string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kw := strings.ToLower(line)
		if !seen[kw] {
			seen[kw] = true
			out = append(out, kw)
		}
	}
	return out
}

func rebuildActiveKeywords(userKeywords []string) {
	rulesMu.RLock()
	rem := make([]string, len(remoteRules))
	copy(rem, remoteRules)
	rulesMu.RUnlock()

	merged := make([]string, 0, len(rem)+len(userKeywords)+16)
	seen := make(map[string]bool)

	addList := func(items []string) {
		for _, k := range items {
			k = strings.ToLower(strings.TrimSpace(k))
			if k != "" && !seen[k] {
				seen[k] = true
				merged = append(merged, k)
			}
		}
	}

	addList(parseRuleLines(embeddedRulesRaw))
	addList(rem)
	addList(userKeywords)
	setSanitizeKeywords(merged)
}

func initRules() {
	remoteRulePath = filepath.Join(dataDir, "remote_rules.txt")
	if b, err := os.ReadFile(remoteRulePath); err == nil {
		rulesMu.Lock()
		remoteRules = parseRuleLines(string(b))
		rulesMu.Unlock()
	}
	cfgMu.RLock()
	ukw := appCfg.SanitizeKeywords
	cfgMu.RUnlock()
	rebuildActiveKeywords(ukw)
}

// Dong bo hot-reload vao RAM khong restart proxy (bypassCache = true khi bam nut tren Web)
func syncRulesFromGitHub(bypassCache bool) (int, bool, error) {
	url := rulesRawURL
	if bypassCache {
		url += "?t=" + time.Now().Format("20060102150405")
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("User-Agent", "ProxyShield-RulesSync/3.0")
	if bypassCache {
		req.Header.Set("Cache-Control", "no-cache")
	} else {
		rulesMu.RLock()
		et := rulesETag
		rulesMu.RUnlock()
		if et != "" {
			req.Header.Set("If-None-Match", et)
		}
	}

	resp, err := rulesClient.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		rulesMu.Lock()
		rulesLastSync = time.Now().Format("15:04:05")
		cnt := len(remoteRules)
		rulesMu.Unlock()
		return cnt, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, false, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return 0, false, err
	}
	parsed := parseRuleLines(string(body))
	if len(parsed) == 0 {
		return 0, false, nil
	}

	_ = atomicWriteFile(remoteRulePath, body, 0644)

	rulesMu.Lock()
	remoteRules = parsed
	if et := resp.Header.Get("ETag"); et != "" {
		rulesETag = et
	}
	rulesLastSync = time.Now().Format("15:04:05")
	rulesMu.Unlock()

	cfgMu.RLock()
	ukw := appCfg.SanitizeKeywords
	cfgMu.RUnlock()
	rebuildActiveKeywords(ukw)

	return len(parsed), true, nil
}

func startRulesSyncLoop() {
	_, _, _ = syncRulesFromGitHub(false)
	tk := time.NewTicker(3 * time.Minute)
	for range tk.C {
		_, _, _ = syncRulesFromGitHub(false)
	}
}

func getRulesStatus() (int, string) {
	kwMu.RLock()
	total := len(sanitizeKW)
	kwMu.RUnlock()
	rulesMu.RLock()
	last := rulesLastSync
	rulesMu.RUnlock()
	if last == "" {
		last = "Embedded"
	}
	return total, last
}