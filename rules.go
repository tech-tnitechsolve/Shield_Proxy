package main

import (
	_ "embed"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed sanitize_domains.txt
var embeddedSanitizeRaw string

//go:embed block_domains.txt
var embeddedBlockRaw string

const (
	sanitizeRawURL = "https://raw.githubusercontent.com/tech-tnitechsolve/Shield_Proxy/main/sanitize_domains.txt"
	blockRawURL    = "https://raw.githubusercontent.com/tech-tnitechsolve/Shield_Proxy/main/block_domains.txt"
)

var (
	rulesMu        sync.RWMutex
	remoteSanitize []string
	remoteBlock    []string
	sanitizeETag   string
	blockETag      string
	rulesLastSync  string

	remoteSanPath string
	remoteBlkPath string

	blockMu             sync.RWMutex
	blockKW             []string
	blockDangerousPorts int32 = 1 // 1 = bat chan SMTP/SSH/RDP/SMB/DB

	rulesClient = &http.Client{Timeout: 6 * time.Second}
)

var dangerousPortMap = map[uint16]string{
	21: "FTP", 22: "SSH", 23: "Telnet",
	25: "SMTP-Spam", 465: "SMTPS", 587: "SMTP-Sub", 110: "POP3", 143: "IMAP", 993: "IMAPS", 995: "POP3S",
	135: "RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "SMB", 445: "SMB-Ransomware",
	1433: "MSSQL", 1521: "OracleDB", 3306: "MySQL", 3389: "RDP-Brute", 5432: "Postgres", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
}

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

func mergeUniqueLists(lists ...[]string) []string {
	var merged []string
	seen := make(map[string]bool)
	for _, list := range lists {
		for _, item := range list {
			k := strings.ToLower(strings.TrimSpace(item))
			if k != "" && !seen[k] {
				seen[k] = true
				merged = append(merged, k)
			}
		}
	}
	return merged
}

func rebuildAllRules(userSanitize, userBlock []string, blockPorts bool) {
	if blockPorts {
		atomic.StoreInt32(&blockDangerousPorts, 1)
	} else {
		atomic.StoreInt32(&blockDangerousPorts, 0)
	}

	rulesMu.RLock()
	remS := remoteSanitize
	remB := remoteBlock
	rulesMu.RUnlock()

	mergedSan := mergeUniqueLists(parseRuleLines(embeddedSanitizeRaw), remS, userSanitize)
	setSanitizeKeywords(mergedSan)

	mergedBlk := mergeUniqueLists(parseRuleLines(embeddedBlockRaw), remB, userBlock)
	blockMu.Lock()
	blockKW = mergedBlk
	blockMu.Unlock()
}

func initRules() {
	remoteSanPath = filepath.Join(dataDir, "remote_sanitize.txt")
	remoteBlkPath = filepath.Join(dataDir, "remote_block.txt")

	if b, err := os.ReadFile(remoteSanPath); err == nil {
		rulesMu.Lock()
		remoteSanitize = parseRuleLines(string(b))
		rulesMu.Unlock()
	}
	if b, err := os.ReadFile(remoteBlkPath); err == nil {
		rulesMu.Lock()
		remoteBlock = parseRuleLines(string(b))
		rulesMu.Unlock()
	}

	cfgMu.RLock()
	us := appCfg.SanitizeKeywords
	ub := appCfg.BlockKeywords
	bp := appCfg.BlockDangerousPorts
	cfgMu.RUnlock()
	rebuildAllRules(us, ub, bp)
}

func isBlockedRequest(host string, port uint16) (bool, string) {
	if atomic.LoadInt32(&blockDangerousPorts) == 1 {
		if svc, bad := dangerousPortMap[port]; bad {
			return true, "port blocked (" + svc + ":" + strconv.Itoa(int(port)) + ")"
		}
	}
	lower := strings.ToLower(strings.TrimSpace(host))
	if strings.HasPrefix(lower, "ipv6.") {
		return true, "ipv6 probe blocked"
	}
	blockMu.RLock()
	kws := blockKW
	blockMu.RUnlock()
	for _, kw := range kws {
		if kw == "" {
			continue
		}
		if strings.HasPrefix(kw, ".") {
			if strings.HasSuffix(lower, kw) {
				return true, "abuse rule (" + kw + ")"
			}
		} else if strings.Contains(lower, kw) {
			return true, "abuse rule (" + kw + ")"
		}
	}
	return false, ""
}

func fetchRuleFile(url, curETag string, bypassCache bool) ([]byte, string, bool, error) {
	u := url
	if bypassCache {
		u += "?t=" + time.Now().Format("20060102150405")
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, curETag, false, err
	}
	req.Header.Set("User-Agent", "ProxyShield-RulesSync/3.5")
	if bypassCache {
		req.Header.Set("Cache-Control", "no-cache")
	} else if curETag != "" {
		req.Header.Set("If-None-Match", curETag)
	}
	resp, err := rulesClient.Do(req)
	if err != nil {
		return nil, curETag, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, curETag, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, curETag, false, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil || len(parseRuleLines(string(body))) == 0 {
		return nil, curETag, false, err
	}
	newETag := resp.Header.Get("ETag")
	if newETag == "" {
		newETag = curETag
	}
	return body, newETag, true, nil
}

func syncRulesFromGitHub(bypassCache bool) (int, int, error) {
	rulesMu.RLock()
	sTag, bTag := sanitizeETag, blockETag
	rulesMu.RUnlock()

	sBody, newSTag, sChanged, err1 := fetchRuleFile(sanitizeRawURL, sTag, bypassCache)
	bBody, newBTag, bChanged, err2 := fetchRuleFile(blockRawURL, bTag, bypassCache)

	if err1 != nil && err2 != nil {
		return 0, 0, err1
	}

	rulesMu.Lock()
	if sChanged && len(sBody) > 0 {
		remoteSanitize = parseRuleLines(string(sBody))
		sanitizeETag = newSTag
		_ = atomicWriteFile(remoteSanPath, sBody, 0644)
	}
	if bChanged && len(bBody) > 0 {
		remoteBlock = parseRuleLines(string(bBody))
		blockETag = newBTag
		_ = atomicWriteFile(remoteBlkPath, bBody, 0644)
	}
	rulesLastSync = time.Now().Format("15:04:05")
	rulesMu.Unlock()

	cfgMu.RLock()
	us := appCfg.SanitizeKeywords
	ub := appCfg.BlockKeywords
	bp := appCfg.BlockDangerousPorts
	cfgMu.RUnlock()
	rebuildAllRules(us, ub, bp)

	sanTotal, blkTotal, _ := getRulesStatus()
	return sanTotal, blkTotal, nil
}

func startRulesSyncLoop() {
	_, _, _ = syncRulesFromGitHub(false)
	tk := time.NewTicker(3 * time.Minute)
	for range tk.C {
		_, _, _ = syncRulesFromGitHub(false)
	}
}

func getRulesStatus() (int, int, string) {
	kwMu.RLock()
	sanTotal := len(sanitizeKW)
	kwMu.RUnlock()
	blockMu.RLock()
	blkTotal := len(blockKW)
	blockMu.RUnlock()
	rulesMu.RLock()
	last := rulesLastSync
	rulesMu.RUnlock()
	if last == "" {
		last = "Embedded"
	}
	return sanTotal, blkTotal, last
}