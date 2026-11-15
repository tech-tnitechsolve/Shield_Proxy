package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type dnsEntry struct {
	ips []string
	exp time.Time
}

type dnsCall struct {
	wg  sync.WaitGroup
	ips []string
	err error
}

var (
	kwMu       sync.RWMutex
	sanitizeKW []string

	dnsMu       sync.RWMutex
	dnsCache    = make(map[string]dnsEntry)
	staleCache  = make(map[string][]string)
	inflightMu  sync.Mutex
	inflightMap = make(map[string]*dnsCall)
	rrCounter   uint64

	privateNets []*net.IPNet

	dohClient = &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   2 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        100,
			IdleConnTimeout:     60 * time.Second,
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 2 * time.Second,
		},
	}
)

func init() {
	cidrs := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"0.0.0.0/8",
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			privateNets = append(privateNets, n)
		}
	}
}

func isPrivateOrReserved(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return true // chan IPv6
	}
	for _, n := range privateNets {
		if n.Contains(ip4) {
			return true
		}
	}
	return false
}

func setSanitizeKeywords(kws []string) {
	var clean []string
	for _, k := range kws {
		k = strings.ToLower(strings.TrimSpace(k))
		if k != "" {
			clean = append(clean, k)
		}
	}
	kwMu.Lock()
	sanitizeKW = clean
	kwMu.Unlock()
}

func needsSanitize(host string) bool {
	if net.ParseIP(host) != nil {
		return false
	}
	lower := strings.ToLower(host)
	kwMu.RLock()
	kws := sanitizeKW
	kwMu.RUnlock()
	for _, kw := range kws {
		if kw != "" && strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func pickRoundRobin(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	if len(ips) == 1 {
		return ips[0]
	}
	idx := atomic.AddUint64(&rrCounter, 1) % uint64(len(ips))
	return ips[idx]
}

func resolveDoH(domain string) (string, error) {
	now := time.Now()
	dnsMu.RLock()
	if ent, ok := dnsCache[domain]; ok && now.Before(ent.exp) && len(ent.ips) > 0 {
		dnsMu.RUnlock()
		return pickRoundRobin(ent.ips), nil
	}
	dnsMu.RUnlock()

	inflightMu.Lock()
	if call, ok := inflightMap[domain]; ok {
		inflightMu.Unlock()
		call.wg.Wait()
		if call.err != nil || len(call.ips) == 0 {
			return "", call.err
		}
		return pickRoundRobin(call.ips), nil
	}
	call := &dnsCall{}
	call.wg.Add(1)
	inflightMap[domain] = call
	inflightMu.Unlock()

	ips, err := fetchDoHIPv4List(domain)
	if err == nil && len(ips) > 0 {
		dnsMu.Lock()
		if len(dnsCache) > 10000 {
			for k := range dnsCache {
				delete(dnsCache, k)
				break
			}
		}
		dnsCache[domain] = dnsEntry{ips: ips, exp: time.Now().Add(300 * time.Second)}
		if len(staleCache) > 10000 {
			for k := range staleCache {
				delete(staleCache, k)
				break
			}
		}
		staleCache[domain] = ips
		dnsMu.Unlock()
	} else {
		// Neu DoH tam thoi loi, lay IP cu da cache truoc do (tuyet doi khong ro ri DNS ra ngoai)
		dnsMu.RLock()
		if oldIPs, ok := staleCache[domain]; ok && len(oldIPs) > 0 {
			ips = oldIPs
			err = nil
		}
		dnsMu.RUnlock()
	}

	call.ips = ips
	call.err = err
	call.wg.Done()

	inflightMu.Lock()
	delete(inflightMap, domain)
	inflightMu.Unlock()

	if err != nil || len(ips) == 0 {
		return "", err
	}
	return pickRoundRobin(ips), nil
}

func queryDoHJSON(endpoint string) ([]string, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var parsed struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var out []string
	for _, ans := range parsed.Answer {
		if ans.Type == 1 {
			if ip := net.ParseIP(ans.Data); ip != nil && ip.To4() != nil {
				out = append(out, ip.To4().String())
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no A record")
	}
	return out, nil
}

func fetchDoHIPv4List(domain string) ([]string, error) {
	// 1. Primary: Cloudflare DoH
	if ips, err := queryDoHJSON("https://1.1.1.1/dns-query?name=" + domain + "&type=A"); err == nil {
		return ips, nil
	}
	// 2. Backup: Google DoH
	if ips, err := queryDoHJSON("https://8.8.8.8/resolve?name=" + domain + "&type=A"); err == nil {
		return ips, nil
	}
	return nil, fmt.Errorf("doh resolve failed: %s", domain)
}

func getDNSCacheCount() int {
	dnsMu.RLock()
	n := len(dnsCache)
	dnsMu.RUnlock()
	return n
}