package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Upstream struct {
	Proto   string `json:"proto"` // "socks5" or "http"
	Host    string `json:"host"`
	PortStr string `json:"port"`
	User    string `json:"user,omitempty"`
	Pass    string `json:"pass,omitempty"`
}

func (u Upstream) Addr() string {
	return net.JoinHostPort(u.Host, u.PortStr)
}

type PortRunner struct {
	ActiveConns   int64
	TotalReqs     int64
	SanitizedReqs int64
	BlockedReqs   int64
	ErrorReqs     int64
	BytesUp       int64
	BytesDown     int64
	LastOKUnix    int64
	LastErrUnix   int64

	Port     int
	mu       sync.RWMutex
	upstream Upstream
	group    string
	note     string
	lastErr  string
	health   string // "untested", "alive", "dead"
	latency  int64
	exitIP   string
	ln       net.Listener
	closed   int32
}

func (pr *PortRunner) GetUpstream() Upstream {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.upstream
}

func (pr *PortRunner) SetMeta(u Upstream, group, note string) {
	pr.mu.Lock()
	pr.upstream = u
	pr.group = group
	pr.note = note
	pr.mu.Unlock()
}

func (pr *PortRunner) SetError(msg string) {
	atomic.AddInt64(&pr.ErrorReqs, 1)
	atomic.StoreInt64(&pr.LastErrUnix, time.Now().Unix())
	pr.mu.Lock()
	pr.lastErr = msg
	pr.mu.Unlock()
}

func (pr *PortRunner) SetHealth(status string, latMs int64, exitIP, errMsg string) {
	pr.mu.Lock()
	pr.health = status
	pr.latency = latMs
	if exitIP != "" {
		pr.exitIP = exitIP
	}
	if errMsg != "" {
		pr.lastErr = errMsg
	} else if status == "alive" {
		pr.lastErr = ""
	}
	pr.mu.Unlock()
}

type RequestRecord struct {
	ID         uint64 `json:"id"`
	TimeStr    string `json:"time"`
	StartUnix  int64  `json:"start_unix"`
	Port       int    `json:"port"`
	ClientIP   string `json:"client_ip"`
	OrigTarget string `json:"orig_target"`
	SentTarget string `json:"sent_target"`
	Sanitized  bool   `json:"sanitized"`
	Upstream   string `json:"upstream"`
	Protocol   string `json:"protocol"`
	BytesUp    int64  `json:"bytes_up"`
	BytesDown  int64  `json:"bytes_down"`
	DurationMs int64  `json:"duration_ms"`
	Status     string `json:"status"` // "LIVE", "OK", "ERR", "BLK"
	ErrorMsg   string `json:"error"`
}

var bufReaderPool = sync.Pool{
	New: func() interface{} { return bufio.NewReaderSize(nil, 8192) },
}

func tuneTCP(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(30 * time.Second)

	if raw, err := tc.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			const (
				optTCPKeepIdle    = 4
				optTCPKeepIntvl   = 5
				optTCPKeepCnt     = 6
				optTCPUserTimeout = 18
			)
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, optTCPKeepIdle, 30)
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, optTCPKeepIntvl, 10)
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, optTCPKeepCnt, 3)
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, optTCPUserTimeout, 30000)
		})
	}
}

func relayTCP(clientConn, upConn net.Conn, clientBuf *bufio.Reader, isTunnel bool) (int64, int64) {
	cTCP, ok1 := clientConn.(*net.TCPConn)
	uTCP, ok2 := upConn.(*net.TCPConn)
	if !ok1 || !ok2 {
		return 0, 0
	}

	var bUp, bDown int64
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		var pre int64
		if clientBuf != nil && clientBuf.Buffered() > 0 {
			b, err := clientBuf.Peek(clientBuf.Buffered())
			if err == nil && len(b) > 0 {
				nw, wErr := uTCP.Write(b)
				pre = int64(nw)
				if wErr != nil {
					atomic.StoreInt64(&bUp, pre)
					_ = uTCP.Close()
					_ = cTCP.Close()
					return
				}
				_, _ = clientBuf.Discard(len(b))
			}
		}
		n, _ := io.Copy(uTCP, cTCP)
		atomic.StoreInt64(&bUp, pre+n)
		_ = uTCP.CloseWrite()
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		n, _ := io.Copy(cTCP, uTCP)
		atomic.StoreInt64(&bDown, n)
		_ = cTCP.CloseWrite()
	}()

	<-done
	grace := 5 * time.Second
	if !isTunnel {
		grace = 1500 * time.Millisecond
	}
	_ = cTCP.SetDeadline(time.Now().Add(grace))
	_ = uTCP.SetDeadline(time.Now().Add(grace))
	<-done

	return atomic.LoadInt64(&bUp), atomic.LoadInt64(&bDown)
}

func dialUpstreamCtx(ctx context.Context, up Upstream, targetHost string, targetPort uint16) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp4", up.Addr())
	if err != nil {
		return nil, err
	}
	tuneTCP(conn)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if up.Proto == "http" {
		target := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))
		var sb strings.Builder
		sb.WriteString("CONNECT " + target + " HTTP/1.1\r\n")
		sb.WriteString("Host: " + target + "\r\n")
		if up.User != "" || up.Pass != "" {
			creds := base64.StdEncoding.EncodeToString([]byte(up.User + ":" + up.Pass))
			sb.WriteString("Proxy-Authorization: Basic " + creds + "\r\n")
		}
		sb.WriteString("Proxy-Connection: Keep-Alive\r\n\r\n")

		if _, err := conn.Write([]byte(sb.String())); err != nil {
			conn.Close()
			return nil, err
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil {
			conn.Close()
			return nil, err
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			conn.Close()
			return nil, fmt.Errorf("upstream HTTP %d", resp.StatusCode)
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	}

	var greet []byte
	if up.User != "" || up.Pass != "" {
		greet = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		greet = []byte{0x05, 0x01, 0x00}
	}
	if _, err := conn.Write(greet); err != nil {
		conn.Close()
		return nil, err
	}
	var gResp [2]byte
	if _, err := io.ReadFull(conn, gResp[:]); err != nil {
		conn.Close()
		return nil, err
	}
	if gResp[0] != 0x05 || gResp[1] == 0xff {
		conn.Close()
		return nil, errors.New("upstream SOCKS5 rejected (IP chua whitelist?)")
	}
	if gResp[1] == 0x02 {
		if len(up.User) > 255 || len(up.Pass) > 255 {
			conn.Close()
			return nil, errors.New("upstream credentials too long")
		}
		authPkt := make([]byte, 0, 3+len(up.User)+len(up.Pass))
		authPkt = append(authPkt, 0x01, byte(len(up.User)))
		authPkt = append(authPkt, up.User...)
		authPkt = append(authPkt, byte(len(up.Pass)))
		authPkt = append(authPkt, up.Pass...)
		if _, err := conn.Write(authPkt); err != nil {
			conn.Close()
			return nil, err
		}
		var aResp [2]byte
		if _, err := io.ReadFull(conn, aResp[:]); err != nil || aResp[1] != 0x00 {
			conn.Close()
			return nil, errors.New("upstream SOCKS5 auth failed")
		}
	}

	var req []byte
	if ip := net.ParseIP(targetHost); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			conn.Close()
			return nil, errors.New("ipv6 blocked")
		}
		req = []byte{0x05, 0x01, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], byte(targetPort >> 8), byte(targetPort)}
	} else {
		if len(targetHost) > 255 {
			conn.Close()
			return nil, errors.New("domain too long")
		}
		req = make([]byte, 0, 7+len(targetHost))
		req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(targetHost)))
		req = append(req, targetHost...)
		req = append(req, byte(targetPort>>8), byte(targetPort))
	}

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	var repHdr [4]byte
	if _, err := io.ReadFull(conn, repHdr[:]); err != nil {
		conn.Close()
		return nil, err
	}
	switch repHdr[3] {
	case 0x01:
		var d [6]byte
		_, err = io.ReadFull(conn, d[:])
	case 0x03:
		var l [1]byte
		_, err = io.ReadFull(conn, l[:])
		if err == nil {
			d := make([]byte, int(l[0])+2)
			_, err = io.ReadFull(conn, d)
		}
	case 0x04:
		var d [18]byte
		_, err = io.ReadFull(conn, d[:])
	}
	if err != nil || repHdr[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("upstream SOCKS5 connect error %d", repHdr[1])
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func handleClient(clientConn net.Conn, pr *PortRunner) {
	defer clientConn.Close()
	tuneTCP(clientConn)
	_ = clientConn.SetDeadline(time.Now().Add(12 * time.Second))

	atomic.AddInt64(&pr.ActiveConns, 1)
	defer atomic.AddInt64(&pr.ActiveConns, -1)

	clientIP, _, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
	br := bufReaderPool.Get().(*bufio.Reader)
	br.Reset(clientConn)
	defer func() {
		br.Reset(nil)
		bufReaderPool.Put(br)
	}()

	first, err := br.Peek(1)
	if err != nil || len(first) == 0 {
		return
	}

	localUser, localPass := getProxyCreds()
	up := pr.GetUpstream()

	if first[0] == 0x05 {
		handleSOCKS5(clientConn, br, pr, up, clientIP, localUser, localPass)
	} else {
		handleHTTP(clientConn, br, pr, up, clientIP, localUser, localPass)
	}
}

func handleSOCKS5(clientConn net.Conn, br *bufio.Reader, pr *PortRunner, up Upstream, clientIP string, localUser, localPass []byte) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	hasUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			hasUserPass = true
			break
		}
	}
	if !hasUserPass {
		_, _ = clientConn.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := clientConn.Write([]byte{0x05, 0x02}); err != nil {
		return
	}

	var sub [2]byte
	if _, err := io.ReadFull(br, sub[:]); err != nil || sub[0] != 0x01 {
		return
	}
	uname := make([]byte, sub[1])
	if _, err := io.ReadFull(br, uname); err != nil {
		return
	}
	var plen [1]byte
	if _, err := io.ReadFull(br, plen[:]); err != nil {
		return
	}
	passwd := make([]byte, plen[0])
	if _, err := io.ReadFull(br, passwd); err != nil {
		return
	}

	if subtle.ConstantTimeCompare(uname, localUser) != 1 || subtle.ConstantTimeCompare(passwd, localPass) != 1 {
		_, _ = clientConn.Write([]byte{0x01, 0x01})
		pr.SetError("client wrong password")
		return
	}
	if _, err := clientConn.Write([]byte{0x01, 0x00}); err != nil {
		return
	}

	var reqHdr [4]byte
	if _, err := io.ReadFull(br, reqHdr[:]); err != nil {
		return
	}
	if reqHdr[1] != 0x01 {
		_, _ = clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var origHost string
	switch reqHdr[3] {
	case 0x01:
		var ip4 [4]byte
		if _, err := io.ReadFull(br, ip4[:]); err != nil {
			return
		}
		origHost = net.IP(ip4[:]).String()
	case 0x03:
		var dl [1]byte
		if _, err := io.ReadFull(br, dl[:]); err != nil {
			return
		}
		db := make([]byte, dl[0])
		if _, err := io.ReadFull(br, db); err != nil {
			return
		}
		origHost = string(db)
	default:
		_, _ = clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		atomic.AddInt64(&pr.BlockedReqs, 1)
		rec := newReqRecord(pr.Port, clientIP, "IPv6", "-", up.Addr(), "SOCKS5", false)
		finishReq(rec, "IPv6", "-", 0, 0, "BLK", "IPv6 blocked")
		return
	}

	var portB [2]byte
	if _, err := io.ReadFull(br, portB[:]); err != nil {
		return
	}
	targetPort := uint16(portB[0])<<8 | uint16(portB[1])
	portStr := strconv.Itoa(int(targetPort))

	origHost = strings.TrimSuffix(strings.TrimSpace(origHost), ".")
	if isPrivateOrReserved(origHost) {
		_, _ = clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		atomic.AddInt64(&pr.BlockedReqs, 1)
		rec := newReqRecord(pr.Port, clientIP, net.JoinHostPort(origHost, portStr), "-", up.Addr(), "SOCKS5", false)
		finishReq(rec, origHost, "-", 0, 0, "BLK", "private IP blocked")
		return
	}

	if blocked, reason := isBlockedRequest(origHost, targetPort); blocked {
		_, _ = clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		atomic.AddInt64(&pr.BlockedReqs, 1)
		rec := newReqRecord(pr.Port, clientIP, net.JoinHostPort(origHost, portStr), "-", up.Addr(), "SOCKS5", false)
		finishReq(rec, origHost, "-", 0, 0, "BLK", reason)
		return
	}

	atomic.AddInt64(&pr.TotalReqs, 1)

	sentHost := origHost
	sanitized := false
	if needsSanitize(origHost) {
		ipStr, err := resolveDoH(origHost)
		if err != nil || ipStr == "" {
			_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			atomic.AddInt64(&pr.BlockedReqs, 1)
			rec := newReqRecord(pr.Port, clientIP, net.JoinHostPort(origHost, portStr), "-", up.Addr(), "SOCKS5", false)
			finishReq(rec, origHost, "-", 0, 0, "BLK", "anti-leak: doh failed")
			return
		}
		if isPrivateOrReserved(ipStr) {
			_, _ = clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			atomic.AddInt64(&pr.BlockedReqs, 1)
			return
		}
		sentHost = ipStr
		sanitized = true
		atomic.AddInt64(&pr.SanitizedReqs, 1)
	}

	rec := newReqRecord(
		pr.Port, clientIP,
		net.JoinHostPort(origHost, portStr),
		net.JoinHostPort(sentHost, portStr),
		up.Addr(), "SOCKS5", sanitized,
	)
	addActiveReq(rec)

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	upConn, err := dialUpstreamCtx(ctx, up, sentHost, targetPort)
	cancel()
	if err != nil {
		_, _ = clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		pr.SetError(err.Error())
		finishReq(rec, origHost, sentHost, 0, 0, "ERR", err.Error())
		return
	}
	defer upConn.Close()

	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		finishReq(rec, origHost, sentHost, 0, 0, "ERR", "client write fail")
		return
	}

	_ = clientConn.SetDeadline(time.Time{})
	bUp, bDown := relayTCP(clientConn, upConn, br, true)
	atomic.AddInt64(&pr.BytesUp, bUp)
	atomic.AddInt64(&pr.BytesDown, bDown)
	atomic.StoreInt64(&pr.LastOKUnix, time.Now().Unix())
	finishReq(rec, origHost, sentHost, bUp, bDown, "OK", "")
}

func checkHTTPAuth(req *http.Request, localUser, localPass []byte) bool {
	auth := req.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(parts[0]), localUser) == 1 &&
		subtle.ConstantTimeCompare([]byte(parts[1]), localPass) == 1
}

func handleHTTP(clientConn net.Conn, br *bufio.Reader, pr *PortRunner, up Upstream, clientIP string, localUser, localPass []byte) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	defer req.Body.Close()

	if !checkHTTPAuth(req, localUser, localPass) {
		_, _ = clientConn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nConnection: close\r\n\r\n"))
		if req.Header.Get("Proxy-Authorization") != "" {
			pr.SetError("client wrong password")
		}
		return
	}

	rawHost := req.Host
	if rawHost == "" && req.URL != nil {
		rawHost = req.URL.Host
	}
	origHost, portStr, err := net.SplitHostPort(rawHost)
	if err != nil {
		origHost = rawHost
		if req.Method == http.MethodConnect {
			portStr = "443"
		} else {
			portStr = "80"
		}
	}
	origHost = strings.TrimSuffix(strings.TrimSpace(origHost), ".")
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		_, _ = clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
		return
	}

	protoLabel := "HTTP-CONNECT"
	isTunnel := true
	if req.Method != http.MethodConnect {
		protoLabel = "HTTP-" + req.Method
		isTunnel = false
	}

	if isPrivateOrReserved(origHost) {
		_, _ = clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"))
		atomic.AddInt64(&pr.BlockedReqs, 1)
		rec := newReqRecord(pr.Port, clientIP, net.JoinHostPort(origHost, portStr), "-", up.Addr(), protoLabel, false)
		finishReq(rec, origHost, "-", 0, 0, "BLK", "private/ipv6 blocked")
		return
	}

	if blocked, reason := isBlockedRequest(origHost, uint16(portNum)); blocked {
		_, _ = clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"))
		atomic.AddInt64(&pr.BlockedReqs, 1)
		rec := newReqRecord(pr.Port, clientIP, net.JoinHostPort(origHost, portStr), "-", up.Addr(), protoLabel, false)
		finishReq(rec, origHost, "-", 0, 0, "BLK", reason)
		return
	}

	atomic.AddInt64(&pr.TotalReqs, 1)
	sentHost := origHost
	sanitized := false
	if needsSanitize(origHost) {
		ipStr, err := resolveDoH(origHost)
		if err != nil || ipStr == "" {
			_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
			atomic.AddInt64(&pr.BlockedReqs, 1)
			rec := newReqRecord(pr.Port, clientIP, net.JoinHostPort(origHost, portStr), "-", up.Addr(), protoLabel, false)
			finishReq(rec, origHost, "-", 0, 0, "BLK", "anti-leak: doh failed")
			return
		}
		if isPrivateOrReserved(ipStr) {
			_, _ = clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"))
			atomic.AddInt64(&pr.BlockedReqs, 1)
			return
		}
		sentHost = ipStr
		sanitized = true
		atomic.AddInt64(&pr.SanitizedReqs, 1)
	}

	rec := newReqRecord(
		pr.Port, clientIP,
		net.JoinHostPort(origHost, portStr),
		net.JoinHostPort(sentHost, portStr),
		up.Addr(), protoLabel, sanitized,
	)
	addActiveReq(rec)

	if !isTunnel && up.Proto == "http" {
		upConn, err := net.DialTimeout("tcp4", up.Addr(), 8*time.Second)
		if err != nil {
			_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
			pr.SetError(err.Error())
			finishReq(rec, origHost, sentHost, 0, 0, "ERR", err.Error())
			return
		}
		defer upConn.Close()
		tuneTCP(upConn)

		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Proxy-Connection")
		if up.User != "" || up.Pass != "" {
			creds := base64.StdEncoding.EncodeToString([]byte(up.User + ":" + up.Pass))
			req.Header.Set("Proxy-Authorization", "Basic "+creds)
		}
		if req.URL != nil {
			req.URL.Host = net.JoinHostPort(sentHost, portStr)
			if req.URL.Scheme == "" {
				req.URL.Scheme = "http"
			}
		}
		req.Close = true
		if err := req.WriteProxy(upConn); err != nil {
			pr.SetError(err.Error())
			finishReq(rec, origHost, sentHost, 0, 0, "ERR", err.Error())
			return
		}
		_ = clientConn.SetDeadline(time.Time{})
		bUp, bDown := relayTCP(clientConn, upConn, br, false)
		atomic.AddInt64(&pr.BytesUp, bUp)
		atomic.AddInt64(&pr.BytesDown, bDown)
		atomic.StoreInt64(&pr.LastOKUnix, time.Now().Unix())
		finishReq(rec, origHost, sentHost, bUp, bDown, "OK", "")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	upConn, err := dialUpstreamCtx(ctx, up, sentHost, uint16(portNum))
	cancel()
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
		pr.SetError(err.Error())
		finishReq(rec, origHost, sentHost, 0, 0, "ERR", err.Error())
		return
	}
	defer upConn.Close()

	if isTunnel {
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			finishReq(rec, origHost, sentHost, 0, 0, "ERR", "client write fail")
			return
		}
	} else {
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Proxy-Connection")
		req.Close = true
		if err := req.Write(upConn); err != nil {
			finishReq(rec, origHost, sentHost, 0, 0, "ERR", err.Error())
			return
		}
	}

	_ = clientConn.SetDeadline(time.Time{})
	bUp, bDown := relayTCP(clientConn, upConn, br, isTunnel)
	atomic.AddInt64(&pr.BytesUp, bUp)
	atomic.AddInt64(&pr.BytesDown, bDown)
	atomic.StoreInt64(&pr.LastOKUnix, time.Now().Unix())
	finishReq(rec, origHost, sentHost, bUp, bDown, "OK", "")
}