package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
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
	TLS     bool   `json:"tls,omitempty"`
}

func (u Upstream) Addr() string {
	return net.JoinHostPort(u.Host, u.PortStr)
}

type PortRunner struct {
	ActiveConns   int64
	UpstreamConns int64
	DialingConns  int64
	TotalReqs     int64
	SanitizedReqs int64
	BlockedReqs   int64
	ErrorReqs     int64
	BytesUp       int64
	BytesDown     int64
	LastOKUnix    int64
	LastErrUnix   int64

	Port             int
	mu               sync.RWMutex
	limitMu          sync.Mutex
	maxUpstreamConns int64
	upstreamSlots    int64
	upstream         Upstream
	group            string
	note             string
	proxyUser        string
	proxyPass        string
	lastErr          string
	health           string // "untested", "alive", "dead"
	latency          int64
	exitIP           string
	ln               net.Listener
	closed           int32
}

func (pr *PortRunner) GetUpstream() Upstream {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.upstream
}

func (pr *PortRunner) GetClientCreds() ([]byte, []byte) {
	pr.mu.RLock()
	u, p := pr.proxyUser, pr.proxyPass
	pr.mu.RUnlock()
	if u != "" && p != "" {
		return []byte(u), []byte(p)
	}
	return getProxyCreds()
}

func (pr *PortRunner) SetMeta(u Upstream, group, note, pUser, pPass string, maxUpstreamConns int64) {
	pr.mu.Lock()
	pr.upstream = u
	pr.group = group
	pr.note = note
	pr.proxyUser = pUser
	pr.proxyPass = pPass
	pr.mu.Unlock()
	pr.limitMu.Lock()
	pr.maxUpstreamConns = maxUpstreamConns
	pr.limitMu.Unlock()
}

func (pr *PortRunner) reserveUpstreamSlot() bool {
	pr.limitMu.Lock()
	defer pr.limitMu.Unlock()
	if pr.maxUpstreamConns > 0 && pr.upstreamSlots >= pr.maxUpstreamConns {
		return false
	}
	pr.upstreamSlots++
	return true
}

func (pr *PortRunner) releaseUpstreamSlot() {
	pr.limitMu.Lock()
	if pr.upstreamSlots > 0 {
		pr.upstreamSlots--
	}
	pr.limitMu.Unlock()
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

type countWriter struct {
	w io.Writer
	n int64
}

func (cw *countWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += int64(n)
	return n, err
}

type countReader struct {
	r io.Reader
	n int64
}

func (cr *countReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.n += int64(n)
	return n, err
}

type trackedConn struct {
	net.Conn
	pr   *PortRunner
	once sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		atomic.AddInt64(&c.pr.UpstreamConns, -1)
		c.pr.releaseUpstreamSlot()
	})
	return err
}

func (c *trackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("upstream connection does not support half-close")
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("upstream connection does not support half-close")
}

var errUpstreamLimit = errors.New("upstream connection limit reached")

func trackUpstreamDial(pr *PortRunner, dial func() (net.Conn, error)) (net.Conn, error) {
	if !pr.reserveUpstreamSlot() {
		return nil, errUpstreamLimit
	}
	atomic.AddInt64(&pr.DialingConns, 1)
	conn, err := dial()
	atomic.AddInt64(&pr.DialingConns, -1)
	if err != nil {
		pr.releaseUpstreamSlot()
		return nil, err
	}
	atomic.AddInt64(&pr.UpstreamConns, 1)
	return &trackedConn{Conn: conn, pr: pr}, nil
}

func writeUpstreamDialError(conn net.Conn, err error) {
	status := "502 Bad Gateway"
	retryAfter := ""
	if errors.Is(err, errUpstreamLimit) {
		status = "503 Service Unavailable"
		retryAfter = "Retry-After: 1\r\n"
	}
	_, _ = io.WriteString(conn, "HTTP/1.1 "+status+"\r\n"+retryAfter+"Connection: close\r\n\r\n")
}

func dialUpstreamTransport(ctx context.Context, up Upstream) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp4", up.Addr())
	if err != nil {
		return nil, fmt.Errorf("upstream TCP connect: %w", err)
	}
	tuneTCP(conn)
	if !up.TLS {
		return conn, nil
	}

	deadline := time.Now().Add(15 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	tlsConn, err := handshakeUpstreamTLS(ctx, conn, up.Host, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return tlsConn, nil
}

func handshakeUpstreamTLS(ctx context.Context, conn net.Conn, host string, baseConfig *tls.Config) (net.Conn, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if baseConfig != nil {
		config = baseConfig.Clone()
		config.ServerName = host
		if config.MinVersion == 0 {
			config.MinVersion = tls.VersionTLS12
		}
	}
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("upstream TLS handshake: %w", err)
	}
	return tlsConn, nil
}

var bufReaderPool = sync.Pool{
	New: func() interface{} { return bufio.NewReaderSize(nil, 16384) },
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
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, optTCPUserTimeout, 45000)
		})
	}
}

func relayTCP(clientConn, upConn net.Conn, clientBuf *bufio.Reader) (int64, int64) {
	var bUp, bDown int64
	done := make(chan error, 2)

	go func() {
		var src io.Reader = clientConn
		if clientBuf != nil {
			src = io.MultiReader(clientBuf, clientConn)
		}
		n, err := io.Copy(upConn, src)
		atomic.StoreInt64(&bUp, n)
		if err == nil {
			if cw, ok := upConn.(interface{ CloseWrite() error }); ok {
				err = cw.CloseWrite()
			} else {
				err = upConn.Close()
			}
		}
		done <- err
	}()

	go func() {
		n, err := io.Copy(clientConn, upConn)
		atomic.StoreInt64(&bDown, n)
		if err == nil {
			if cw, ok := clientConn.(interface{ CloseWrite() error }); ok {
				err = cw.CloseWrite()
			} else {
				err = clientConn.Close()
			}
		}
		done <- err
	}()

	if err := <-done; err != nil {
		_ = clientConn.Close()
		_ = upConn.Close()
	}
	if err := <-done; err != nil {
		_ = clientConn.Close()
		_ = upConn.Close()
	}

	return atomic.LoadInt64(&bUp), atomic.LoadInt64(&bDown)
}

func dialUpstreamCtx(ctx context.Context, up Upstream, targetHost string, targetPort uint16) (net.Conn, error) {
	conn, err := dialUpstreamTransport(ctx, up)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

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
			return nil, fmt.Errorf("upstream HTTP CONNECT write: %w", err)
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("upstream HTTP CONNECT handshake: %w", err)
		}
		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			conn.Close()
			return nil, fmt.Errorf("upstream HTTP CONNECT rejected with status %d", resp.StatusCode)
		}
		_ = conn.SetDeadline(time.Time{})
		return &bufferedConn{Conn: conn, reader: br}, nil
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
		if gResp[0] != 0x05 {
			return nil, fmt.Errorf("upstream SOCKS5 invalid version %d", gResp[0])
		}
		return nil, errors.New("upstream SOCKS5 has no acceptable authentication method")
	}
	switch gResp[1] {
	case 0x00:
	case 0x02:
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
			if err != nil {
				return nil, fmt.Errorf("upstream SOCKS5 authentication response: %w", err)
			}
			return nil, fmt.Errorf("upstream SOCKS5 authentication rejected with code %d", aResp[1])
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("upstream SOCKS5 selected unsupported authentication method %d", gResp[1])
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
		if err != nil {
			return nil, fmt.Errorf("upstream SOCKS5 connect response: %w", err)
		}
		return nil, fmt.Errorf("upstream SOCKS5 destination rejected with reply code %d", repHdr[1])
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func handleClient(clientConn net.Conn, pr *PortRunner) {
	defer clientConn.Close()
	tuneTCP(clientConn)
	_ = clientConn.SetDeadline(time.Now().Add(20 * time.Second))

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

	up := pr.GetUpstream()

	if first[0] == 0x05 {
		localUser, localPass := pr.GetClientCreds()
		handleSOCKS5(clientConn, br, pr, up, clientIP, localUser, localPass)
	} else {
		handleHTTP(clientConn, br, pr, up, clientIP)
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
		pr.SetError("wrong pass: " + clientIP)
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
		_, _ = clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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
		replyCode := byte(0x02)
		if strings.HasPrefix(strings.ToLower(origHost), "ipv6.") {
			replyCode = 0x04
		}
		_, _ = clientConn.Write([]byte{0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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
			_, _ = clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	upConn, err := trackUpstreamDial(pr, func() (net.Conn, error) {
		return dialUpstreamCtx(ctx, up, sentHost, targetPort)
	})
	cancel()
	if err != nil {
		reply := byte(0x05)
		if errors.Is(err, errUpstreamLimit) {
			reply = 0x01
		}
		_, _ = clientConn.Write([]byte{0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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
	bUp, bDown := relayTCP(clientConn, upConn, br)
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

func handleHTTP(clientConn net.Conn, br *bufio.Reader, pr *PortRunner, up Upstream, clientIP string) {
	for {
		_ = clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = clientConn.SetDeadline(time.Now().Add(20 * time.Second))

		localUser, localPass := pr.GetClientCreds()
		if !checkHTTPAuth(req, localUser, localPass) {
			_, _ = clientConn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nConnection: close\r\n\r\n"))
			if req.Header.Get("Proxy-Authorization") != "" {
				pr.SetError("wrong pass: " + clientIP)
			}
			req.Body.Close()
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
			req.Body.Close()
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
			req.Body.Close()
			return
		}

		if blocked, reason := isBlockedRequest(origHost, uint16(portNum)); blocked {
			respMsg := "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
			if strings.HasPrefix(strings.ToLower(origHost), "ipv6.") {
				respMsg = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
			}
			_, _ = clientConn.Write([]byte(respMsg))
			atomic.AddInt64(&pr.BlockedReqs, 1)
			rec := newReqRecord(pr.Port, clientIP, net.JoinHostPort(origHost, portStr), "-", up.Addr(), protoLabel, false)
			finishReq(rec, origHost, "-", 0, 0, "BLK", reason)
			req.Body.Close()
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
				req.Body.Close()
				return
			}
			if isPrivateOrReserved(ipStr) {
				_, _ = clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"))
				atomic.AddInt64(&pr.BlockedReqs, 1)
				req.Body.Close()
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

		if isTunnel {
			req.Body.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			upConn, err := trackUpstreamDial(pr, func() (net.Conn, error) {
				return dialUpstreamCtx(ctx, up, sentHost, uint16(portNum))
			})
			cancel()
			if err != nil {
				writeUpstreamDialError(clientConn, err)
				pr.SetError(err.Error())
				finishReq(rec, origHost, sentHost, 0, 0, "ERR", err.Error())
				return
			}
			defer upConn.Close()

			if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				finishReq(rec, origHost, sentHost, 0, 0, "ERR", "client write fail")
				return
			}
			_ = clientConn.SetDeadline(time.Time{})
			bUp, bDown := relayTCP(clientConn, upConn, br)
			atomic.AddInt64(&pr.BytesUp, bUp)
			atomic.AddInt64(&pr.BytesDown, bDown)
			atomic.StoreInt64(&pr.LastOKUnix, time.Now().Unix())
			finishReq(rec, origHost, sentHost, bUp, bDown, "OK", "")
			return
		}

		keepAlive := handleHTTPPlain(clientConn, req, pr, up, rec, origHost, sentHost, portStr, uint16(portNum))
		if !keepAlive {
			return
		}
	}
}

func handleHTTPPlain(clientConn net.Conn, req *http.Request, pr *PortRunner, up Upstream, rec *RequestRecord, origHost, sentHost, portStr string, portNum uint16) bool {
	origBody := req.Body
	defer origBody.Close()

	clientKeepAlive := req.ProtoAtLeast(1, 1) &&
		!strings.EqualFold(req.Header.Get("Connection"), "close") &&
		!strings.EqualFold(req.Header.Get("Proxy-Connection"), "close")

	var upConn net.Conn
	var err error
	if up.Proto == "http" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		upConn, err = trackUpstreamDial(pr, func() (net.Conn, error) {
			return dialUpstreamTransport(ctx, up)
		})
		cancel()
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		upConn, err = trackUpstreamDial(pr, func() (net.Conn, error) {
			return dialUpstreamCtx(ctx, up, sentHost, portNum)
		})
		cancel()
	}
	if err != nil {
		writeUpstreamDialError(clientConn, err)
		pr.SetError(err.Error())
		finishReq(rec, origHost, sentHost, 0, 0, "ERR", err.Error())
		return false
	}
	defer upConn.Close()
	_ = upConn.SetDeadline(time.Now().Add(25 * time.Second))

	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	if up.Proto == "http" && (up.User != "" || up.Pass != "") {
		creds := base64.StdEncoding.EncodeToString([]byte(up.User + ":" + up.Pass))
		req.Header.Set("Proxy-Authorization", "Basic "+creds)
	}
	if up.Proto == "http" && req.URL != nil {
		req.URL.Host = net.JoinHostPort(sentHost, portStr)
		if req.URL.Scheme == "" {
			req.URL.Scheme = "http"
		}
	}

	req.Close = true
	cr := &countReader{r: origBody}
	req.Body = io.NopCloser(cr)

	var wErr error
	if up.Proto == "http" {
		wErr = req.WriteProxy(upConn)
	} else {
		wErr = req.Write(upConn)
	}
	if wErr != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
		pr.SetError(wErr.Error())
		finishReq(rec, origHost, sentHost, cr.n, 0, "ERR", wErr.Error())
		return false
	}

	resp, rErr := http.ReadResponse(bufio.NewReader(upConn), req)
	if rErr != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
		pr.SetError(rErr.Error())
		finishReq(rec, origHost, sentHost, cr.n, 0, "ERR", rErr.Error())
		return false
	}
	defer resp.Body.Close()

	resp.Close = !clientKeepAlive
	if clientKeepAlive {
		resp.Header.Set("Proxy-Connection", "keep-alive")
	}

	_ = clientConn.SetWriteDeadline(time.Now().Add(25 * time.Second))
	cw := &countWriter{w: clientConn}
	if err := resp.Write(cw); err != nil {
		finishReq(rec, origHost, sentHost, cr.n, cw.n, "ERR", "client write fail")
		return false
	}

	atomic.AddInt64(&pr.BytesUp, cr.n)
	atomic.AddInt64(&pr.BytesDown, cw.n)
	atomic.StoreInt64(&pr.LastOKUnix, time.Now().Unix())
	finishReq(rec, origHost, sentHost, cr.n, cw.n, "OK", "")
	return clientKeepAlive
}
