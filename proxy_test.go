package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestDialHTTPConnectPreservesEarlyTunnelData(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	releaseServer := make(chan struct{})
	serverDone := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseServer) })
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\nready"))
		<-releaseServer
	}()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialUpstreamCtx(ctx, Upstream{
		Proto:   "http",
		Host:    "127.0.0.1",
		PortStr: port,
	}, "example.com", 443)
	if err != nil {
		t.Fatalf("CONNECT handshake failed: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("ready"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading bytes sent with CONNECT response: %v", err)
	}
	if string(got) != "ready" {
		t.Fatalf("got %q, want %q", got, "ready")
	}

	releaseOnce.Do(func() { close(releaseServer) })
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("upstream test server did not stop")
	}
}

func TestHTTPSUpstreamUsesTLSAndPreservesScheme(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	up, ok := parseSingleUpstream("https://localhost:"+port, "http")
	if !ok {
		t.Fatal("HTTPS upstream was rejected")
	}
	if up.Proto != "http" || !up.TLS {
		t.Fatalf("parsed upstream = %#v, want HTTP over TLS", up)
	}
	if got, want := formatOneUpstream(up), "https://localhost:"+port; got != want {
		t.Fatalf("formatted upstream = %q, want %q", got, want)
	}

	rawConn, err := net.DialTimeout("tcp4", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()
	config := server.Client().Transport.(*http.Transport).TLSClientConfig
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := handshakeUpstreamTLS(ctx, rawConn, up.Host, config)
	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("HTTPS proxy response body = %q, want %q", body, "ok")
	}
}

func TestParseHTTPUpstreamWithCredentials(t *testing.T) {
	const line = "http://test-user:test-pass@127.0.0.1:8080"
	up, ok := parseSingleUpstream(line, "socks5")
	if !ok {
		t.Fatal("HTTP upstream with credentials was rejected")
	}
	if up.Proto != "http" || up.TLS || up.User != "test-user" || up.Pass != "test-pass" {
		t.Fatalf("parsed upstream = %#v, want HTTP with parsed credentials", up)
	}
	if got := formatOneUpstream(up); got != line {
		t.Fatalf("formatted upstream = %q, want %q", got, line)
	}
}

func TestRelayTCPPreservesDelayedHalfCloseResponse(t *testing.T) {
	clientApp, clientRelay := tcpPair(t)
	upstreamRelay, upstreamApp := tcpPair(t)
	defer clientApp.Close()
	defer upstreamApp.Close()

	relayDone := make(chan struct{})
	go func() {
		relayTCP(clientRelay, upstreamRelay, nil)
		close(relayDone)
	}()

	if _, err := clientApp.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := clientApp.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	request, err := io.ReadAll(upstreamApp)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "request" {
		t.Fatalf("got request %q, want %q", request, "request")
	}

	time.Sleep(5200 * time.Millisecond)
	if _, err := upstreamApp.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := upstreamApp.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if err := clientApp.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(clientApp)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response" {
		t.Fatalf("got response %q, want %q", response, "response")
	}

	select {
	case <-relayDone:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not finish after both half-closes")
	}
}

func TestTrackUpstreamDialCountsConnections(t *testing.T) {
	pr := &PortRunner{}
	pr.SetMeta(Upstream{}, "", "", "", "", 1)
	var peer net.Conn
	defer func() {
		if peer != nil {
			_ = peer.Close()
		}
	}()
	conn, err := trackUpstreamDial(pr, func() (net.Conn, error) {
		client, server := net.Pipe()
		peer = server
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := pr.UpstreamConns; got != 1 {
		t.Fatalf("active upstream connections = %d, want 1", got)
	}
	if got := pr.DialingConns; got != 0 {
		t.Fatalf("dialing upstream connections = %d, want 0", got)
	}
	dialCalled := false
	if _, err := trackUpstreamDial(pr, func() (net.Conn, error) {
		dialCalled = true
		return nil, nil
	}); !errors.Is(err, errUpstreamLimit) {
		t.Fatalf("second dial error = %v, want upstream limit error", err)
	}
	if dialCalled {
		t.Fatal("dial function ran while the upstream limit was full")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	if got := pr.UpstreamConns; got != 0 {
		t.Fatalf("active upstream connections after close = %d, want 0", got)
	}
	replacement, err := trackUpstreamDial(pr, func() (net.Conn, error) {
		client, server := net.Pipe()
		peer = server
		return client, nil
	})
	if err != nil {
		t.Fatalf("dial after releasing the limit: %v", err)
	}
	_ = replacement.Close()
}

func TestTrackUpstreamDialReleasesLimitAfterFailure(t *testing.T) {
	pr := &PortRunner{}
	pr.SetMeta(Upstream{}, "", "", "", "", 1)
	dialErr := errors.New("dial failed")
	if _, err := trackUpstreamDial(pr, func() (net.Conn, error) {
		return nil, dialErr
	}); !errors.Is(err, dialErr) {
		t.Fatalf("dial error = %v, want %v", err, dialErr)
	}
	if got := pr.DialingConns; got != 0 {
		t.Fatalf("dialing upstream connections after failure = %d, want 0", got)
	}

	conn, err := trackUpstreamDial(pr, func() (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, server)
			_ = server.Close()
		}()
		return client, nil
	})
	if err != nil {
		t.Fatalf("dial after failed attempt: %v", err)
	}
	_ = conn.Close()
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}

	defer listener.Close()

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server := <-accepted:
		return client, server
	case err := <-acceptErr:
		client.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		client.Close()
		t.Fatal("timed out accepting TCP connection")
	}
	return nil, nil
}
