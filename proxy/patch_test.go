package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var crlf = string([]byte{13, 10})
var lf = byte(10)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

type recAddon struct {
	BaseAddon
	seen atomic.Value
	t    *testing.T
}

func (a *recAddon) Request(f *Flow) {
	a.seen.Store(f.Request.Method + " " + f.Request.URL.Path)
}

func (a *recAddon) RequestError(f *Flow, err error) {
	if a.t != nil {
		a.t.Logf("RequestError: %v", err)
	}
}

func startProxy(t *testing.T) (*Proxy, string) {
	t.Helper()
	addr := freeAddr(t)
	p, err := NewProxy(&Options{Addr: addr, SslInsecure: true, CaRootPath: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.Start() }()
	time.Sleep(100 * time.Millisecond)
	return p, addr
}

func connect(t *testing.T, addr, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1%sHost: %s%s%s", target, crlf, target, crlf, crlf)
	br := bufio.NewReader(c)
	line, err := br.ReadString(lf)
	if err != nil {
		t.Fatal(err)
	}
	for {
		l, err := br.ReadString(lf)
		if err != nil {
			t.Fatal(err)
		}
		if l == crlf {
			break
		}
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT failed: %q", line)
	}
	return c, br
}

// The policy hook rejects a CONNECT without ever dialing the target.
func TestPolicyReject(t *testing.T) {
	p, addr := startProxy(t)
	defer p.Close()
	p.SetPolicy(func(res http.ResponseWriter, req *http.Request) bool {
		res.WriteHeader(http.StatusForbidden)
		_, _ = res.Write([]byte("out_of_scope"))
		return false
	})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT 127.0.0.1:1 HTTP/1.1%sHost: 127.0.0.1:1%s%s", crlf, crlf, crlf)
	line, err := bufio.NewReader(c).ReadString(lf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "403") {
		t.Fatalf("want 403, got %q", line)
	}
}

// A plaintext HTTP request sent after CONNECT is served by the L7 path: addons
// see the method and path, and the response is proxied back.
func TestPlainHTTPOverConnect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello-plain")
	}))
	defer target.Close()
	th := strings.TrimPrefix(target.URL, "http://")

	p, addr := startProxy(t)
	defer p.Close()
	p.SetShouldInterceptRule(func(*http.Request) bool { return false })
	rec := &recAddon{t: t}
	p.AddAddon(rec)

	c, br := connect(t, addr, th)
	defer c.Close()
	fmt.Fprintf(c, "GET /plain HTTP/1.1%sHost: %s%sConnection: close%s%s", crlf, th, crlf, crlf, crlf)
	body, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "hello-plain") {
		t.Fatalf("body not proxied, got %q", string(body))
	}
	if got, _ := rec.seen.Load().(string); got != "GET /plain" {
		t.Fatalf("addon did not see the L7 request, got %q", got)
	}
}

// Non-HTTP tunnels are still tunnelled, and the byte counts are reported.
func TestTunnelByteAccounting(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()

	p, addr := startProxy(t)
	defer p.Close()
	p.SetShouldInterceptRule(func(*http.Request) bool { return false })
	var up, down int64
	p.SetTunnelDone(func(f *Flow, u, d int64, _ time.Duration, _ string) { up = u; down = d })

	c, br := connect(t, addr, l.Addr().String())
	fmt.Fprintf(c, "SSH-2.0-protocol-test%s", crlf)
	echoed := make([]byte, 10)
	if _, err := io.ReadFull(br, echoed); err != nil {
		t.Fatalf("echo: %v", err)
	}
	c.Close()
	for i := 0; i < 30 && up == 0; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if up < 10 || down < 10 {
		t.Fatalf("tunnel bytes not accounted: up=%d down=%d", up, down)
	}
}

// CONNECT 后的明文 HTTP 在**默认拦截开启**时也必须进 L7。
// 之前的实现只在 shouldIntercept=false（directTransfer）路径上嗅探；拦截开启时
// 明文被当盲隧道，扫描器/curl -p 的请求既不审查也不记录——2026-10 用真实内网
// 目标复扫时发现（一轮 300 个端口只留 1 条证据）。
func TestPlainHTTPWithInterceptEnabled(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello-intercept")
	}))
	defer target.Close()
	th := strings.TrimPrefix(target.URL, "http://")

	p, addr := startProxy(t)
	defer p.Close()
	// 不调用 SetShouldInterceptRule：默认拦截（生产配置）
	rec := &recAddon{t: t}
	p.AddAddon(rec)

	c, br := connect(t, addr, th)
	defer c.Close()
	fmt.Fprintf(c, "GET /plain HTTP/1.1%sHost: %s%sConnection: close%s%s", crlf, th, crlf, crlf, crlf)
	body, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "hello-intercept") {
		t.Fatalf("body not proxied: %q", string(body))
	}
	if got, _ := rec.seen.Load().(string); got != "GET /plain" {
		t.Fatalf("addon did not see the L7 request (plaintext tunneled?): %q", got)
	}
}

// 服务端先发言的协议（SSH/SMTP/MySQL banner）：客户端连上不发任何字节。
// 拦截路径必须在一个短窗口后判定为"非 TLS 隧道"并立即拨上游，否则只监听不发包的
// NULL 探针永远看不到 banner——端口扫描会把 22 判成未知（2026-10 实测发现）。
func TestServerFirstProtocolTunnel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// banner 立刻发出，然后等客户端
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			go func() {
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				c.Close()
			}()
		}
	}()

	p, addr := startProxy(t)
	defer p.Close()
	// 默认拦截（生产配置）——这正是出问题的路径
	c, br := connect(t, addr, ln.Addr().String())
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := br.ReadString(lf)
	if err != nil {
		t.Fatalf("server-first banner not delivered: %v", err)
	}
	if !strings.HasPrefix(line, "SSH-2.0-OpenSSH") {
		t.Fatalf("banner = %q", line)
	}
}

// 隧道字节预算：超过上限必须断连并上报 terminated=budget_bytes，不能静默半开。
func TestTunnelByteBudget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// 服务端先发言，且一次写满 4KB，必然超过 256 字节预算。
		_, _ = c.Write(make([]byte, 4096))
		time.Sleep(2 * time.Second)
	}()

	addr := freeAddr(t)
	p, err := NewProxy(&Options{Addr: addr, SslInsecure: true, CaRootPath: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu     sync.Mutex
		up     int64
		down   int64
		reason string
	)
	p.SetTunnelBudget(func(*Flow) (int64, time.Duration) { return 256, 0 })
	p.SetTunnelDone(func(_ *Flow, u, d int64, _ time.Duration, term string) {
		mu.Lock()
		up, down, reason = u, d, term
		mu.Unlock()
	})
	go func() { _ = p.Start() }()
	time.Sleep(100 * time.Millisecond)

	c, br := connect(t, addr, ln.Addr().String())
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	_, _ = br.Read(buf)

	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		r := reason
		mu.Unlock()
		if r != "" || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if reason != "budget_bytes" {
		t.Fatalf("terminated = %q, want budget_bytes", reason)
	}
	if up+down > 256+4096 {
		t.Fatalf("bytes %d+%d far beyond the 256-byte budget", up, down)
	}
}
