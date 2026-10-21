package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
}

func (a *recAddon) Request(f *Flow) {
	a.seen.Store(f.Request.Method + " " + f.Request.URL.Path)
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
	rec := &recAddon{}
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
	p.SetTunnelDone(func(f *Flow, u, d int64) { up = u; down = d })

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
