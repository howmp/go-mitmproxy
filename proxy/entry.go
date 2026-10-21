package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	log "github.com/sirupsen/logrus"
)

// wrap tcpListener for remote client
type wrapListener struct {
	net.Listener
	proxy *Proxy
}

func (l *wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	proxy := l.proxy
	wc := newWrapClientConn(c, proxy)
	connCtx := newConnContext(wc, proxy)
	wc.connCtx = connCtx

	for _, addon := range proxy.Addons {
		addon.ClientConnected(connCtx.ClientConn)
	}

	return wc, nil
}

// wrap tcpConn for remote client
type wrapClientConn struct {
	net.Conn
	r       *bufio.Reader
	proxy   *Proxy
	connCtx *ConnContext

	closeMu   sync.Mutex
	closed    bool
	closeErr  error
	closeChan chan struct{}
}

func newWrapClientConn(c net.Conn, proxy *Proxy) *wrapClientConn {
	return &wrapClientConn{
		Conn:      c,
		r:         bufio.NewReader(c),
		proxy:     proxy,
		closeChan: make(chan struct{}),
	}
}

func (c *wrapClientConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func (c *wrapClientConn) PeekBuffered() ([]byte, error) {
	return c.r.Peek(c.r.Buffered())
}

// peekHTTP reports whether the tunnel's first bytes look like an HTTP/1.x
// request line. It never consumes bytes; a client that stays silent past the
// deadline is treated as a non-HTTP tunnel.
func (c *wrapClientConn) peekHTTP() bool {
	_ = c.Conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	defer func() { _ = c.Conn.SetReadDeadline(time.Time{}) }()
	buf, err := c.r.Peek(8)
	if err != nil {
		// bufio 会把这次读错误记下来，后续 Read 会一直返回它（粘滞）。若不重置，
		// 后面的 transfer 会立刻"读失败"并关闭连接——服务端先发言的协议因此永远
		// 收不到 banner（真实目标 22 端口复扫时发现）。
		c.resetReader()
		return false
	}
	i := strings.IndexByte(string(buf), ' ')
	if i <= 0 {
		return false
	}
	switch string(buf[:i]) {
	case "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "TRACE":
		return true
	}
	return false
}

func (c *wrapClientConn) Read(data []byte) (int, error) {
	return c.r.Read(data)
}

func (c *wrapClientConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	log.Debugln("in wrapClientConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()
	close(c.closeChan)

	for _, addon := range c.proxy.Addons {
		addon.ClientDisconnected(c.connCtx.ClientConn)
	}

	if c.connCtx.ServerConn != nil && c.connCtx.ServerConn.Conn != nil {
		c.connCtx.ServerConn.Conn.Close()
	}

	return c.closeErr
}

// wrap tcpConn for remote server
type wrapServerConn struct {
	net.Conn
	proxy   *Proxy
	connCtx *ConnContext

	closeMu  sync.Mutex
	closed   bool
	closeErr error
}

func (c *wrapServerConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	log.Debugln("in wrapServerConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()

	for _, addon := range c.proxy.Addons {
		addon.ServerDisconnected(c.connCtx)
	}

	if !c.connCtx.ClientConn.Tls {
		c.connCtx.ClientConn.Conn.(*wrapClientConn).Conn.(*net.TCPConn).CloseRead()
	} else {
		// if keep-alive connection close
		if !c.connCtx.closeAfterResponse {
			c.connCtx.ClientConn.Conn.Close()
		}
	}

	return c.closeErr
}

type entry struct {
	proxy  *Proxy
	server *http.Server
}

func newEntry(proxy *Proxy) *entry {
	e := &entry{proxy: proxy}
	e.server = &http.Server{
		Addr:    proxy.Opts.Addr,
		Handler: e,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*wrapClientConn).connCtx)
		},
	}
	return e
}

func (e *entry) start() error {
	addr := e.server.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Infof("Proxy start listen at %v\n", e.server.Addr)
	pln := &wrapListener{
		Listener: ln,
		proxy:    e.proxy,
	}
	return e.server.Serve(pln)
}

func (e *entry) close() error {
	return e.server.Close()
}

func (e *entry) shutdown(ctx context.Context) error {
	return e.server.Shutdown(ctx)
}

func (e *entry) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.ServeHTTP",
		"host": req.Host,
	})
	// Add entry proxy authentication
	if e.proxy.authProxy != nil {
		b, err := e.proxy.authProxy(res, req)
		if !b {
			log.Errorf("Proxy authentication failed: %s", err.Error())
			httpError(res, "", http.StatusProxyAuthRequired)
			return
		}
	}
	// Pre-connect policy. The hook owns the response when it returns false, so
	// a rejected request never reaches the target.
	if e.proxy.policy != nil && !e.proxy.policy(res, req) {
		log.Errorf("Proxy policy rejected %s %s", req.Method, req.Host)
		return
	}
	// proxy via connect tunnel
	if req.Method == "CONNECT" {
		e.handleConnect(res, req)
		return
	}

	if !req.URL.IsAbs() || req.URL.Host == "" {
		res = helper.NewResponseCheck(res)
		for _, addon := range proxy.Addons {
			addon.AccessProxyServer(req, res)
		}
		if res, ok := res.(*helper.ResponseCheck); ok {
			if !res.Wrote {
				res.WriteHeader(400)
				io.WriteString(res, "此为代理服务器，不能直接发起请求")
			}
		}
		return
	}

	// http proxy
	proxy.attacker.initHttpDialFn(req)
	proxy.attacker.attack(res, req)
}

func (e *entry) handleConnect(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.handleConnect",
		"host": req.Host,
	})

	shouldIntercept := proxy.shouldIntercept == nil || proxy.shouldIntercept(req)
	f := newFlow()
	f.Request = newRequest(req)
	f.ConnContext = req.Context().Value(connContextKey).(*ConnContext)
	f.ConnContext.Intercept = shouldIntercept
	defer f.finish()

	// trigger addon event Requestheaders
	for _, addon := range proxy.Addons {
		addon.Requestheaders(f)
	}

	if !shouldIntercept {
		log.Debugf("begin transpond %v", req.Host)
		e.directTransfer(res, req, f)
		return
	}

	if f.ConnContext.ClientConn.UpstreamCert {
		e.httpsDialFirstAttack(res, req, f)
		return
	}

	log.Debugf("begin intercept %v", req.Host)
	e.httpsDialLazyAttack(res, req, f)
}

func (e *entry) establishConnection(res http.ResponseWriter, f *Flow) (net.Conn, error) {
	cconn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		for _, addon := range e.proxy.Addons {
			addon.HTTPConnectError(f, err)
		}
		res.WriteHeader(502)
		return nil, err
	}
	_, err = io.WriteString(cconn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		cconn.Close()
		for _, addon := range e.proxy.Addons {
			addon.HTTPConnectError(f, err)
		}
		return nil, err
	}

	f.Response = &Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	// trigger addon event Responseheaders
	for _, addon := range e.proxy.Addons {
		addon.Responseheaders(f)
	}

	return cconn, nil
}

// errPeekTimeout marks "the client sent nothing within the sniff window". That is
// the normal shape of a server-first protocol (SSH/SMTP/MySQL banner, FTP, ...): it
// is not TLS (TLS always starts with a client ClientHello) and it must not be held
// back waiting for client bytes, or a probe that only listens never sees the banner.
var errPeekTimeout = errors.New("peek timeout")

// sniffWindow 是"客户端是否会先说话"的判定窗口。TLS 的 ClientHello 在连接建立后
// 立即发出，几百毫秒足够；给太短会误判慢客户端，太长会让 server-first 协议白等。
const sniffWindow = 300 * time.Millisecond

// resetReader rebuilds the buffered reader after a failed Peek. bufio.Reader caches
// the error from the failed read and returns it on every later call, so a timed-out
// sniff would poison the tunnel. Bytes already buffered are preserved.
func (c *wrapClientConn) resetReader() {
	n := c.r.Buffered()
	var prefix []byte
	if n > 0 {
		prefix, _ = c.r.Peek(n)
	}
	var r io.Reader = c.Conn
	if len(prefix) > 0 {
		r = io.MultiReader(bytes.NewReader(prefix), c.Conn)
	}
	c.r = bufio.NewReader(r)
}

// peekWithin peeks n bytes, waiting at most d for the client to send them.
func peekWithin(wc *wrapClientConn, n int, d time.Duration) ([]byte, error) {
	_ = wc.Conn.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = wc.Conn.SetReadDeadline(time.Time{}) }()
	b, err := wc.Peek(n)
	if err != nil {
		wc.resetReader()
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, errPeekTimeout
		}
		return nil, err
	}
	return b, nil
}

// tunnelLimits asks the app for this tunnel's budgets (0 = unlimited).
func (e *entry) tunnelLimits(f *Flow) (int64, time.Duration) {
	if e.proxy.tunnelBudget == nil {
		return 0, 0
	}
	return e.proxy.tunnelBudget(f)
}

// runTunnel transfers the tunnel with the app's budgets and reports stats.
func (e *entry) runTunnel(log *log.Entry, server, client io.ReadWriteCloser, f *Flow) transferStats {
	maxBytes, maxDur := e.tunnelLimits(f)
	st := transfer(log, server, client, maxBytes, maxDur)
	if e.proxy.tunnelDone != nil {
		e.proxy.tunnelDone(f, st.Up, st.Down, st.Duration, st.Terminated)
	}
	return st
}

func (e *entry) directTransfer(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.directTransfer",
		"host": req.Host,
	})

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		return
	}

	// After 200 Connection Established the client starts sending. If it speaks
	// plaintext HTTP (curl -p, proxychains-ng) the stream belongs in the L7 path,
	// not in a blind tunnel; serve it through the same http.Server as MITM'd
	// traffic so addons see method/path/headers/body.
	if wc, ok := cconn.(*wrapClientConn); ok && wc.peekHTTP() {
		f.ConnContext.ClientConn.Tls = false
		proxy.attacker.initHttpDialFn(req)
		proxy.attacker.servePlain(cconn, f.ConnContext) // takes ownership of cconn
		return
	}

	conn, err := proxy.getUpstreamConn(req.Context(), req)
	if err != nil {
		for _, addon := range proxy.Addons {
			addon.HTTPConnectError(f, err)
		}
		// already hijacked: res is unusable, answer on the raw conn
		_, _ = io.WriteString(cconn, "HTTP/1.1 502 Bad Gateway"+string([]byte{13, 10, 13, 10}))
		cconn.Close()
		return
	}
	defer conn.Close()
	defer cconn.Close()

	e.runTunnel(log, conn, cconn, f)
}

func (e *entry) httpsDialFirstAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.httpsDialFirstAttack",
		"host": req.Host,
	})

	conn, err := proxy.attacker.httpsDial(req.Context(), req)
	if err != nil {
		for _, addon := range proxy.Addons {
			addon.HTTPConnectError(f, err)
		}
		res.WriteHeader(502)
		return
	}

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		conn.Close()
		return
	}

	wcFA, _ := cconn.(*wrapClientConn)
	peek, err := peekWithin(wcFA, 3, sniffWindow)
	if err == errPeekTimeout {
		// 服务端先发言（SSH/SMTP/...）：上游已拨好，直接透传。
		defer conn.Close()
		defer cconn.Close()
		e.runTunnel(log, conn, cconn, f)
		return
	}
	if err != nil {
		cconn.Close()
		conn.Close()
		log.Error(err)
		return
	}

	if helper.IsTls(peek) {
		f.ConnContext.ClientConn.Tls = true
		proxy.attacker.httpsTlsDial(req.Context(), cconn, conn)
		return
	}

	wsPeek, err := cconn.(*wrapClientConn).PeekBuffered()
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		cconn.Close()
		conn.Close()
		log.Error(err)
		return
	}

	if helper.IsWebSocket(wsPeek) {
		err = proxy.webSocketHandler.handle(conn, cconn, f)
		if err != nil {
			log.Errorf("WebSocket handle error: %v", err)
			cconn.Close()
			conn.Close()
		}
		return
	}

	// Plaintext HTTP over CONNECT (curl -p, proxychains, a plain HTTP probe): serve it
	// through the same http.Server as MITM'd traffic so addons see method/path/body.
	// The upstream conn dialed for the TLS attempt must be dropped first, otherwise
	// this branch would keep bypassing every addon.
	if wc, ok := cconn.(*wrapClientConn); ok && wc.peekHTTP() {
		conn.Close()
		// 上面为 TLS 尝试拨过的上游连接已关闭，但它把 ServerConn 挂在了 ConnContext 上；
		// 不清掉的话 attack() 会复用这条已关闭的连接（表现为 200 + 空 body）。
		f.ConnContext.ServerConn = nil
		f.ConnContext.ClientConn.Tls = false
		proxy.attacker.initHttpDialFn(req)
		proxy.attacker.servePlain(cconn, f.ConnContext) // takes ownership of cconn
		return
	}

	e.runTunnel(log, conn, cconn, f)
	cconn.Close()
	conn.Close()
}

func (e *entry) httpsDialLazyAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.httpsDialLazyAttack",
		"host": req.Host,
	})

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		log.Error(err)
		return
	}

	wc, _ := cconn.(*wrapClientConn)
	peek, err := peekWithin(wc, 3, sniffWindow)
	if err == errPeekTimeout {
		// 服务端先发言：不能等客户端。直接拨上游并透传，否则 NULL 探针看不到 banner。
		// 这里必须用脱钩的 ctx：CONNECT handler 一返回，req.Context() 就被取消。
		dctx, dcancel := context.WithTimeout(context.WithoutCancel(req.Context()), 10*time.Second)
		conn, derr := proxy.attacker.httpsDial(dctx, req)
		dcancel()
		if derr != nil {
			cconn.Close()
			log.Error(derr)
			return
		}
		defer conn.Close()
		defer cconn.Close()
		e.runTunnel(log, conn, cconn, f)
		return
	}
	if err != nil {
		cconn.Close()
		log.Error(err)
		return
	}

	if helper.IsTls(peek) {
		f.ConnContext.ClientConn.Tls = true
		proxy.attacker.httpsLazyAttack(req.Context(), cconn, req)
		return
	}

	wsPeek, err := cconn.(*wrapClientConn).PeekBuffered()
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		cconn.Close()
		log.Error(err)
		return
	}

	if helper.IsWebSocket(wsPeek) {
		conn, err := proxy.attacker.httpsDial(req.Context(), req)
		if err != nil {
			cconn.Close()
			log.Error(err)
			return
		}
		err = proxy.webSocketHandler.handle(conn, cconn, f)
		if err != nil {
			log.Errorf("WebSocket handle error: %v", err)
			cconn.Close()
			conn.Close()
		}
		return
	}

	conn, err := proxy.attacker.httpsDial(req.Context(), req)
	if err != nil {
		cconn.Close()
		log.Error(err)
		return
	}
	// Plaintext HTTP over CONNECT (curl -p, proxychains, a plain HTTP probe): serve it
	// through the same http.Server as MITM'd traffic so addons see method/path/body.
	// No upstream conn is open yet on this path.
	if wc, ok := cconn.(*wrapClientConn); ok && wc.peekHTTP() {
		conn.Close()
		// 上面为 TLS 尝试拨过的上游连接已关闭，但它把 ServerConn 挂在了 ConnContext 上；
		// 不清掉的话 attack() 会复用这条已关闭的连接（表现为 200 + 空 body）。
		f.ConnContext.ServerConn = nil
		f.ConnContext.ClientConn.Tls = false
		proxy.attacker.initHttpDialFn(req)
		proxy.attacker.servePlain(cconn, f.ConnContext) // takes ownership of cconn
		return
	}

	e.runTunnel(log, conn, cconn, f)
	conn.Close()
	cconn.Close()
}
