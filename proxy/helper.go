package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

var normalErrMsgs []string = []string{
	"read: connection reset by peer",
	"write: broken pipe",
	"i/o timeout",
	"net/http: TLS handshake timeout",
	"io: read/write on closed pipe",
	"connect: connection refused",
	"connect: connection reset by peer",
	"use of closed network connection",
}

// 仅打印预料之外的错误信息
func logErr(log *log.Entry, err error) (loged bool) {
	msg := err.Error()

	for _, str := range normalErrMsgs {
		if strings.Contains(msg, str) {
			log.Debug(err)
			return
		}
	}

	log.Error(err)
	loged = true
	return
}

// errTunnelBudget marks a tunnel aborted because the app's byte budget ran out.
var errTunnelBudget = errors.New("tunnel byte budget exceeded")

// transferStats is what the app needs to account for one tunnel: direction
// counts, how long it lived, and why it ended (closed / budget_bytes /
// budget_duration / error).
type transferStats struct {
	Up         int64
	Down       int64
	Duration   time.Duration
	Terminated string
}

// budgetReader stops a tunnel once the shared bidirectional byte budget is
// exhausted. It returns the bytes it already read, then errTunnelBudget, so the
// peer sees a closed connection rather than a silent half-open one.
type budgetReader struct {
	r     io.Reader
	used  *int64
	limit int64
}

func (b *budgetReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if n > 0 && b.limit > 0 {
		if atomic.AddInt64(b.used, int64(n)) > b.limit {
			return n, errTunnelBudget
		}
	}
	return n, err
}

// transfer copies data in both directions and reports how many bytes went
// client->server (up) and server->client (down). The counts used to be thrown
// away, which made per-tunnel accounting impossible.
//
// maxBytes caps the sum of both directions (0 = unlimited); maxDur caps the
// tunnel lifetime (0 = unlimited). Both are enforced here because this is the
// only place that sees the bytes as they flow.
func transfer(log *log.Entry, server, client io.ReadWriteCloser, budget TunnelBudget) transferStats {
	maxBytes, maxDur := budget.MaxBytes, budget.MaxDur
	start := time.Now()
	if maxDur > 0 {
		deadline := start.Add(maxDur)
		if c, ok := server.(net.Conn); ok {
			_ = c.SetDeadline(deadline)
		}
		if c, ok := client.(net.Conn); ok {
			_ = c.SetDeadline(deadline)
		}
	}
	var used int64
	// failClosed flips when the app reports the policy source unavailable; after
	// that the tunnel gets an idle deadline (refreshed by activity) and is closed
	// with terminated=fail_closed.
	var failClosed atomic.Bool
	guardDone := make(chan struct{})
	defer close(guardDone)
	if budget.Abort != nil {
		go func() {
			t := time.NewTicker(500 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-guardDone:
					return
				case <-t.C:
					if budget.Abort() {
						failClosed.Store(true)
						idle := budget.Idle
						if idle <= 0 {
							idle = 60 * time.Second
						}
						dl := time.Now().Add(idle)
						if c, ok := server.(net.Conn); ok {
							_ = c.SetReadDeadline(dl)
						}
						if c, ok := client.(net.Conn); ok {
							_ = c.SetReadDeadline(dl)
						}
						return
					}
				}
			}
		}()
	}
	var src io.Reader = client
	if maxBytes > 0 {
		src = &budgetReader{r: client, used: &used, limit: maxBytes}
	}
	src = &guardReader{r: src, conn: connOf(client), idle: budget.Idle, closed: &failClosed}
	var dstW io.Writer = client
	type copyResult struct {
		dir string
		n   int64
		err error
	}
	done := make(chan struct{})
	defer close(done)

	resChan := make(chan copyResult, 2)
	go func() {
		n, err := io.Copy(server, src)
		log.Debugln("client copy end", err)
		client.Close()
		// A client EOF ends the tunnel. Without closing the upstream side the
		// other direction never returns and the tunnel (with its accounting)
		// leaks.
		server.Close()
		select {
		case <-done:
		case resChan <- copyResult{"up", n, err}:
		}
	}()
	go func() {
		var r io.Reader = server
		if maxBytes > 0 {
			r = &budgetReader{r: server, used: &used, limit: maxBytes}
		}
		r = &guardReader{r: r, conn: connOf(server), idle: budget.Idle, closed: &failClosed}
		n, err := io.Copy(dstW, r)
		log.Debugln("server copy end", err)
		server.Close()
		if err != nil {
			// 预算/超时/上游异常都必须立即掐断客户端，否则另一方向还阻塞在
			// client.Read 上，隧道要等客户端自己断开才结束（预算形同虚设）。
			client.Close()
		}

		if clientConn, ok := client.(*wrapClientConn); ok {
			err := clientConn.Conn.(*net.TCPConn).CloseRead()
			log.Debugln("clientConn.Conn.(*net.TCPConn).CloseRead()", err)
		}

		select {
		case <-done:
		case resChan <- copyResult{"down", n, err}:
		}
	}()

	stats := transferStats{Terminated: "closed"}
	budgetHit := false
	policyCut := false
	for i := 0; i < 2; i++ {
		res := <-resChan
		if res.dir == "up" {
			stats.Up = res.n
		} else {
			stats.Down = res.n
		}
		if res.err != nil {
			if errors.Is(res.err, errTunnelBudget) {
				budgetHit = true
				continue
			}
			if failClosed.Load() {
				policyCut = true
				continue
			}
			var ne net.Error
			if maxDur > 0 && errors.As(res.err, &ne) && ne.Timeout() {
				stats.Terminated = "budget_duration"
				continue
			}
			logErr(log, res.err)
			// Drain the other direction so its goroutine does not leak, but keep
			// the byte counts we already have.
			for j := i + 1; j < 2; j++ {
				rest := <-resChan
				if rest.dir == "up" {
					stats.Up = rest.n
				} else {
					stats.Down = rest.n
				}
			}
			break
		}
	}
	if budgetHit {
		stats.Terminated = "budget_bytes"
	}
	if policyCut {
		stats.Terminated = "fail_closed"
	}
	stats.Duration = time.Since(start)
	return stats
}

// guardReader refreshes the idle deadline on every read once the policy source is
// gone: an active tunnel stays alive, an idle one hits the deadline and closes.
type guardReader struct {
	r      io.Reader
	conn   net.Conn
	idle   time.Duration
	closed *atomic.Bool
}

func (g *guardReader) Read(p []byte) (int, error) {
	if g.conn != nil && g.closed != nil && g.closed.Load() {
		idle := g.idle
		if idle <= 0 {
			idle = 60 * time.Second
		}
		_ = g.conn.SetReadDeadline(time.Now().Add(idle))
	}
	return g.r.Read(p)
}

// connOf returns the net.Conn underneath a reader/writer when there is one.
func connOf(v any) net.Conn {
	if c, ok := v.(net.Conn); ok {
		return c
	}
	return nil
}

func httpError(w http.ResponseWriter, error string, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`) // Indicates that the proxy server requires client credentials
	w.WriteHeader(code)
	fmt.Fprintln(w, error)
}
