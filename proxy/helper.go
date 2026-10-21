package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

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

// transfer copies data in both directions and reports how many bytes went
// client->server (up) and server->client (down). The counts used to be thrown
// away, which made per-tunnel accounting impossible.
func transfer(log *log.Entry, server, client io.ReadWriteCloser) (up, down int64) {
	type copyResult struct {
		dir string
		n   int64
		err error
	}
	done := make(chan struct{})
	defer close(done)

	resChan := make(chan copyResult, 2)
	go func() {
		n, err := io.Copy(server, client)
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
		n, err := io.Copy(client, server)
		log.Debugln("server copy end", err)
		server.Close()

		if clientConn, ok := client.(*wrapClientConn); ok {
			err := clientConn.Conn.(*net.TCPConn).CloseRead()
			log.Debugln("clientConn.Conn.(*net.TCPConn).CloseRead()", err)
		}

		select {
		case <-done:
		case resChan <- copyResult{"down", n, err}:
		}
	}()

	for i := 0; i < 2; i++ {
		res := <-resChan
		if res.dir == "up" {
			up = res.n
		} else {
			down = res.n
		}
		if res.err != nil {
			logErr(log, res.err)
			// Drain the other direction so its goroutine does not leak, but keep
			// the byte counts we already have.
			for j := i + 1; j < 2; j++ {
				rest := <-resChan
				if rest.dir == "up" {
					up = rest.n
				} else {
					down = rest.n
				}
			}
			return up, down
		}
	}
	return up, down
}

func httpError(w http.ResponseWriter, error string, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`) // Indicates that the proxy server requires client credentials
	w.WriteHeader(code)
	fmt.Fprintln(w, error)
}
