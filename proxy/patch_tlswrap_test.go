package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "patch-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A TLS-wrapped non-HTTP protocol (LDAPS, RDP, DB-TLS) must fail closed in a
// bounded time instead of hanging forever: ReadHeaderTimeout answers 400 and
// closes the connection.
func TestTLSWrappedNonHTTP(t *testing.T) {
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
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
			go func() {
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("LDAP-OK"))
				time.Sleep(2 * time.Second)
				c.Close()
			}()
		}
	}()

	p, addr := startProxy(t)
	defer p.Close()
	rec := &recAddon{}
	p.AddAddon(rec)

	c, _ := connect(t, addr, ln.Addr().String())
	defer c.Close()
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "127.0.0.1"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake through MITM failed: %v", err)
	}
	_, _ = tc.Write([]byte("NOT-HTTP-BINARY"))
	_ = tc.SetReadDeadline(time.Now().Add(10 * time.Second))
	start := time.Now()
	buf := make([]byte, 16)
	n, err := tc.Read(buf)
	elapsed := time.Since(start)
	t.Logf("read n=%d err=%v elapsed=%s", n, err, elapsed)
	if elapsed > 5*time.Second {
		t.Fatalf("connection hung (no fail-closed) for %s", elapsed)
	}
	if got := rec.seen.Load(); got != nil {
		t.Fatalf("non-HTTP stream should not surface as an HTTP request, got %v", got)
	}
}
