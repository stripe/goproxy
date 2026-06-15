package goproxy

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

type writeErrConn struct {
	closed   bool
	writeErr error
}

func (c *writeErrConn) Read(_ []byte) (int, error)       { return 0, io.EOF }
func (c *writeErrConn) Write(_ []byte) (int, error)      { return 0, c.writeErr }
func (c *writeErrConn) Close() error                     { c.closed = true; return nil }
func (c *writeErrConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *writeErrConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *writeErrConn) SetDeadline(time.Time) error      { return nil }
func (c *writeErrConn) SetReadDeadline(time.Time) error  { return nil }
func (c *writeErrConn) SetWriteDeadline(time.Time) error { return nil }

func TestConnectDialProxyWithContextReturnsWriteError(t *testing.T) {
	proxy := NewProxyHttpServer()
	expectedErr := errors.New("write failed")
	conn := &writeErrConn{writeErr: expectedErr}

	proxy.ConnectDialContext = func(ctx *ProxyCtx, network, addr string) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("unexpected network %q", network)
		}
		if addr != "proxy.example:8080" {
			t.Fatalf("unexpected proxy addr %q", addr)
		}
		return conn, nil
	}

	ctx := &ProxyCtx{proxy: proxy}
	_, err := proxy.connectDialProxyWithContext(ctx, "http://proxy.example:8080", "example.com:443")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected write error to be wrapped, got %v", err)
	}
	if !strings.Contains(err.Error(), "write CONNECT request") {
		t.Fatalf("expected wrapped write error, got %q", err)
	}
	if !conn.closed {
		t.Fatal("expected upstream proxy connection to be closed")
	}
}
