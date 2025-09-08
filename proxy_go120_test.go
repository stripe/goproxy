//go:build go1.20
// +build go1.20

package goproxy_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stripe/goproxy"
)

func TestAddServerIpHeader(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer(goproxy.WithAddServerIpHeader(true))
	s := httptest.NewServer(proxy)
	proxyUrl, _ := url.Parse(s.URL)

	tr := &http.Transport{
		OnProxyConnectResponse: func(ctx context.Context, proxyURL *url.URL, connectReq *http.Request, connectRes *http.Response) error {
			if connectRes.Header.Get(goproxy.ServerIpHeaderKey) != "127.0.0.1" {
				t.Errorf("Expected %s, got %s", "127.0.0.1", connectRes.Header.Get(goproxy.ServerIpHeaderKey))
			}
			return nil
		},
		Proxy:           http.ProxyURL(proxyUrl),
		TLSClientConfig: acceptAllCerts,
	}
	client := &http.Client{Transport: tr}
	if resp := string(getOrFail(https.URL+"/bobo", client, t)); resp != "bobo" {
		t.Error("Wrong response when mitm", resp, "expected bobo")
	}
}

func newIPv6TestServer(t *testing.T, handler http.Handler) *httptest.Server {
	server := httptest.NewUnstartedServer(handler)
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available")
	}
	server.Listener = l
	server.StartTLS()
	return server
}

func TestAddServerIpHeaderIpv6(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer(goproxy.WithAddServerIpHeader(true))
	s := httptest.NewServer(proxy)
	proxyUrl, _ := url.Parse(s.URL)
	
	ipv6 := newIPv6TestServer(t, ConstantHanlder("bobo"))
	defer ipv6.Close()

	tr := &http.Transport{
		OnProxyConnectResponse: func(ctx context.Context, proxyURL *url.URL, connectReq *http.Request, connectRes *http.Response) error {
			serverIP := connectRes.Header.Get(goproxy.ServerIpHeaderKey)
			if serverIP != "::1" {
				t.Errorf("Expected ::1, got %s", serverIP)
			}
			return nil
		},
		Proxy:           http.ProxyURL(proxyUrl),
		TLSClientConfig: acceptAllCerts,
	}
	client := &http.Client{Transport: tr}
	if resp := string(getOrFail(ipv6.URL+"/bobo", client, t)); resp != "bobo" {
		t.Error("Wrong response when mitm", resp, "expected bobo")
	}
}
