package goproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func orFatal(msg string, err error, t *testing.T) {
	if err != nil {
		t.Fatal(msg, err)
	}
}

type ConstantHanlder string

func (h ConstantHanlder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h))
}

func rsaPrivateKeyFromCert(t *testing.T, cert tls.Certificate) *rsa.PrivateKey {
	t.Helper()
	key, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected RSA private key, got %T", cert.PrivateKey)
	}
	return key
}

func testTLSCertificate(id byte) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{{id}}}
}

func getBrowser(args []string) string {
	for i, arg := range args {
		if arg == "-browser" && i+1 < len(arg) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "-browser=") {
			return arg[len("-browser="):]
		}
	}
	return ""
}

func TestMITMCertCacheReturnsStoredCertificate(t *testing.T) {
	cache := newMITMCertCache(2, time.Hour)
	cert1 := testTLSCertificate(1)
	cert2 := testTLSCertificate(2)

	if got := cache.store("example.com", cert1); got.Certificate[0][0] != 1 {
		t.Fatalf("expected stored certificate 1, got %d", got.Certificate[0][0])
	}
	if got := cache.store("example.com", cert2); got.Certificate[0][0] != 1 {
		t.Fatalf("expected existing certificate 1 on duplicate store, got %d", got.Certificate[0][0])
	}
	if got, ok := cache.get("example.com"); !ok || got.Certificate[0][0] != 1 {
		t.Fatalf("expected cached certificate 1, got %v, ok=%v", got.Certificate, ok)
	}
}

func TestMITMCertCacheEvictsLeastRecentlyUsedCertificate(t *testing.T) {
	cache := newMITMCertCache(2, time.Hour)
	cache.store("first.example", testTLSCertificate(1))
	cache.store("second.example", testTLSCertificate(2))
	if _, ok := cache.get("first.example"); !ok {
		t.Fatal("expected first.example to be cached")
	}
	cache.store("third.example", testTLSCertificate(3))

	if _, ok := cache.get("second.example"); ok {
		t.Fatal("expected second.example to be evicted")
	}
	if _, ok := cache.get("first.example"); !ok {
		t.Fatal("expected first.example to remain cached")
	}
	if _, ok := cache.get("third.example"); !ok {
		t.Fatal("expected third.example to be cached")
	}
}

func TestMITMCertCacheExpiresCertificates(t *testing.T) {
	now := time.Unix(100, 0)
	cache := newMITMCertCache(2, time.Minute)
	cache.now = func() time.Time { return now }

	cache.store("example.com", testTLSCertificate(1))
	now = now.Add(time.Minute)
	if _, ok := cache.get("example.com"); ok {
		t.Fatal("expected certificate to expire at TTL boundary")
	}
	cache.store("example.com", testTLSCertificate(2))
	got, ok := cache.get("example.com")
	if !ok {
		t.Fatal("expected replacement certificate to be cached")
	}
	if got.Certificate[0][0] != 2 {
		t.Fatalf("expected replacement certificate 2, got %d", got.Certificate[0][0])
	}
}

func TestSignHostGeneratesRandomLeafPrivateKey(t *testing.T) {
	cert1, err := signHost(GoproxyCa, []string{"example.com"})
	orFatal("singHost", err, t)
	cert2, err := signHost(GoproxyCa, []string{"example.com"})
	orFatal("singHost", err, t)
	leaf1, err := x509.ParseCertificate(cert1.Certificate[0])
	orFatal("ParseCertificate", err, t)
	leaf2, err := x509.ParseCertificate(cert2.Certificate[0])
	orFatal("ParseCertificate", err, t)

	key1 := rsaPrivateKeyFromCert(t, cert1)
	key2 := rsaPrivateKeyFromCert(t, cert2)
	if key1.N.Cmp(key2.N) == 0 {
		t.Fatal("signHost generated identical RSA private keys for repeated host")
	}
	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) == 0 {
		t.Fatal("signHost generated identical serial numbers for repeated host")
	}
}

func TestTLSConfigFromCACachesHostCertificates(t *testing.T) {
	tlsConfig := TLSConfigFromCA(&GoproxyCa)
	ctx := &ProxyCtx{proxy: NewProxyHttpServer()}

	config1, err := tlsConfig("example.com:443", ctx)
	orFatal("TLSConfigFromCA", err, t)
	config2, err := tlsConfig("example.com:443", ctx)
	orFatal("TLSConfigFromCA", err, t)
	if len(config1.Certificates) != 1 {
		t.Fatalf("expected one certificate in first TLS config, got %d", len(config1.Certificates))
	}
	if len(config2.Certificates) != 1 {
		t.Fatalf("expected one certificate in second TLS config, got %d", len(config2.Certificates))
	}

	key1 := rsaPrivateKeyFromCert(t, config1.Certificates[0])
	key2 := rsaPrivateKeyFromCert(t, config2.Certificates[0])
	if key1 != key2 {
		t.Fatal("TLSConfigFromCA did not reuse the cached host certificate")
	}
}

func TestTLSConfigFromCACacheCanBeDisabled(t *testing.T) {
	tlsConfig := TLSConfigFromCAWithCache(&GoproxyCa, 0, time.Hour)
	ctx := &ProxyCtx{proxy: NewProxyHttpServer()}

	config1, err := tlsConfig("example.com:443", ctx)
	orFatal("TLSConfigFromCAWithCache", err, t)
	config2, err := tlsConfig("example.com:443", ctx)
	orFatal("TLSConfigFromCAWithCache", err, t)

	key1 := rsaPrivateKeyFromCert(t, config1.Certificates[0])
	key2 := rsaPrivateKeyFromCert(t, config2.Certificates[0])
	if key1.N.Cmp(key2.N) == 0 {
		t.Fatal("TLSConfigFromCAWithCache reused a certificate when caching was disabled")
	}
}

func TestSingerTls(t *testing.T) {
	cert, err := signHost(GoproxyCa, []string{"example.com", "1.1.1.1", "localhost"})
	orFatal("singHost", err, t)
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	orFatal("ParseCertificate", err, t)
	expected := "key verifies with Go"
	server := httptest.NewUnstartedServer(ConstantHanlder(expected))
	defer server.Close()
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert, GoproxyCa}}
	server.TLS.BuildNameToCertificate()
	server.StartTLS()
	certpool := x509.NewCertPool()
	certpool.AddCert(GoproxyCa.Leaf)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certpool},
	}
	asLocalhost := strings.Replace(server.URL, "127.0.0.1", "localhost", -1)
	req, err := http.NewRequest("GET", asLocalhost, nil)
	orFatal("NewRequest", err, t)
	resp, err := tr.RoundTrip(req)
	orFatal("RoundTrip", err, t)
	txt, err := ioutil.ReadAll(resp.Body)
	orFatal("ioutil.ReadAll", err, t)
	if string(txt) != expected {
		t.Errorf("Expected '%s' got '%s'", expected, string(txt))
	}
	browser := getBrowser(os.Args)
	if browser != "" {
		exec.Command(browser, asLocalhost).Run()
		time.Sleep(10 * time.Second)
	}
}

func TestSingerX509(t *testing.T) {
	cert, err := signHost(GoproxyCa, []string{"example.com", "1.1.1.1", "localhost"})
	orFatal("singHost", err, t)
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	orFatal("ParseCertificate", err, t)
	certpool := x509.NewCertPool()
	certpool.AddCert(GoproxyCa.Leaf)
	orFatal("VerifyHostname", cert.Leaf.VerifyHostname("example.com"), t)
	orFatal("CheckSignatureFrom", cert.Leaf.CheckSignatureFrom(GoproxyCa.Leaf), t)
	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   certpool,
	})
	orFatal("Verify", err, t)
}
