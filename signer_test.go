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
	"strconv"
	"strings"
	"sync"
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

func TestMITMCertCacheDuplicateStoreRefreshesTTL(t *testing.T) {
	now := time.Unix(100, 0)
	cache := newMITMCertCache(1, time.Hour)
	cache.now = func() time.Time { return now }

	cache.store("example.com", testTLSCertificate(1))
	now = now.Add(30 * time.Minute)
	cache.store("example.com", testTLSCertificate(2))

	now = now.Add(31 * time.Minute)
	if got, ok := cache.get("example.com"); !ok || got.Certificate[0][0] != 1 {
		t.Fatalf("expected cached certificate 1 after refreshed TTL, got %v, ok=%v", got.Certificate, ok)
	}
	now = now.Add(29 * time.Minute)
	if _, ok := cache.get("example.com"); ok {
		t.Fatal("expected certificate to expire one hour after the duplicate store")
	}
}

func TestMITMCertCacheLookupDoesNotRefreshTTL(t *testing.T) {
	now := time.Unix(100, 0)
	cache := newMITMCertCache(2, time.Hour)
	cache.now = func() time.Time { return now }
	cache.store("example.com", testTLSCertificate(1))

	now = now.Add(time.Hour - time.Nanosecond)
	if _, ok := cache.get("example.com"); !ok {
		t.Fatal("expected example.com to be cached")
	}
	now = now.Add(time.Nanosecond)
	if _, ok := cache.get("example.com"); ok {
		t.Fatal("expected certificate to expire at its original TTL despite the lookup")
	}
}

func TestMITMCertCacheEvictsLeastRecentlyUsedCertificate(t *testing.T) {
	for _, refresh := range []string{"lookup", "duplicate store"} {
		t.Run(refresh, func(t *testing.T) {
			cache := newMITMCertCache(2, time.Hour)
			cache.store("first.example", testTLSCertificate(1))
			cache.store("second.example", testTLSCertificate(2))
			if refresh == "lookup" {
				if _, ok := cache.get("first.example"); !ok {
					t.Fatal("expected first.example to be cached")
				}
			} else {
				cache.store("first.example", testTLSCertificate(4))
			}
			cache.store("third.example", testTLSCertificate(3))

			if _, ok := cache.get("second.example"); ok {
				t.Fatal("expected second.example to be evicted")
			}
			if got, ok := cache.get("first.example"); !ok || got.Certificate[0][0] != 1 {
				t.Fatalf("expected first.example to retain certificate 1, got %v, ok=%v", got.Certificate, ok)
			}
			if got, ok := cache.get("third.example"); !ok || got.Certificate[0][0] != 3 {
				t.Fatalf("expected third.example to be cached, got %v, ok=%v", got.Certificate, ok)
			}
			if got := len(cache.entries); got != 2 {
				t.Fatalf("expected exactly 2 stored entries, got %d", got)
			}
		})
	}
}

func TestMITMCertCacheExpiresCertificates(t *testing.T) {
	for _, lookupFirst := range []bool{false, true} {
		t.Run("lookupFirst="+strconv.FormatBool(lookupFirst), func(t *testing.T) {
			now := time.Unix(100, 0)
			cache := newMITMCertCache(1, time.Minute)
			cache.now = func() time.Time { return now }
			cache.store("example.com", testTLSCertificate(1))
			now = now.Add(time.Minute)

			if lookupFirst {
				if _, ok := cache.get("example.com"); ok {
					t.Fatal("expected expired certificate to be a cache miss")
				}
				if len(cache.entries) != 0 || cache.recent.Len() != 0 {
					t.Fatal("expected expired lookup to remove the certificate and its eviction bookkeeping")
				}
			}
			cache.store("example.com", testTLSCertificate(2))
			if got, ok := cache.get("example.com"); !ok || got.Certificate[0][0] != 2 {
				t.Fatalf("expected replacement certificate 2, got %v, ok=%v", got.Certificate, ok)
			}
			if len(cache.entries) != 1 || cache.recent.Len() != 1 {
				t.Fatal("expected replacement to occupy exactly one cache and eviction-order entry")
			}
		})
	}
}

func TestMITMCertCacheConcurrentStoresReuseCertificate(t *testing.T) {
	cache := newMITMCertCache(2, time.Hour)
	const writers = 32
	start := make(chan struct{})
	results := make(chan tls.Certificate, writers)
	for i := 0; i < writers; i++ {
		go func(id byte) {
			<-start
			results <- cache.store("example.com", testTLSCertificate(id))
		}(byte(i))
	}
	close(start)

	want := (<-results).Certificate[0][0]
	for i := 1; i < writers; i++ {
		if got := (<-results).Certificate[0][0]; got != want {
			t.Errorf("expected concurrent stores to reuse certificate %d, got %d", want, got)
		}
	}
	if got, ok := cache.get("example.com"); !ok || got.Certificate[0][0] != want {
		t.Fatalf("expected certificate %d to remain cached, got %v, ok=%v", want, got.Certificate, ok)
	}
}

func TestMITMCertCacheConcurrentAccessRemainsBounded(t *testing.T) {
	const maxEntries = 4
	cache := newMITMCertCache(maxEntries, time.Hour)
	var writers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		writers.Add(1)
		go func(id int) {
			defer writers.Done()
			host := strconv.Itoa(id) + ".example"
			<-start
			for j := 0; j < 20; j++ {
				cache.store(host, testTLSCertificate(byte(id)))
				cache.get(host)
				cache.mu.Lock()
				got := len(cache.entries)
				cache.mu.Unlock()
				if got > maxEntries {
					t.Errorf("cache exceeded its capacity of %d: got %d entries", maxEntries, got)
				}
			}
		}(i)
	}
	close(start)
	writers.Wait()

	if got := len(cache.entries); got != maxEntries {
		t.Fatalf("expected %d entries after filling the cache, got %d", maxEntries, got)
	}
	if cache.recent.Len() != maxEntries {
		t.Fatalf("expected %d eviction-order entries, got %d", maxEntries, cache.recent.Len())
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
	for _, config := range []struct {
		name       string
		maxEntries int
		ttl        time.Duration
	}{
		{"zero capacity", 0, time.Hour},
		{"negative capacity", -1, time.Hour},
		{"zero TTL", 2, 0},
		{"negative TTL", 2, -time.Second},
	} {
		t.Run(config.name, func(t *testing.T) {
			tlsConfig := TLSConfigFromCAWithCache(&GoproxyCa, config.maxEntries, config.ttl)
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
		})
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
