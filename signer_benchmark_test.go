package goproxy

import (
	"crypto/tls"
	"strconv"
	"testing"
	"time"
)

// Benchmark only cache operations; certificate generation is identical on misses
// and would obscure the cost of lookups, TTL refresh, and bounded eviction.
func BenchmarkMITMCertCache(b *testing.B) {
	b.Run("Hit", func(b *testing.B) {
		cache, hosts, _ := benchmarkMITMCertCache()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cache.get(hosts[i%DefaultMITMCertCacheMaxEntries])
		}
	})

	b.Run("HitParallel", func(b *testing.B) {
		cache, hosts, _ := benchmarkMITMCertCache()
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				cache.get(hosts[i%DefaultMITMCertCacheMaxEntries])
				i++
			}
		})
	})

	b.Run("DuplicateStore", func(b *testing.B) {
		cache, hosts, cert := benchmarkMITMCertCache()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cache.store(hosts[i%DefaultMITMCertCacheMaxEntries], cert)
		}
	})

	b.Run("Eviction", func(b *testing.B) {
		cache, hosts, cert := benchmarkMITMCertCache()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Start outside the prefilled cache and cycle over twice its capacity
			// so every insertion evicts an entry.
			cache.store(hosts[(i+DefaultMITMCertCacheMaxEntries)%len(hosts)], cert)
		}
	})
}

func benchmarkMITMCertCache() (*mitmCertCache, []string, tls.Certificate) {
	cache := newMITMCertCache(DefaultMITMCertCacheMaxEntries, time.Hour)
	hosts := make([]string, 2*DefaultMITMCertCacheMaxEntries)
	cert := tls.Certificate{Certificate: [][]byte{{1}}}
	for i := range hosts {
		hosts[i] = strconv.Itoa(i) + ".example"
		if i < DefaultMITMCertCacheMaxEntries {
			cache.store(hosts[i], cert)
		}
	}
	return cache, hosts, cert
}
