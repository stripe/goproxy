package goproxy

import (
	"crypto/tls"
	"crypto/x509"
)

func init() {
	if goproxyCaErr != nil {
		panic("Error parsing builtin CA " + goproxyCaErr.Error())
	}
	var err error
	if GoproxyCa.Leaf, err = x509.ParseCertificate(GoproxyCa.Certificate[0]); err != nil {
		panic("Error parsing builtin CA " + err.Error())
	}
}

var tlsClientSkipVerify = &tls.Config{InsecureSkipVerify: true}

var defaultTlsConfig = &tls.Config{
	InsecureSkipVerify: true,
}

var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCnAjeLF59hdjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0xOTAzMDYxODM0MjFaFw0yOTAzMDMxODM0MjFaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstfJ5POnD/fEi/Wfu27L
vHA7c+UnDSS71IpVhwAuozK7YsefPBMl69H3hH/JmxouBQ7w930KaJRq0Dz+IHgZ
gbcHOaJpwmbDMtD510eD5kScS/HoY2Wii9uOSm9eDEsOpx7lBeV4jb4i9galZ4Pf
KN3Oq0Ngo69Nzp8M/JpGWYyI0w5XkQdXjDZMQwFUg1f7Npkp4PMLvJO5KIQECc+7
fqZbZo82Hvgx9dMZCil7a8yvZJ1MBNeCPxp7rr2TaxDRJW2NmFo4C44Uo8ykHTO4
fFahQ/n80N+P/l+r1RQ7nHGMGy+I09CGLgRu1bkwrf0NuKUCNioVbn8ymS3FXQyt
6wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA0NhkSeKaka1Ew5USmktgsJphjlDLL
XD5GaAGokvXOJoz18HTDhP9mns353fwSi6OFNlv/tj51wDckzqqJi3+1qAXlINxz
vooF07yLZDNy339Zkj45iP72QDpasuglt881xfjZPNMo0ZYW10/u4+hpfn0G1Zd0
Nqoih2BNd/CBLLkijBZoFFN+mWCivS8uk9yvUEQgk+GFMbmSynfbz2yUouc8hf9H
1dzgguBjtbZIP9dw64f7RO+eSxbz6I0qm0JavJ6+6brih8ktMXTsvhJhRnD0PC+M
HrwFXuZGu9hlVFaEuWJspeIIJwgq8ekWcUWbPkLBFPgRDqlg7+ToGxSu
-----END CERTIFICATE-----`)

var CA_KEY = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCy18nk86cP98SL
9Z+7bsu8cDtz5ScNJLvUilWHAC6jMrtix588EyXr0feEf8mbGi4FDvD3fQpolGrQ
PP4geBmBtwc5omnCZsMy0PnXR4PmRJxL8ehjZaKL245Kb14MSw6nHuUF5XiNviL2
BqVng98o3c6rQ2Cjr03Onwz8mkZZjIjTDleRB1eMNkxDAVSDV/s2mSng8wu8k7ko
hAQJz7t+pltmjzYe+DH10xkKKXtrzK9knUwE14I/GnuuvZNrENElbY2YWjgLjhSj
zKQdM7h8VqFD+fzQ34/+X6vVFDuccYwbL4jT0IYuBG7VuTCt/Q24pQI2KhVufzKZ
LcVdDK3rAgMBAAECggEAc2xzwBFE3DhjoJTZD4YVdbvVkxntFz2DAEx7oJKMhwWC
DOGbMpGFIuqzXc9/lVvTIa6f9Iq+Afrv6Q/ET75Tb/Vpc1gP+8iI6K4Y4UklpqLX
YOhyvFvnCW6dKgswXqy+ezukQib0pD53n+NwMxvYFi75aG0m3N2SUO0z23/SMY49
jTznLGISEKens2Uq7o8KsfGZjmvJNFy1lje8YasUXrfDW0nvvJw9UML49KS9avDn
n0kMsY0UDuGnHwHR7tvmJ4ijGF7D9jly4P2rAaBD5Evh2UQ/1jvHaLnSu2Hpzl3T
pTe2X1JZ2HOmCuD8GL60wwRxq7OZUTEejLh5jEM7KQKBgQDqpwF0Op9ilyTv8g7y
oE+nbLH5QOEk01OYMCQOvG/nveiQJMrtPGC1F+IH5J6VMfH2ngtVZwBTUe/Xel1W
9DTMZM0zmKCefXP5bUMczNUgAleoRxeZ8LvNi466QIL0sLJgIA6XpfvtV5vt+wRa
udAsvE/smoW+qc3vsuOuo9bYPQKBgQDDHP7D5LQYBU7mT75AMEMFtloXq8LcAoIC
iG7bDnG/ifplhvZmFCrb6hlqDBTxZpYEYzvFTDNaKlDsTzHTkki4ZGsx+uuSoyAr
k3/WsJ0extnpo1BNz2UZCaXJecNtKJN0eIPPqRDapZq6wsfrU5yByFEDVCersonc
jDkRU4fZRwKBgCnG2gdreH0BE950ZhzkVcolG/qYhn0b8sIhsAm/mtzTfthK9KYQ
HdegDOoC1gkR/1Y9BR+LWw96gw0GCCA3Ej9hovcQsWgGReOehFhYT4mHYTvgjF8n
8QfDVQHsAmS2IMvkaTSupI+5DVXtXvUYJ+wPCtvBFxa+/J80Zjztho6xAoGALfVN
eT0Mwr+1VwCfkqULlHPggsTdkE8y6n/ShNzBJFnO1k1VCrRjaAubUuRnpnkAiyYI
tS9+xRVEnHUHCovhfzWAHnS5OoAcGseSjDJrwA0c1TC3wKxCZwRjvbJluveczAl7
GtX691WcvbMVvjOioNtbYcpX0dSrLn0FEDS5wg8CgYEArzAT0Rq8XK/+vUB5QVGG
Z0MIc89P1Ahdd1cNZqJrZie7P3Oem9zSBwUi3EPd9puev4Zpxk4HYB9Gml1h5X6n
0GfQG7fo1gUF3LcL4vTa/rQk8aGAK8s2DI7zk8q6KTxBwwCcWucG28GO/krVQjZM
kYUHxJdmg/sQhB7vQ1Amf30=
-----END PRIVATE KEY-----`)

var GoproxyCa, goproxyCaErr = tls.X509KeyPair(CA_CERT, CA_KEY)
