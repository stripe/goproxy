package goproxy_test

import (
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stripe/goproxy"
)

func awaitHTTPStats(t *testing.T, results <-chan goproxy.HTTPRequestStats) goproxy.HTTPRequestStats {
	t.Helper()
	select {
	case stats := <-results:
		return stats
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP completion callback did not run")
		return goproxy.HTTPRequestStats{}
	}
}

func TestHTTPRequestCompleteCounts(t *testing.T) {
	tests := []struct {
		name           string
		replaceRequest bool
		replaceReply   bool
		bytesOut       int64
	}{
		{
			name:     "unknown body length",
			bytesOut: 6,
		},
		{
			name:           "request filter replacement",
			replaceRequest: true,
			bytesOut:       3,
		},
		{
			name:         "response filter replacement",
			replaceReply: true,
			bytesOut:     6,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			proxy := goproxy.NewProxyHttpServer()
			results := make(chan goproxy.HTTPRequestStats, 2)
			proxy.HTTPRequestCompleteHandler = func(ctx *goproxy.ProxyCtx, stats goproxy.HTTPRequestStats) {
				if ctx.Resp == nil || ctx.Resp.StatusCode != http.StatusOK || ctx.UserData != "consumer" {
					t.Error("completion lost request context")
				}
				results <- stats
			}
			proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				ctx.UserData = "consumer"
				if testCase.replaceRequest {
					req.Body.Close()
					req.Body = ioutil.NopCloser(strings.NewReader("new"))
				}
				ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
					defer req.Body.Close()
					if _, err := io.Copy(ioutil.Discard, req.Body); err != nil {
						return nil, err
					}
					return &http.Response{
						StatusCode:    http.StatusOK,
						Header:        make(http.Header),
						Body:          ioutil.NopCloser(strings.NewReader("reply")),
						ContentLength: -1,
					}, nil
				})
				return req, nil
			})
			proxy.OnResponse().DoFunc(func(resp *http.Response, _ *goproxy.ProxyCtx) *http.Response {
				select {
				case <-results:
					t.Error("completion ran before the response was forwarded")
				default:
				}
				if testCase.replaceReply {
					io.Copy(ioutil.Discard, resp.Body)
					resp.Body.Close()
					resp.Body = ioutil.NopCloser(strings.NewReader("local replacement"))
				}
				return resp
			})
			proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "http://example.com/", strings.NewReader("upload")))
			stats := awaitHTTPStats(t, results)
			if stats.BytesIn != 5 || stats.BytesOut != testCase.bytesOut || stats.Error != nil {
				t.Fatalf("unexpected stats: %+v", stats)
			}
			select {
			case <-results:
				t.Fatal("duplicate completion callback")
			default:
			}
		})
	}
}

type failingHTTPBody struct {
	reader io.Reader
	err    error
}

func (b *failingHTTPBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	if err == io.EOF {
		err = b.err
	}
	return n, err
}

func (b *failingHTTPBody) Close() error { return nil }

func TestHTTPRequestCompleteFailures(t *testing.T) {
	failure := errors.New("forwarding failed")
	tests := []struct {
		name     string
		mode     string
		bytesIn  int64
		bytesOut int64
		wantErr  error
	}{
		{
			name: "filter rejection",
			mode: "reject",
		},
		{
			name:     "transport failure after partial upload",
			mode:     "transport",
			bytesOut: 3,
			wantErr:  failure,
		},
		{
			name:     "response read failure",
			mode:     "response",
			bytesIn:  3,
			bytesOut: 3,
			wantErr:  failure,
		},
		{
			name:     "response filter consumes read failure",
			mode:     "filter",
			bytesIn:  3,
			bytesOut: 3,
			wantErr:  failure,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			proxy := goproxy.NewProxyHttpServer()
			results := make(chan goproxy.HTTPRequestStats, 2)
			proxy.HTTPRequestCompleteHandler = func(_ *goproxy.ProxyCtx, stats goproxy.HTTPRequestStats) { results <- stats }
			proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				if testCase.mode == "reject" {
					return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "denied")
				}
				ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
					defer req.Body.Close()
					io.CopyN(ioutil.Discard, req.Body, 3)
					if testCase.mode == "transport" {
						return nil, failure
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       &failingHTTPBody{reader: strings.NewReader("abc"), err: failure},
					}, nil
				})
				return req, nil
			})
			if testCase.mode == "filter" {
				proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
					io.Copy(ioutil.Discard, resp.Body)
					resp.Body.Close()
					resp.Body = ioutil.NopCloser(strings.NewReader("replacement"))
					return resp
				})
			}
			proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "http://example.com/", strings.NewReader("long upload")))
			stats := awaitHTTPStats(t, results)
			if stats.BytesIn != testCase.bytesIn || stats.BytesOut != testCase.bytesOut || stats.Error != testCase.wantErr {
				t.Fatalf("unexpected stats: %+v", stats)
			}
			select {
			case <-results:
				t.Fatal("duplicate completion callback")
			default:
			}
		})
	}
}

type partialErrorHTTPResponseWriter struct {
	header http.Header
	err    error
}

func (w *partialErrorHTTPResponseWriter) Header() http.Header { return w.header }

func (w *partialErrorHTTPResponseWriter) WriteHeader(int) {}

func (w *partialErrorHTTPResponseWriter) Write(p []byte) (int, error) {
	n := 2
	if n > len(p) {
		n = len(p)
	}
	return n, w.err
}

type writerToHTTPBody struct{ data []byte }

type readOnlyHTTPBody struct{ io.Reader }

func (readOnlyHTTPBody) Close() error { return nil }

func (*writerToHTTPBody) Read([]byte) (int, error) {
	panic("response body did not use its WriterTo method")
}

func (*writerToHTTPBody) Close() error { return nil }

func (b *writerToHTTPBody) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(b.data)
	return int64(n), err
}

func TestHTTPRequestCompleteCountsBodyReadOnPartialOutputError(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		writerTo    bool
		wantBytesIn int64
	}{
		{name: "plain body counts bytes consumed by Read", wantBytesIn: 6},
		{name: "WriterTo body counts bytes accepted by destination", writerTo: true, wantBytesIn: 2},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			outputErr := errors.New("client write failed")
			proxy := goproxy.NewProxyHttpServer()
			results := make(chan goproxy.HTTPRequestStats, 2)
			proxy.HTTPRequestCompleteHandler = func(_ *goproxy.ProxyCtx, stats goproxy.HTTPRequestStats) { results <- stats }
			proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				ctx.RoundTripper = goproxy.RoundTripperFunc(func(*http.Request, *goproxy.ProxyCtx) (*http.Response, error) {
					var body io.ReadCloser = readOnlyHTTPBody{Reader: strings.NewReader("abcdef")}
					if testCase.writerTo {
						body = &writerToHTTPBody{data: []byte("abcdef")}
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       body,
					}, nil
				})
				return req, nil
			})
			writer := &partialErrorHTTPResponseWriter{header: make(http.Header), err: outputErr}
			proxy.ServeHTTP(writer, httptest.NewRequest("GET", "http://example.com/", nil))

			stats := awaitHTTPStats(t, results)
			if stats.BytesIn != testCase.wantBytesIn || stats.BytesOut != 0 || stats.Error != outputErr {
				t.Fatalf("unexpected stats after partial output failure: %+v", stats)
			}
			select {
			case <-results:
				t.Fatal("completion callback ran more than once")
			default:
			}
		})
	}
}

type concurrentReadHTTPBody struct {
	mu             sync.Mutex
	remaining      int
	firstReaders   int
	firstReadCount int
	firstReadDone  chan struct{}
}

func (b *concurrentReadHTTPBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.remaining == 0 {
		b.mu.Unlock()
		return 0, io.EOF
	}
	b.remaining--
	waitForFirstReaders := false
	if b.firstReadCount < b.firstReaders {
		b.firstReadCount++
		waitForFirstReaders = true
		if b.firstReadCount == b.firstReaders {
			close(b.firstReadDone)
		}
	}
	b.mu.Unlock()
	if waitForFirstReaders {
		<-b.firstReadDone
	}
	p[0] = 'x'
	return 1, nil
}

func (*concurrentReadHTTPBody) Close() error { return nil }

func TestHTTPRequestCompleteConcurrentResponseReads(t *testing.T) {
	const readers = 8
	const bodyBytes = 4096
	proxy := goproxy.NewProxyHttpServer()
	results := make(chan goproxy.HTTPRequestStats, 1)
	proxy.HTTPRequestCompleteHandler = func(_ *goproxy.ProxyCtx, stats goproxy.HTTPRequestStats) { results <- stats }
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(*http.Request, *goproxy.ProxyCtx) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: &concurrentReadHTTPBody{
					remaining:     bodyBytes,
					firstReaders:  readers,
					firstReadDone: make(chan struct{}),
				},
			}, nil
		})
		return req, nil
	})
	proxy.OnResponse().DoFunc(func(resp *http.Response, _ *goproxy.ProxyCtx) *http.Response {
		var wg sync.WaitGroup
		wg.Add(readers)
		for i := 0; i < readers; i++ {
			go func() {
				defer wg.Done()
				if _, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
					t.Errorf("concurrent response read failed: %v", err)
				}
			}()
		}
		wg.Wait()
		return resp
	})

	proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://example.com/", nil))
	stats := awaitHTTPStats(t, results)
	if stats.BytesIn != bodyBytes || stats.BytesOut != 0 || stats.Error != nil {
		t.Fatalf("unexpected stats after concurrent reads: %+v", stats)
	}
}

func TestHTTPRequestCompleteWaitsForUpload(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	results := make(chan goproxy.HTTPRequestStats, 1)
	proxy.HTTPRequestCompleteHandler = func(_ *goproxy.ProxyCtx, stats goproxy.HTTPRequestStats) { results <- stats }
	var upload io.ReadCloser
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			upload = req.Body
			return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusOK, "reply"), nil
		})
		return req, nil
	})
	proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "http://example.com/", strings.NewReader("upload")))
	select {
	case <-results:
		t.Fatal("completion ran while upload was still open")
	default:
	}
	if _, err := io.Copy(ioutil.Discard, upload); err != nil {
		t.Fatal(err)
	}
	if err := upload.Close(); err != nil {
		t.Fatal(err)
	}
	stats := awaitHTTPStats(t, results)
	if stats.BytesOut != 6 || stats.BytesIn != 5 || stats.Error != nil {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestHTTPRequestCompleteIncludesResponseReadsWhileWaitingForUpload(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	results := make(chan goproxy.HTTPRequestStats, 1)
	proxy.HTTPRequestCompleteHandler = func(_ *goproxy.ProxyCtx, stats goproxy.HTTPRequestStats) { results <- stats }
	var upload io.ReadCloser
	var retainedResponse io.ReadCloser
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			upload = req.Body
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       ioutil.NopCloser(strings.NewReader("original response")),
			}, nil
		})
		return req, nil
	})
	proxy.OnResponse().DoFunc(func(resp *http.Response, _ *goproxy.ProxyCtx) *http.Response {
		retainedResponse = resp.Body
		resp.Body = ioutil.NopCloser(strings.NewReader("replacement"))
		return resp
	})

	proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "http://example.com/", strings.NewReader("upload")))
	select {
	case <-results:
		t.Fatal("completion ran while upload was still open")
	default:
	}
	if _, err := io.Copy(ioutil.Discard, retainedResponse); err != nil {
		t.Fatal(err)
	}
	if err := upload.Close(); err != nil {
		t.Fatal(err)
	}

	stats := awaitHTTPStats(t, results)
	if stats.BytesIn != int64(len("original response")) || stats.BytesOut != 0 || stats.Error != nil {
		t.Fatalf("unexpected stats after deferred response read: %+v", stats)
	}
}

type partialReadErrorHTTPBody struct {
	err      error
	returned bool
}

func (b *partialReadErrorHTTPBody) Read(p []byte) (int, error) {
	if b.returned {
		return 0, b.err
	}
	b.returned = true
	return copy(p, "response"), b.err
}

func (*partialReadErrorHTTPBody) Close() error { return nil }

func TestHTTPRequestCompleteIncludesPartialResponseReadErrorWhileWaitingForUpload(t *testing.T) {
	readErr := errors.New("response read failed")
	proxy := goproxy.NewProxyHttpServer()
	results := make(chan goproxy.HTTPRequestStats, 1)
	proxy.HTTPRequestCompleteHandler = func(_ *goproxy.ProxyCtx, stats goproxy.HTTPRequestStats) { results <- stats }
	var upload io.ReadCloser
	var retainedResponse io.ReadCloser
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			upload = req.Body
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       &partialReadErrorHTTPBody{err: readErr},
			}, nil
		})
		return req, nil
	})
	proxy.OnResponse().DoFunc(func(resp *http.Response, _ *goproxy.ProxyCtx) *http.Response {
		retainedResponse = resp.Body
		resp.Body = ioutil.NopCloser(strings.NewReader("replacement"))
		return resp
	})

	proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "http://example.com/", strings.NewReader("upload")))
	if _, err := retainedResponse.Read(make([]byte, len("response"))); err != readErr {
		t.Fatalf("retained response read error = %v, want %v", err, readErr)
	}
	if err := upload.Close(); err != nil {
		t.Fatal(err)
	}

	stats := awaitHTTPStats(t, results)
	if stats.BytesIn != int64(len("response")) || stats.BytesOut != 0 || stats.Error != readErr {
		t.Fatalf("unexpected stats after partial response read failure: %+v", stats)
	}
}

func TestHTTPRequestCompleteWaitsForStreamingResponse(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	results := make(chan goproxy.HTTPRequestStats, 1)
	proxy.HTTPRequestCompleteHandler = func(_ *goproxy.ProxyCtx, stats goproxy.HTTPRequestStats) { results <- stats }
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       reader,
			}, nil
		})
		return req, nil
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://example.com/", nil))
	}()
	if _, err := writer.Write([]byte("streamed")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-results:
		t.Fatal("completion ran before response EOF")
	default:
	}
	writer.Close()
	stats := awaitHTTPStats(t, results)
	if stats.BytesIn != 8 || stats.BytesOut != 0 || stats.Error != nil {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	<-done
}

type delayedHTTPUpload struct {
	started chan struct{}
	release chan struct{}
}

func (b *delayedHTTPUpload) Read(p []byte) (int, error) {
	close(b.started)
	<-b.release
	return copy(p, "end"), io.EOF
}

func (b *delayedHTTPUpload) Close() error { return nil }

func TestHTTPRequestCompleteWaitsForReadDuringClose(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	results := make(chan goproxy.HTTPRequestStats, 1)
	proxy.HTTPRequestCompleteHandler = func(_ *goproxy.ProxyCtx, stats goproxy.HTTPRequestStats) { results <- stats }
	body := &delayedHTTPUpload{started: make(chan struct{}), release: make(chan struct{})}
	var upload io.ReadCloser
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			upload = req.Body
			return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusOK, "reply"), nil
		})
		return req, nil
	})
	proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "http://example.com/", body))
	done := make(chan struct{})
	go func() {
		defer close(done)
		upload.Read(make([]byte, 3))
	}()
	<-body.started
	upload.Close()
	select {
	case <-results:
		t.Error("completion ran before the active upload read returned")
	default:
	}
	close(body.release)
	stats := awaitHTTPStats(t, results)
	if stats.BytesOut != 3 || stats.BytesIn != 5 || stats.Error != nil {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	<-done
}

func TestHTTPRequestCompletePooledConnection(t *testing.T) {
	addresses := make(chan string, 2)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		addresses <- req.RemoteAddr
		io.Copy(w, req.Body)
	}))
	defer backend.Close()
	proxy := goproxy.NewProxyHttpServer()
	defer proxy.Tr.CloseIdleConnections()
	results := make(chan goproxy.HTTPRequestStats, 2)
	proxy.HTTPRequestCompleteHandler = func(_ *goproxy.ProxyCtx, stats goproxy.HTTPRequestStats) { results <- stats }
	server := httptest.NewServer(proxy)
	defer server.Close()
	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, payload := range []string{"one", "second request"} {
		resp, err := client.Post(backend.URL, "text/plain", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(body) != payload {
			t.Fatalf("unexpected reply %q, error %v", body, err)
		}
		stats := awaitHTTPStats(t, results)
		if stats.BytesIn != int64(len(payload)) || stats.BytesOut != int64(len(payload)) || stats.Error != nil {
			t.Fatalf("unexpected stats: %+v", stats)
		}
	}
	if first, second := <-addresses, <-addresses; first != second {
		t.Fatalf("test did not reuse the outbound connection: %s != %s", first, second)
	}
}

func TestHTTPRequestCompletePreservesRequestTrailers(t *testing.T) {
	trailers := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		io.Copy(ioutil.Discard, req.Body)
		trailers <- req.Trailer.Get("Checksum")
	}))
	defer backend.Close()
	proxy := goproxy.NewProxyHttpServer()
	defer proxy.Tr.CloseIdleConnections()
	results := make(chan goproxy.HTTPRequestStats, 1)
	proxy.HTTPRequestCompleteHandler = func(_ *goproxy.ProxyCtx, stats goproxy.HTTPRequestStats) { results <- stats }
	server := httptest.NewServer(proxy)
	defer server.Close()
	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequest("POST", backend.URL, strings.NewReader("upload"))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	req.Trailer = http.Header{"Checksum": []string{"original"}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()
	if trailer := <-trailers; trailer != "original" {
		t.Fatalf("request trailer was lost: %q", trailer)
	}
	stats := awaitHTTPStats(t, results)
	if stats.BytesOut != 6 || stats.BytesIn != 0 || stats.Error != nil {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}
