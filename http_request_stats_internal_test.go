package goproxy

import (
	"errors"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type statsWriterToBody struct {
	data       []byte
	writeToErr error
	started    chan struct{}
	release    chan struct{}
}

func (*statsWriterToBody) Read([]byte) (int, error) { return 0, io.EOF }

func (*statsWriterToBody) Close() error { return nil }

func (b *statsWriterToBody) WriteTo(w io.Writer) (int64, error) {
	if b.started != nil {
		close(b.started)
	}
	if b.release != nil {
		<-b.release
	}
	n, err := w.Write(b.data)
	if err == nil {
		err = b.writeToErr
	}
	return int64(n), err
}

type statsTestWriter struct {
	maxBytes int
	err      error
}

type statsPlainBody struct{ io.Reader }

func (statsPlainBody) Close() error { return nil }

func (w statsTestWriter) Write(p []byte) (int, error) {
	n := len(p)
	if w.maxBytes >= 0 && n > w.maxBytes {
		n = w.maxBytes
	}
	return n, w.err
}

func TestHTTPRequestStatsRequestWriterToIsConditional(t *testing.T) {
	completion := &httpRequestCompletion{}
	writerToBody := &statsWriterToBody{data: []byte("writer-to")}
	if _, ok := completion.requestBody(writerToBody).(io.WriterTo); !ok {
		t.Fatal("request body lost its underlying WriterTo")
	}
	plainBody := statsPlainBody{Reader: strings.NewReader("plain")}
	if _, ok := completion.requestBody(plainBody).(io.WriterTo); ok {
		t.Fatal("ordinary request body unexpectedly exposes WriterTo")
	}
}

func TestHTTPRequestStatsRequestWriterToCountsReturnedBytes(t *testing.T) {
	outputErr := errors.New("request destination failed")
	result := make(chan HTTPRequestStats, 1)
	completion := &httpRequestCompletion{handler: func(_ *ProxyCtx, stats HTTPRequestStats) { result <- stats }}
	body := &statsWriterToBody{data: []byte("abcdef")}
	wrapped := completion.requestBody(body)
	completion.finish(nil, nil)

	n, err := wrapped.(io.WriterTo).WriteTo(statsTestWriter{maxBytes: 2, err: outputErr})
	if n != 2 || err != outputErr {
		t.Fatalf("WriteTo=(%d,%v), want (2,%v)", n, err, outputErr)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	stats := <-result
	if stats.BytesOut != 2 || stats.Error != outputErr {
		t.Fatalf("unexpected stats after request transfer failure: %+v", stats)
	}
	select {
	case <-result:
		t.Fatal("completion callback ran more than once")
	default:
	}
}

func TestHTTPRequestStatsRequestWriterToRecordsSourceFailure(t *testing.T) {
	sourceErr := errors.New("request source failed")
	result := make(chan HTTPRequestStats, 1)
	completion := &httpRequestCompletion{handler: func(_ *ProxyCtx, stats HTTPRequestStats) { result <- stats }}
	body := &statsWriterToBody{data: []byte("abcdef"), writeToErr: sourceErr}
	wrapped := completion.requestBody(body)
	completion.finish(nil, nil)

	n, err := wrapped.(io.WriterTo).WriteTo(statsTestWriter{maxBytes: -1})
	if n != 6 || err != sourceErr {
		t.Fatalf("WriteTo=(%d,%v), want (6,%v)", n, err, sourceErr)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	stats := <-result
	if stats.BytesOut != 6 || stats.Error != sourceErr {
		t.Fatalf("unexpected stats after source transfer failure: %+v", stats)
	}
}

func TestHTTPRequestStatsUploadWriterToWaitsForActiveWriteDuringClose(t *testing.T) {
	result := make(chan HTTPRequestStats, 2)
	completion := &httpRequestCompletion{handler: func(_ *ProxyCtx, stats HTTPRequestStats) { result <- stats }}
	body := &statsWriterToBody{
		data:    []byte("abcdef"),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	wrapped := completion.requestBody(body)
	completion.finish(nil, nil)

	writeDone := make(chan error, 1)
	go func() {
		n, err := wrapped.(io.WriterTo).WriteTo(statsTestWriter{maxBytes: -1})
		if n != 6 || err != nil {
			writeDone <- errors.New("unexpected WriterTo result")
			return
		}
		writeDone <- nil
	}()
	<-body.started
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case stats := <-result:
		t.Fatalf("completion ran before active WriterTo returned: %+v", stats)
	default:
	}
	close(body.release)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	stats := <-result
	if stats.BytesOut != 6 || stats.Error != nil {
		t.Fatalf("unexpected stats after active WriterTo: %+v", stats)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case stats := <-result:
		t.Fatalf("completion callback ran more than once: %+v", stats)
	default:
	}
}

func TestHTTPResponseWriterToCountsReturnedBytes(t *testing.T) {
	completion := &httpRequestCompletion{}
	body := &statsWriterToBody{data: []byte("response")}
	counter := &httpResponseBodyCounter{ReadCloser: body, completion: completion}
	wrapped := &httpResponseBodyWriterTo{httpResponseBodyCounter: counter, writerTo: body}
	if _, err := wrapped.WriteTo(statsTestWriter{maxBytes: -1}); err != nil {
		t.Fatal(err)
	}
	result := make(chan HTTPRequestStats, 1)
	completion.handler = func(_ *ProxyCtx, stats HTTPRequestStats) { result <- stats }
	completion.finish(nil, counter)
	stats := <-result
	if stats.BytesIn != int64(len("response")) || stats.Error != nil {
		t.Fatalf("unexpected response WriterTo stats: %+v", stats)
	}
}

type gatedPartialErrorBody struct {
	readStarted chan struct{}
	allowRead   chan struct{}
	err         error
}

func (b *gatedPartialErrorBody) Read(p []byte) (int, error) {
	close(b.readStarted)
	<-b.allowRead
	return copy(p, "response"), b.err
}

func (*gatedPartialErrorBody) Close() error { return nil }

type closeStartedBody struct {
	closeStarted chan struct{}
}

func (*closeStartedBody) Read([]byte) (int, error) { return 0, io.EOF }

func (b *closeStartedBody) Close() error {
	close(b.closeStarted)
	return nil
}

func TestHTTPResponseReadErrorAndPartialBytesPublishTogether(t *testing.T) {
	readErr := errors.New("response read failed")
	result := make(chan HTTPRequestStats, 1)
	completion := &httpRequestCompletion{
		handler: func(_ *ProxyCtx, stats HTTPRequestStats) { result <- stats },
		ctx:     &ProxyCtx{},
	}
	uploadClosed := make(chan struct{})
	upload := completion.requestBody(&closeStartedBody{closeStarted: uploadClosed})
	readStarted := make(chan struct{})
	allowRead := make(chan struct{})
	responseBody := &httpResponseBodyCounter{
		ReadCloser: &gatedPartialErrorBody{
			readStarted: readStarted,
			allowRead:   allowRead,
			err:         readErr,
		},
		completion: completion,
	}
	completion.finish(nil, responseBody)

	completion.mu.Lock()
	closeDone := make(chan struct{})
	go func() {
		_ = upload.Close()
		close(closeDone)
	}()
	select {
	case <-uploadClosed:
	case <-time.After(time.Second):
		completion.mu.Unlock()
		t.Fatal("upload close did not start")
	}

	readDone := make(chan struct{})
	go func() {
		_, _ = responseBody.Read(make([]byte, len("response")))
		close(readDone)
	}()
	select {
	case <-readStarted:
	case <-time.After(time.Second):
		completion.mu.Unlock()
		t.Fatal("response read did not start")
	}
	close(allowRead)

	// Give the read goroutine a chance to publish while completion is held.
	// A non-EOF partial read must wait for this lock before publishing either
	// its bytes or its error.
	for i := 0; i < 1000; i++ {
		if got := atomic.LoadInt64(&responseBody.bytesRead); got != 0 {
			completion.mu.Unlock()
			t.Fatalf("partial bytes published before acquiring completion lock: %d", got)
		}
		runtime.Gosched()
	}
	completion.mu.Unlock()

	var stats HTTPRequestStats
	select {
	case stats = <-result:
	case <-time.After(time.Second):
		t.Fatal("completion callback did not run")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("upload close did not finish")
	}
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("response read did not finish")
	}

	if (stats.BytesIn == 0 && stats.Error != nil) || (stats.BytesIn != 0 && (stats.BytesIn != int64(len("response")) || stats.Error != readErr)) {
		t.Fatalf("partial bytes and error were not reported together: %+v", stats)
	}
}
