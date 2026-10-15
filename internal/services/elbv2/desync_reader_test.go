package elbv2

import (
	"bufio"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestNativePreParserPreservesOriginalChunkWire(t *testing.T) {
	classifier := installedDesyncClassifier(t)
	client, raw := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	conn := newDesyncConnection(raw, classifier, nil)
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	first := "POST /wire HTTP/1.1\r\nHost: alb.invalid\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n3;token=original\r\none\r\n2\r\n!!\r\n0\r\nX-Trailer: untouched\r\n\r\n"
	second := "POST /next HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 2\r\n\r\nOK"
	written := make(chan error, 1)
	go func() {
		_, err := io.WriteString(client, first+second)
		written <- err
	}()
	wire := make([]byte, len(first))
	if _, err := io.ReadFull(conn, wire); err != nil || string(wire) != first {
		t.Fatalf("chunked wire changed before net/http: %q err=%v", wire, err)
	}
	// A net/http background read can be aborted at the boundary without consuming
	// or exposing the pipelined next request. Then StateIdle releases that request.
	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	var byteBuffer [1]byte
	if n, err := conn.Read(byteBuffer[:]); n != 0 || !os.IsTimeout(err) {
		t.Fatalf("boundary deadline did not interrupt read: n=%d err=%v", n, err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn.completeRequest(false)
	wire = make([]byte, len(second))
	if _, err := io.ReadFull(conn, wire); err != nil || string(wire) != second {
		t.Fatalf("pipeline wire changed before net/http: %q err=%v", wire, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestNativePreParserRetainsDisconnectDetection(t *testing.T) {
	classifier := installedDesyncClassifier(t)
	client, raw := net.Pipe()
	conn := newDesyncConnection(raw, classifier, nil)
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	header := "GET /disconnect HTTP/1.1\r\nHost: alb.invalid\r\n\r\n"
	go func() {
		_, _ = io.WriteString(client, header)
		_ = client.Close()
	}()
	wire := make([]byte, len(header))
	if _, err := io.ReadFull(conn, wire); err != nil {
		t.Fatal(err)
	}
	var byteBuffer [1]byte
	if n, err := conn.Read(byteBuffer[:]); n != 0 || err != io.EOF {
		t.Fatalf("active response lost client disconnect detection: n=%d err=%v", n, err)
	}
}

func TestNativeDesyncAcceptableKeepsConnectionReusable(t *testing.T) {
	h := nativeDesyncProxy(t, false)
	conn := h.dial(t)
	raw := "POST /acceptable HTTP/1.1\nHost: alb.invalid\nContent-Length: 0\n\nPOST /next HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 0\r\n\r\n"
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	readDesyncResponse(t, reader, 200, "target:/acceptable::", false)
	readDesyncResponse(t, reader, 200, "target:/next::", false)
}
