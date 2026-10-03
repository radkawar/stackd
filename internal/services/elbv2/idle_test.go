package elbv2

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestIdleTimeoutUpdatesExistingConnection(t *testing.T) {
	policy := newConnectionIdlePolicy(time.Hour)
	local, remote := net.Pipe()
	defer remote.Close()
	conn := policy.wrap(local)
	defer conn.Close()
	done := make(chan error, 1)
	go func() { var b [1]byte; _, err := conn.Read(b[:]); done <- err }()
	policy.setTimeout(20 * time.Millisecond)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("idle socket returned data instead of closing")
		}
	case <-time.After(time.Second):
		t.Fatal("updated timeout did not close existing socket")
	}
}
func TestIdleTimeoutTracksStreamingBytesInBothDirections(t *testing.T) {
	policy := newConnectionIdlePolicy(150 * time.Millisecond)
	local, remote := net.Pipe()
	defer remote.Close()
	conn := policy.wrap(local)
	defer conn.Close()
	// Continuous body traffic must outlive the interval even without another
	// HTTP request or response header. Exercise both upload and download bytes.
	for i := range 8 {
		var from, to net.Conn
		if i%2 == 0 {
			from, to = conn, remote
		} else {
			from, to = remote, conn
		}
		done := make(chan error, 1)
		go func() { _, err := from.Write([]byte{'x'}); done <- err }()
		var b [1]byte
		if _, err := io.ReadFull(to, b[:]); err != nil {
			t.Fatal("active stream closed", err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if b[0] != 'x' {
			t.Fatal("stream byte changed")
		}
		time.Sleep(40 * time.Millisecond)
	}
	if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err := remote.Read(b[:])
	if err != io.EOF {
		t.Fatalf("stalled response body must close, got %v", err)
	}
}
