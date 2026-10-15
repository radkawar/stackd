package desync

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func nativeExecutable(t *testing.T) string {
	t.Helper()
	executable := os.Getenv("STACKD_HTTP_DESYNC_GUARDIAN")
	if executable == "" {
		t.Skip("install the pinned native C adapter and set STACKD_HTTP_DESYNC_GUARDIAN to its absolute path")
	}
	return executable
}

func nativeClassifier(t *testing.T) *Classifier {
	t.Helper()
	classifier, err := New(t.Context(), nativeExecutable(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = classifier.Close() })
	return classifier
}

func TestNativeGuardianOriginalBytes(t *testing.T) {
	classifier := nativeClassifier(t)
	cases := []struct {
		name, raw string
		tier      Tier
		reason    uint32
	}{
		{"compliant", "POST /raw HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 0\r\n\r\n", Compliant, 0},
		// docs/README.md:55-57: original LF-only line endings are Acceptable.
		{"lf-before-go-normalization", "POST /raw HTTP/1.1\nHost: alb.invalid\nContent-Length: 0\n\n", Acceptable, 20},
		// tests/acceptable.yaml:79-89.
		{"get-zero-body", "GET /raw HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 0\r\n\r\n", Acceptable, 10},
		// tests/ambiguous.yaml and docs/README.md:111-125. Go deduplicates this.
		{"duplicate-original-length", "POST /raw HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n", Ambiguous, 13},
		// misc/demo-c/analyze_raw_request.c:30-54, same real raw C entrypoint.
		{"both-te-cl", "POST /raw HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 9\r\nTransfer-Encoding: chunked\r\n\r\n", Ambiguous, 18},
		// tests/ambiguous.yaml:7-19; spelling must not be trimmed by Go first.
		{"suspicious-original-name", "POST /raw HTTP/1.1\r\nHost: alb.invalid\r\nTransfer-Encoding : chunked\r\n\r\n", Ambiguous, 2},
		// tests/severe.yaml:16-29.
		{"different-original-lengths", "POST /raw HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", Severe, 12},
		// tests/severe.yaml:90-100.
		{"bad-original-transfer-encoding", "POST /raw HTTP/1.1\r\nHost: alb.invalid\r\nTransfer-Encoding: xchunked\r\n\r\n", Severe, 17},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := classifier.Classify(t.Context(), []byte(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if verdict.Tier != tc.tier || verdict.Reason != tc.reason {
				t.Fatalf("real native verdict=%+v, want tier=%d reason=%d", verdict, tc.tier, tc.reason)
			}
		})
	}
}

func TestNativeGuardianBoundsAndUnavailability(t *testing.T) {
	classifier := nativeClassifier(t)
	for _, raw := range [][]byte{nil, []byte(strings.Repeat("X", MaxHeaderBytes+1))} {
		if _, err := classifier.Classify(t.Context(), raw); err == nil {
			t.Fatal("out-of-bound native call succeeded")
		}
	}
	if err := classifier.Health(t.Context()); err != nil {
		t.Fatal("bad caller bounds poisoned a healthy native worker", err)
	}
	if err := classifier.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if _, err := classifier.Classify(t.Context(), []byte("GET / HTTP/1.1\r\nHost: alb.invalid\r\n\r\n")); err == nil {
		t.Fatal("dead native library worker produced a successful classification")
	}
	if err := classifier.Health(t.Context()); err == nil {
		t.Fatal("dead native library worker claimed readiness")
	}
}

func TestNativeAdapterRejectsInvalidFrames(t *testing.T) {
	executable := nativeExecutable(t)
	for _, length := range []uint32{0, MaxHeaderBytes + 1} {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		cmd := exec.CommandContext(ctx, executable)
		input, err := cmd.StdinPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		output, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		var hello [len(greeting)]byte
		if _, err := io.ReadFull(output, hello[:]); err != nil || string(hello[:]) != greeting {
			cancel()
			_ = cmd.Wait()
			t.Fatalf("real adapter greeting=%q err=%v", hello, err)
		}
		var frame [4]byte
		binary.BigEndian.PutUint32(frame[:], length)
		if err := writeFull(input, frame[:]); err != nil {
			cancel()
			_ = cmd.Wait()
			t.Fatal(err)
		}
		_ = input.Close()
		if err := cmd.Wait(); err == nil || ctx.Err() != nil {
			cancel()
			t.Fatalf("invalid frame %d did not fail closed promptly: %v", length, err)
		}
		cancel()
	}
}

func TestNativeGuardianInitializationContextAndReapedClose(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	classifier, err := New(ctx, nativeExecutable(t))
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = classifier.Close() })
	if err := classifier.Health(t.Context()); err != nil {
		t.Fatal("initialization context cancellation killed the owned worker", err)
	}
	if err := classifier.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-classifier.wait:
	default:
		t.Fatal("Close returned before the real native process was reaped")
	}
	if err := classifier.Close(); err != nil {
		t.Fatal("repeated Close was not idempotent", err)
	}
	if err := classifier.Health(t.Context()); err == nil {
		t.Fatal("closed and reaped worker reported readiness")
	}
}
