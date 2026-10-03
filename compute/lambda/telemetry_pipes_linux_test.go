package lambda

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsumerPipeDrainsInvocationBytesWithoutClosingWarmStream(t *testing.T) {
	var delivered bytes.Buffer
	manager := newTelemetryManager(t.Context(), nil, &delivered)
	defer manager.Close()
	path := filepath.Join(t.TempDir(), "stdout")
	pipe, err := newTelemetryPipe(path, manager.Output("function", "runtime").(io.WriteCloser))
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.close()
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	manager.BeginInvocation()
	first := strings.Repeat("λ", 100000) + "\nfirst-final\n"
	if _, err := io.WriteString(writer, first); err != nil {
		t.Fatal(err)
	}
	if err := pipe.drain(); err != nil {
		t.Fatal(err)
	}
	if tail := manager.EndInvocation(); !bytes.HasSuffix(tail, []byte("first-final\n")) || bytes.Contains(tail, []byte("second")) {
		t.Fatalf("first invocation did not own final output: %q", tail)
	}
	if delivered.String() != first {
		t.Fatal("bounded Invoke tail truncated full log delivery")
	}
	manager.BeginInvocation()
	if _, err := io.WriteString(writer, "second-final\npartial "); err != nil {
		t.Fatal(err)
	}
	if err := pipe.drain(); err != nil {
		t.Fatal(err)
	}
	if tail := manager.EndInvocation(); string(tail) != "second-final\n" {
		t.Fatalf("warm tail contains previous bytes or unfinished line: %q", tail)
	}
	manager.BeginInvocation()
	if _, err := io.WriteString(writer, "completed\n"); err != nil {
		t.Fatal(err)
	}
	if err := pipe.drain(); err != nil {
		t.Fatal(err)
	}
	if tail := manager.EndInvocation(); string(tail) != "partial completed\n" {
		t.Fatalf("native unfinished-line framing was lost: %q", tail)
	}
}
