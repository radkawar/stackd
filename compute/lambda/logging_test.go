package lambda

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRuntimeLoggingFramesPreserveRecordsAndFilterSeverity(t *testing.T) {
	var output bytes.Buffer
	manager := newTelemetryManager(t.Context(), nil, &output)
	defer manager.Close()
	manager.logging = LoggingConfig{Format: "JSON", ApplicationLevel: "ERROR", SystemLevel: "WARN"}
	stream := &runtimeLogFrames{manager: manager}
	var wire []byte
	for _, item := range []struct {
		kind uint32
		body string
	}{
		{0xa55a000e, `{"level":"INFO","message":"filtered"}`},
		{0xa55a0016, `{"level":"ERROR","message":"retained λ"}`},
	} {
		var header [16]byte
		binary.BigEndian.PutUint32(header[:4], item.kind)
		binary.BigEndian.PutUint32(header[4:8], uint32(len(item.body)))
		binary.BigEndian.PutUint64(header[8:], uint64(time.Now().UnixMicro()))
		wire = append(wire, header[:]...)
		wire = append(wire, item.body...)
	}
	// Docker attach may split every header and multibyte UTF-8 sequence.
	for _, b := range wire {
		if _, err := stream.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "{\"level\":\"ERROR\",\"message\":\"retained λ\"}\n" {
		t.Fatalf("framed output: %q", got)
	}
	// Ordinary stdout is separately owned, even if it resembles platform events.
	raw := manager.Output("function", "runtime")
	for _, line := range []string{"ordinary INFO\n", `{"level":"invalid","message":"filtered"}` + "\n", `{"level":"ERROR","message":"no timestamp"}` + "\n"} {
		if _, err := raw.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Contains(output.Bytes(), []byte("filtered")) || !bytes.Contains(output.Bytes(), []byte("no timestamp")) || bytes.Contains(output.Bytes(), []byte("ordinary")) {
		t.Fatalf("raw filter: %q", output.String())
	}
}

func TestSystemLoggingThresholdsKeepNativeEnvelopes(t *testing.T) {
	at := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	for _, level := range []string{"DEBUG", "INFO", "WARN"} {
		t.Run(level, func(t *testing.T) {
			var output bytes.Buffer
			manager := newTelemetryManager(t.Context(), nil, &output)
			defer manager.Close()
			manager.logging = LoggingConfig{Format: "JSON", SystemLevel: level}
			manager.Emit(at, "platform.start", map[string]string{"requestId": "request"})
			manager.Emit(at, "platform.runtimeDone", map[string]string{"requestId": "request", "status": "success"})
			manager.Emit(at, "platform.report", map[string]any{"requestId": "failed", "status": "error", "metrics": map[string]int{"durationMs": 1}})
			manager.Emit(at, "platform.end", map[string]string{"requestId": "request"})
			seen := map[string]bool{}
			for _, line := range bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'}) {
				var event struct {
					Time   string         `json:"time"`
					Type   string         `json:"type"`
					Record map[string]any `json:"record"`
				}
				if err := json.Unmarshal(line, &event); err != nil {
					t.Fatal(err)
				}
				if event.Time != at.Format(time.RFC3339Nano) || event.Record["requestId"] == nil {
					t.Fatalf("invalid system envelope: %s", line)
				}
				seen[event.Type] = true
			}
			if seen["platform.start"] != (level != "WARN") || seen["platform.runtimeDone"] != (level == "DEBUG") || !seen["platform.report"] || seen["platform.end"] {
				t.Fatalf("%s event filtering: %v", level, seen)
			}
		})
	}
}

// Reconstruct the overflowing customer record from the captured handler, retaining
// AWS's actual following records. This catches byte/rune truncation and JSON's
// whole-record eviction without pinning generated request IDs or durations.
func TestInvocationTailNativeByteBoundaries(t *testing.T) {
	var fixture struct {
		Cases []struct {
			Label     string `json:"label"`
			LogResult string
		}
	}
	data, err := os.ReadFile("../../testdata/aws/lambda/invocation_tails.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"python3.12-Text-None-unicode", "python3.12-Text-None-unicode-pad", "python3.12-JSON-DEBUG-unicode"} {
		t.Run(label, func(t *testing.T) {
			var captured []byte
			for _, row := range fixture.Cases {
				if row.Label == label {
					captured, err = base64.StdEncoding.DecodeString(row.LogResult)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if len(captured) == 0 {
				t.Fatal("missing native observation")
			}
			var output bytes.Buffer
			manager := newTelemetryManager(t.Context(), nil, &output)
			defer manager.Close()
			format := "Text"
			following := captured[bytes.IndexByte(captured, '\n')+1:]
			if strings.Contains(label, "-JSON-") {
				format = "JSON"
				following = captured
			}
			manager.logging.Format = format
			record := strings.Repeat("😀", 2200)
			if strings.HasSuffix(label, "-pad") {
				record += "é"
			}
			record += "\n"
			manager.BeginInvocation()
			manager.forward([]byte("discarded earlier record\n"), true, true)
			manager.forward([]byte(record), true, true)
			for _, line := range bytes.SplitAfter(following, []byte{'\n'}) {
				manager.forward(line, true, true)
			}
			if actual := manager.EndInvocation(); !bytes.Equal(actual, captured) {
				t.Fatalf("native tail differs: got %d bytes, want %d\n%q\n%q", len(actual), len(captured), actual, captured)
			}
			if !strings.Contains(output.String(), record) {
				t.Fatal("Invoke-tail truncation removed full-destination output")
			}
		})
	}
}

func TestInvocationTailIsIndependentOfFilteringAndPriorInvocations(t *testing.T) {
	var output bytes.Buffer
	manager := newTelemetryManager(t.Context(), nil, &output)
	defer manager.Close()
	manager.logging = LoggingConfig{Format: "JSON", ApplicationLevel: "ERROR", SystemLevel: "WARN"}
	stream := manager.Output("function", "runtime")
	manager.BeginInvocation()
	if _, err := io.WriteString(stream, "first invocation\n"); err != nil {
		t.Fatal(err)
	}
	manager.Emit(time.Now(), "platform.start", map[string]string{"requestId": "first"})
	first := manager.EndInvocation()
	if !bytes.Contains(first, []byte("first invocation")) || !bytes.Contains(first, []byte("platform.start")) || output.Len() != 0 {
		t.Fatalf("backend filtering changed Tail: tail=%s output=%s", first, output.Bytes())
	}
	if _, err := io.WriteString(stream, "idle output\n"); err != nil {
		t.Fatal(err)
	}
	manager.BeginInvocation()
	if _, err := io.WriteString(stream, "{\"level\":\"ERROR\",\"message\":\"second invocation\"}\n"); err != nil {
		t.Fatal(err)
	}
	second := manager.EndInvocation()
	if bytes.Contains(second, []byte("first")) || bytes.Contains(second, []byte("idle")) || !bytes.Contains(second, []byte("second invocation")) || !bytes.Contains(output.Bytes(), []byte("second invocation")) {
		t.Fatalf("invocation ownership: tail=%s output=%s", second, output.Bytes())
	}
}
