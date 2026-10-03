package mq

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	service "stackd/internal/services/mq"
)

func nativeLogTestLine(t *testing.T, stamp, message string) []byte {
	t.Helper()
	line, err := json.Marshal(struct {
		Timestamp string `json:"timestamp"`
		Message   string `json:"message"`
	}{stamp, message})
	if err != nil {
		t.Fatal(err)
	}
	return append(line, '\n')
}

func TestNativeLogPayloadAndExactCursor(t *testing.T) {
	stamp := "2026-09-29T12:34:56.123Z"
	message := "INFO | user sent body=[first\nsecond 雪\r\n\"quoted\"\\value]\n\tat native.frame"
	line := nativeLogTestLine(t, stamp, message)
	data := append(append([]byte(nil), line...), []byte(`{"timestamp":"2026-09-29`)...)
	records, consumed, err := parseNativeLogs(data, int64(len(data)), "ACTIVEMQ")
	if err != nil {
		t.Fatal(err)
	}
	wantTime, _ := time.Parse(time.RFC3339Nano, stamp)
	if len(records) != 1 || records[0].Message != message || !records[0].Timestamp.Equal(wantTime) || consumed != len(line) {
		t.Fatalf("native payload/cursor changed: records=%+v consumed=%d want=%d", records, consumed, len(line))
	}
	incomplete := data[len(line):]
	records, consumed, err = parseNativeLogs(incomplete, int64(len(incomplete)), "ACTIVEMQ")
	if err != nil || len(records) != 0 || consumed != 0 {
		t.Fatalf("partial event acknowledged: %+v %d %v", records, consumed, err)
	}
}

func TestNativeLogRequestByteBoundary(t *testing.T) {
	// Account for UTF-8 bytes rather than runes, and the required per-event
	// overhead. The second record must remain for the following request.
	message := strings.Repeat("雪", (mqLogBatchBytes-26)/3)
	line := nativeLogTestLine(t, "2026-09-29T12:34:56.123Z", message)
	second := nativeLogTestLine(t, "2026-09-29T12:34:57.123Z", "next")
	data := append(append([]byte(nil), line...), second...)
	records, consumed, err := parseNativeLogs(data, int64(len(data)), "ACTIVEMQ")
	if err != nil || len(records) != 1 || consumed != len(line) || records[0].Message != message {
		t.Fatalf("request byte boundary: events=%d consumed=%d err=%v", len(records), consumed, err)
	}
	records, consumed, err = parseNativeLogs(data[consumed:], int64(len(second)), "ACTIVEMQ")
	if err != nil || len(records) != 1 || records[0].Message != "next" || consumed != len(second) {
		t.Fatalf("following request lost record: %+v %d %v", records, consumed, err)
	}
}

func TestNativeLogInvalidRecordsAreNotAcknowledged(t *testing.T) {
	cases := map[string][]byte{
		"invalid JSON":      []byte("not a native event\n"),
		"invalid timestamp": nativeLogTestLine(t, "yesterday", "message"),
		"empty message":     nativeLogTestLine(t, "2026-09-29T12:34:56.123Z", ""),
		"oversized message": nativeLogTestLine(t, "2026-09-29T12:34:56.123Z", strings.Repeat("x", mqLogBatchBytes-25)),
		"invalid UTF8":      append([]byte(`{"timestamp":"2026-09-29T12:34:56.123Z","message":"`), 0xff, '"', '}', '\n'),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			records, consumed, err := parseNativeLogs(data, int64(len(data)), "ACTIVEMQ")
			if err == nil || consumed != 0 || len(records) != 0 {
				t.Fatalf("invalid native event acknowledged: %+v %d %v", records, consumed, err)
			}
		})
	}
}

func TestNativeLogRequestTimeSpan(t *testing.T) {
	first := nativeLogTestLine(t, "2026-09-27T12:34:56.123Z", "retained before downtime")
	second := nativeLogTestLine(t, "2026-09-29T12:34:56.123Z", "native restart")
	data := append(append([]byte(nil), first...), second...)
	records, consumed, err := parseNativeLogs(data, int64(len(data)), "ACTIVEMQ")
	if err != nil || len(records) != 1 || records[0].Message != "retained before downtime" || consumed != len(first) {
		t.Fatalf("request crossed 24-hour span: %+v %d %v", records, consumed, err)
	}
}

func TestNativeLogEventLimit(t *testing.T) {
	line := nativeLogTestLine(t, "2026-09-29T12:34:56.123Z", "event")
	data := []byte(strings.Repeat(string(line), mqLogBatchEvents+1))
	records, consumed, err := parseNativeLogs(data, int64(len(data)), "ACTIVEMQ")
	if err != nil || len(records) != mqLogBatchEvents || consumed != mqLogBatchEvents*len(line) {
		t.Fatalf("event limit lost native cursor: events=%d consumed=%d err=%v", len(records), consumed, err)
	}
}

func TestRabbitNativeLogPayloadAndTimestamp(t *testing.T) {
	// Native rabbit_logger_json_fmt uses time/msg, not ActiveMQ's fields.
	line := []byte("{\"time\":\"2026-09-29T14:34:56.123456+02:00\",\"level\":\"error\",\"msg\":\"channel error: 雪\\nsecond\\t\\\"quoted\\\"\",\"pid\":\"<0.1.0>\"}\n")
	data := append(append([]byte(nil), line...), []byte(`{"time":"2026-09-29`)...)
	records, consumed, err := parseNativeLogs(data, int64(len(data)), "RABBITMQ")
	wantTime := time.Date(2026, 9, 29, 12, 34, 56, 123456000, time.UTC)
	if err != nil || len(records) != 1 || consumed != len(line) || records[0].Message != "channel error: 雪\nsecond\t\"quoted\"" || !records[0].Timestamp.Equal(wantTime) {
		t.Fatalf("RabbitMQ native event changed: records=%+v consumed=%d err=%v", records, consumed, err)
	}
	records, consumed, err = parseNativeLogs(data[consumed:], int64(len(data)-consumed), "RABBITMQ")
	if err != nil || consumed != 0 || len(records) != 0 {
		t.Fatalf("partial RabbitMQ event acknowledged: records=%+v consumed=%d err=%v", records, consumed, err)
	}
	for _, invalid := range [][]byte{
		nativeLogTestLine(t, "2026-09-29T12:34:56.123Z", "not the RabbitMQ encoding"),
		[]byte("{\"time\":\"2026-09-29 12:34:56.123456+00:00\",\"msg\":\"wrong time format\"}\n"),
		[]byte("{\"time\":\"2026-09-29T12:34:56.123456Z\",\"msg\":\"\"}\n"),
	} {
		records, consumed, err = parseNativeLogs(invalid, int64(len(invalid)), "RABBITMQ")
		if err == nil || consumed != 0 || len(records) != 0 {
			t.Fatalf("invalid RabbitMQ event acknowledged: records=%+v consumed=%d err=%v", records, consumed, err)
		}
	}
}

func TestRabbitNativeLogArchiveOrderAndGuards(t *testing.T) {
	layout, err := logLayout("RABBITMQ", service.GeneralLog)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logs := filepath.Join(dir, "stackd-logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	list := func() ([]byte, error) {
		return exec.Command("sh", "-c", nativeLogListScript, "test", dir, layout.file, layout.archives).CombinedOutput()
	}
	for index := range 7 {
		if err := os.WriteFile(filepath.Join(logs, layout.file+"."+strconv.Itoa(index)), []byte("retained\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	current := filepath.Join(logs, layout.file)
	if err := os.WriteFile(current, []byte("native event\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := list()
	if err != nil {
		t.Fatalf("list archives: %v: %s", err, out)
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) != 8 {
		t.Fatalf("missing retained archive: %s", out)
	}
	for index, line := range lines {
		want := layout.file
		if index < 7 {
			want += "." + strconv.Itoa(6-index)
		}
		if strings.Split(line, "|")[0] != want {
			t.Fatalf("archive delivery order changed: %s", out)
		}
	}
	metadata := strings.Split(lines[7], "|")
	read := func() ([]byte, error) {
		return exec.Command("sh", "-c", nativeLogReadScript, "test", layout.file, metadata[1], "0", metadata[2], metadata[2], dir).CombinedOutput()
	}
	if out, err = read(); err != nil || string(out) != "native event\n" {
		t.Fatalf("read current event: %v: %q", err, out)
	}
	if err = os.Truncate(current, 0); err != nil {
		t.Fatal(err)
	}
	if out, err = read(); err == nil {
		t.Fatalf("concurrent truncation passed stability guard: %q", out)
	}
	if err = os.WriteFile(current, []byte("native event\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// A retained cursor must follow inode identity across native rename,
	// while a replacement at its previous name must fail the read guard.
	if err = os.Rename(current, filepath.Join(logs, layout.file+".0")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(current, []byte("replacement event\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err = read(); err == nil {
		t.Fatalf("replacement passed native identity guard: %q", out)
	}
	out, err = list()
	if err != nil {
		t.Fatalf("list after native rename: %v: %s", err, out)
	}
	lines = strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	retained := strings.Split(lines[6], "|")
	if retained[0] != layout.file+".0" || retained[1] != metadata[1] {
		t.Fatalf("native identity did not follow rotation: %s", out)
	}
	out, err = exec.Command("sh", "-c", nativeLogReadScript, "test", retained[0], metadata[1], "0", metadata[2], metadata[2], dir).CombinedOutput()
	if err != nil || string(out) != "native event\n" {
		t.Fatalf("retained cursor cannot read rotated source: %v: %q", err, out)
	}
	if err = os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(logs, layout.file+".0"), current); err != nil {
		t.Fatal(err)
	}
	if out, err = list(); err == nil {
		t.Fatalf("symlink source accepted: %q", out)
	}
	if out, err = read(); err == nil {
		t.Fatalf("symlink read accepted: %q", out)
	}
	if err = os.Rename(logs, filepath.Join(dir, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(dir, "elsewhere"), logs); err != nil {
		t.Fatal(err)
	}
	if out, err = list(); err == nil {
		t.Fatalf("symlink log directory accepted: %q", out)
	}
}

func TestRabbitAuditRejectedBeforeNativeAccess(t *testing.T) {
	if _, err := logLayout("RABBITMQ", service.AuditLog); err == nil {
		t.Fatal("RabbitMQ audit source accepted")
	}
	v := service.BrokerRecord{}
	v.Logs.Audit = true
	if _, err := rabbitLoggingConfiguration(v); err == nil {
		t.Fatal("RabbitMQ audit configuration accepted")
	}
}
