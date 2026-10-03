package eks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFailedLoggingConfigurationKeepsCommittedMaskAndOffsets(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	logs := &nativeLogs{dir: dir, cursor: logCursor{AuthOffset: 41, AuditOffset: 83, EnabledSince: map[string]time.Time{"audit": at}}}
	if err := logs.save(logs.cursor); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "log-cursor.json"))
	if err != nil {
		t.Fatal(err)
	}
	// A missing destination deterministically fails the real atomic writer,
	// including when tests run as root. Disabling logging requires no sink.
	logs.dir = filepath.Join(dir, "unavailable")
	if err := logs.configure(Specification{}, false); err == nil {
		t.Fatal("configuration unexpectedly persisted into an unavailable directory")
	}
	if !logs.enabled("audit", at) || logs.cursor.AuthOffset != 41 || logs.cursor.AuditOffset != 83 {
		t.Fatal("failed configuration changed the committed mask or acknowledged source offsets")
	}
	after, err := os.ReadFile(filepath.Join(dir, "log-cursor.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed configuration replaced the retained checkpoint: %v", err)
	}
	logs.dir = dir
	if err := logs.configure(Specification{}, false); err != nil {
		t.Fatal(err)
	}
	if logs.enabled("audit", at) {
		t.Fatal("successfully disabled source remained live")
	}
	after, err = os.ReadFile(filepath.Join(dir, "log-cursor.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recovered logCursor
	if err = json.Unmarshal(after, &recovered); err != nil {
		t.Fatal(err)
	}
	if len(recovered.EnabledSince) != 0 || recovered.AuthOffset != 41 || recovered.AuditOffset != 83 {
		t.Fatalf("recovery would re-enable a disabled source or lose acknowledged offsets: %+v", recovered)
	}
}

type authenticationLogSink struct {
	fail    bool
	records []LogRecord
}

func (s *authenticationLogSink) PutControlPlaneLogs(_ context.Context, _ string, records []LogRecord) error {
	if s.fail {
		return errors.New("delivery unavailable")
	}
	s.records = append(s.records, records...)
	return nil
}

func TestAuthenticationCheckpointUsesAdmittedServiceRecords(t *testing.T) {
	at := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	record := LogRecord{Category: "authenticator", Stream: "authenticator-owned", Timestamp: at, Message: `{"msg":"access denied"}`}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	body = append(body, '\n')
	if err := os.WriteFile(filepath.Join(dir, "authenticator.jsonl"), body, 0600); err != nil {
		t.Fatal(err)
	}
	sink := &authenticationLogSink{fail: true}
	logs := &nativeLogs{dir: dir, sink: sink, cursor: logCursor{EnabledSince: map[string]time.Time{"authenticator": at.Add(24 * time.Hour)}}}
	if err := logs.collectAuthentication(t.Context()); err == nil || logs.cursor.AuthOffset != 0 {
		t.Fatal("undelivered service-time decision was acknowledged")
	}
	sink.fail = false
	if err := logs.collectAuthentication(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 1 || sink.records[0] != record || logs.cursor.AuthOffset != int64(len(body)) {
		t.Fatalf("service-time decision lost or changed: records=%+v offset=%d", sink.records, logs.cursor.AuthOffset)
	}
	if err := logs.collectAuthentication(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 1 {
		t.Fatal("acknowledged authenticator decision was replayed")
	}
}
