package lambda

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	api "stackd/internal/awsapi/lambda"
)

func TestDocumentDBNativeAdmissionBoundaries(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/lambda/documentdb_admission.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Label  string
			Input  json.RawMessage
			Result struct{ Code string }
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	control := documentDBMappingControl{s: New(Config{})}
	defer control.s.Close()
	for _, row := range fixture.Observations {
		switch row.Label {
		case "missing_documentdb_config", "missing_database", "missing_secret", "timestamp_required", "filter_unsupported", "partial_batch_unsupported":
		default:
			continue
		}
		t.Run(row.Label, func(t *testing.T) {
			var input api.CreateEventSourceMappingInput
			if err := json.Unmarshal(row.Input, &input); err != nil {
				t.Fatal(err)
			}
			_, wire := control.createSettings(&input)
			if wire == nil || wire.Code != row.Result.Code {
				t.Fatalf("native rejection %s, local %v", row.Result.Code, wire)
			}
		})
	}
}

func TestDocumentDBNativeNamespaceUpdateRejections(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/cloudformation/lambda_documentdb_mapping_nondefault.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Calls []struct {
			Label, Code string
			Input       json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	control := documentDBMappingControl{}
	initial := EventSourceMappingSettings{
		BatchSize: 100, BatchingWindow: 500 * time.Millisecond,
		DocumentDB: &DocumentDBMappingSettings{
			Database: "owned", Collection: "events", FullDocument: "UpdateLookup",
			SecretARN: "arn:aws:secretsmanager:us-east-1:123456789012:secret:owned",
		},
	}
	pending := map[string]bool{"direct-same-database": true, "direct-collection-only": true, "direct-database-only": true}
	for _, row := range fixture.Calls {
		if !pending[row.Label] {
			continue
		}
		t.Run(row.Label, func(t *testing.T) {
			var input api.UpdateEventSourceMappingInput
			if err := json.Unmarshal(row.Input, &input); err != nil {
				t.Fatal(err)
			}
			_, wire := control.updateSettings(initial, &input)
			if wire == nil || wire.Code != row.Code {
				t.Fatalf("native rejection %s, local %v", row.Code, wire)
			}
			if initial.DocumentDB.Database != "owned" || initial.DocumentDB.Collection != "events" || initial.DocumentDB.FullDocument != "UpdateLookup" {
				t.Fatalf("rejected update changed retained watch settings: %+v", initial.DocumentDB)
			}
		})
		delete(pending, row.Label)
	}
	if len(pending) != 0 {
		t.Fatalf("missing native namespace cases: %v", pending)
	}
}

func TestDocumentDBCheckpointFencesMappingChanges(t *testing.T) {
	repo := NewMemoryRepository(nil)
	service := &Service{repository: repo}
	key := EventSourceMappingKey{Scope: Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, UUID: "owned-mapping"}
	mapping := EventSourceMappingRecord{Key: key, Version: 1, State: "Enabled", Settings: EventSourceMappingSettings{DocumentDB: &DocumentDBMappingSettings{Incarnation: "original"}}}
	if err := repo.Update(t.Context(), func(tx Transaction) error { return tx.PutEventSourceMapping(mapping) }); err != nil {
		t.Fatal(err)
	}
	initial := DocumentDBCheckpoint{Mapping: key, Incarnation: "original", ResumeToken: []byte{1, 2, 3}, StartSeconds: 7, StartIncrement: 11}
	if err := service.commitDocumentDBPosition(t.Context(), mapping, initial, false, time.Time{}); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, state, incarnation string
		version                  uint64
	}{
		{"disable", "Disabled", "original", 1},
		{"update", "Enabled", "original", 2},
		{"replace source", "Enabled", "replacement", 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			changed := cloneEventSourceMapping(mapping)
			changed.State, changed.Version, changed.Settings.DocumentDB.Incarnation = row.state, row.version, row.incarnation
			if err := repo.Update(t.Context(), func(tx Transaction) error { return tx.PutEventSourceMapping(changed) }); err != nil {
				t.Fatal(err)
			}
			next := initial
			next.ResumeToken = []byte{4, 5, 6}
			if err := service.commitDocumentDBPosition(t.Context(), mapping, next, false, time.Time{}); !errors.Is(err, context.Canceled) {
				t.Fatalf("stale completion admitted: %v", err)
			}
			if err := repo.View(t.Context(), func(r Reader) error {
				retained, err := r.DocumentDBCheckpoint(key)
				if err != nil {
					return err
				}
				if !bytes.Equal(retained.ResumeToken, initial.ResumeToken) || retained.StartSeconds != 7 || retained.StartIncrement != 11 {
					t.Fatalf("stale completion advanced native resume point: %+v", retained)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := repo.Update(t.Context(), func(tx Transaction) error { return tx.DeleteEventSourceMapping(key) }); err != nil {
		t.Fatal(err)
	}
	if err := repo.View(t.Context(), func(r Reader) error { _, err := r.DocumentDBCheckpoint(key); return err }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted mapping retained checkpoint: %v", err)
	}
}
