package integrations

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/services/cloudtrail"
	"stackd/internal/services/guardduty"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqltrail "stackd/storage/sqlite/cloudtrail"
	sqlguard "stackd/storage/sqlite/guardduty"
	sqljournal "stackd/storage/sqlite/journal"
)

func TestGuardDutySourceTransactionRollbackIsolationAndSuppression(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			domain := memory.NewDomain()
			var findings guardduty.Repository = guardduty.NewMemoryRepository(domain)
			var trails cloudtrail.Repository = cloudtrail.NewMemoryRepository(domain)
			events := journal.NewMemory(domain)
			if backend == "sqlite" {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "detection.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				findings, trails, events = sqlguard.New(db), sqltrail.New(db), sqljournal.New(db)
			}
			now := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
			sourceClock := clock.NewManual(now)
			service := guardduty.New(guardduty.Config{Repository: findings, Clock: sourceClock})
			t.Cleanup(func() { _ = service.Close() })
			adapter := &GuardDutyEvents{Journal: events, Detector: service, Trails: trails}
			source := &cloudtrail.APIEvents{Repository: trails, Journal: adapter, Clock: sourceClock}
			scopes := []guardduty.Scope{{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, {Partition: "aws-cn", AccountID: "123456789012", Region: "us-east-1"}, {Partition: "aws", AccountID: "222222222222", Region: "us-east-1"}, {Partition: "aws", AccountID: "123456789012", Region: "us-west-2"}}
			err := findings.Update(t.Context(), func(tx guardduty.Transaction) error {
				for _, sc := range scopes {
					detector := guardduty.Detector{Scope: sc, ID: "detector", ARN: "arn:" + sc.Partition + ":guardduty:" + sc.Region + ":" + sc.AccountID + ":detector/detector", Status: "ENABLED", Features: []guardduty.Feature{{Name: "CLOUD_TRAIL", Status: "ENABLED"}}, Created: now, Updated: now}
					if err := tx.PutDetector(detector); err != nil {
						return err
					}
					if err := tx.PutFilter(guardduty.Filter{Scope: sc, DetectorID: detector.ID, Name: "suppress-root", ARN: detector.ARN + "/filter/suppress-root", Action: "ARCHIVE", Created: now, Updated: now, Criteria: api.FindingCriteria{Criterion: api.Criterion{"type": {Equals: api.Equals{"Policy:IAMUser/RootCredentialUsage"}}}}}); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			envelope := journal.Envelope{At: now, Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
			call := journal.APICallCompleted{EventID: "root-event", EventSource: "iam.amazonaws.com", EventName: "ListUsers", Category: journal.CategoryManagement, Identity: journal.APIIdentity{Type: "Root", PrincipalID: envelope.AccountID, AccountID: envelope.AccountID, AccessKeyID: "root-key"}, SourceIPAddress: "192.0.2.10"}
			rollback := errors.New("source transaction rejected")
			err = trails.Update(t.Context(), func(tx cloudtrail.Transaction) error {
				if err := source.AppendAPICallCompleted(tx.Context(), envelope, call); err != nil {
					return err
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
			assertCount := func(want int64) {
				t.Helper()
				if err := findings.View(t.Context(), func(r guardduty.Reader) error {
					for i, sc := range scopes {
						rows, err := r.Findings(sc, "detector")
						if err != nil {
							return err
						}
						expected := 0
						if i == 0 && want > 0 {
							expected = 1
						}
						if len(rows) != expected {
							t.Fatalf("scope %+v: findings=%+v want %d", sc, rows, expected)
						}
						if expected == 1 && (rows[0].Count != want || !rows[0].Suppressed || !rows[0].Archived || !rows[0].PublishDue.IsZero() || rows[0].SampleRevision != "" || rows[0].Observation.EventID != "root-event") {
							t.Fatalf("incorrect observed lifecycle: %+v", rows[0])
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			assertCount(0)
			retained, err := events.Read(t.Context(), 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(retained) != 0 {
				t.Fatalf("rolled-back event remained: %+v", retained)
			}
			if err := source.AppendAPICallCompleted(t.Context(), envelope, call); err != nil {
				t.Fatal(err)
			}
			assertCount(1)
			err = findings.Update(t.Context(), func(tx guardduty.Transaction) error {
				d, err := tx.Detector(scopes[0], "detector")
				if err != nil {
					return err
				}
				d.Status = "DISABLED"
				return tx.PutDetector(d)
			})
			if err != nil {
				t.Fatal(err)
			}
			call.EventID = "disabled-event"
			if err := source.AppendAPICallCompleted(t.Context(), envelope, call); err != nil {
				t.Fatal(err)
			}
			assertCount(1)
			retained, err = events.Read(context.Background(), 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(retained) != 2 {
				t.Fatalf("detector gate changed source history: %d", len(retained))
			}
		})
	}
}
