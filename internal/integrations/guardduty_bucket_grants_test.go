package integrations

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/services/guardduty"
	"stackd/internal/services/s3"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlguard "stackd/storage/sqlite/guardduty"
	sqljournal "stackd/storage/sqlite/journal"
	sqls3 "stackd/storage/sqlite/s3"
)

func TestGuardDutyBucketGrantCommitsWithAdmittedState(t *testing.T) {
	for _, source := range []struct{ backend, operation string }{
		{"memory", "PutBucketAcl"}, {"sqlite", "PutBucketAcl"},
		{"memory", "PutBucketPolicy"}, {"sqlite", "PutBucketPolicy"},
	} {
		t.Run(source.backend+"/"+source.operation, func(t *testing.T) {
			domain := memory.NewDomain()
			var buckets s3.Repository = s3.NewMemoryRepository(domain)
			var findings guardduty.Repository = guardduty.NewMemoryRepository(domain)
			events := journal.NewMemory(domain)
			if source.backend == "sqlite" {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				buckets, findings, events = sqls3.New(db), sqlguard.New(db), sqljournal.New(db)
			}
			now := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
			scope := guardduty.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
			detector := guardduty.Detector{Scope: scope, ID: "detector", ARN: "arn:aws:guardduty:us-east-1:123456789012:detector/detector", Status: "ENABLED", Features: []guardduty.Feature{{Name: "CLOUD_TRAIL", Status: "ENABLED"}}, Created: now, Updated: now}
			if err := findings.Update(t.Context(), func(tx guardduty.Transaction) error { return tx.PutDetector(detector) }); err != nil {
				t.Fatal(err)
			}
			service := guardduty.New(guardduty.Config{Repository: findings, Clock: clock.NewManual(now)})
			t.Cleanup(func() { _ = service.Close() })
			adapter := GuardDutyEvents{Journal: events, Detector: service, Buckets: buckets}
			bucket := s3.BucketRecord{Key: s3.BucketKey{Partition: scope.Partition, Name: "source-bucket"}, AccountID: scope.AccountID, Region: scope.Region, Created: now, ACL: &s3.AccessControlList{OwnerAccountID: scope.AccountID, OwnerID: "owner", Grants: []s3.ACLGrant{{Type: "Group", URI: "http://acs.amazonaws.com/groups/global/AllUsers", Permission: "READ"}}}}
			envelope := journal.Envelope{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, At: now}
			call := journal.APICallCompleted{EventID: "actual-grant", EventSource: "s3.amazonaws.com", EventName: source.operation, Category: journal.CategoryManagement, Identity: journal.APIIdentity{Type: "IAMUser", PrincipalID: "caller"}, RequestParameters: []byte(`{"bucketName":"source-bucket","bucketPolicy":"not admitted evidence"}`)}
			if source.operation == "PutBucketPolicy" {
				bucket.ACL = nil
				bucket.Policy = authorization.BoundPolicy{Document: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::source-bucket/*"}]}`}
			}
			rejected := errors.New("rollback after observation")
			mutate := func(rollback bool) error {
				return buckets.Update(t.Context(), func(tx s3.Transaction) error {
					if err := tx.PutBucket(bucket); err != nil {
						return err
					}
					if err := adapter.AppendAPICallCompleted(tx.Context(), envelope, call); err != nil {
						return err
					}
					if rollback {
						return rejected
					}
					return nil
				})
			}
			if err := mutate(true); !errors.Is(err, rejected) {
				t.Fatal(err)
			}
			check := func(want int) {
				t.Helper()
				if err := findings.View(t.Context(), func(r guardduty.Reader) error {
					rows, err := r.Findings(scope, detector.ID)
					if err != nil {
						return err
					}
					if len(rows) != want {
						t.Fatalf("findings=%+v want %d", rows, want)
					}
					if want == 1 && (rows[0].Observation.Type != "Policy:S3/BucketAnonymousAccessGranted" || rows[0].Count != 1 || rows[0].Observation.ResourceName != bucket.Key.Name) {
						t.Fatalf("incorrect retained grant: %+v", rows[0])
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			check(0)
			rows, err := events.Read(t.Context(), 0, 100)
			if err != nil || len(rows) != 0 {
				t.Fatalf("rollback journal=%+v error=%v", rows, err)
			}
			if err := mutate(false); err != nil {
				t.Fatal(err)
			}
			check(1)
			// A private replacement must not reuse the previous committed grant.
			if source.operation == "PutBucketAcl" {
				bucket.ACL.Grants = nil
			} else {
				bucket.Policy = authorization.BoundPolicy{}
			}
			call.EventID = "private-replacement"
			if err := mutate(false); err != nil {
				t.Fatal(err)
			}
			check(1)
		})
	}
}
