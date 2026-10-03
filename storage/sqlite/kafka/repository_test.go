package kafka_test

import (
	"context"
	"path/filepath"
	"stackd/internal/authorization"
	"stackd/journal"
	domain "stackd/storage/kafka"
	"stackd/storage/sqlite"
	journaldb "stackd/storage/sqlite/journal"
	backend "stackd/storage/sqlite/kafka"
	"testing"
	"time"
)

func TestNativeIntentAndPolicyRollbackTogetherAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "msk.sqlite")
	db, e := sqlite.Open(t.Context(), path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := backend.New(db)
	events := journaldb.New(db)
	sc := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	now := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	original := domain.ClusterRecord{Scope: sc, ARN: "arn:aws:kafka:us-east-1:111111111111:cluster/owned/id", Name: "owned", Incarnation: "id", Brokers: 1, KafkaVersion: "3.7.1", SecurityMode: "SASL_SCRAM", State: "UPDATING", Operation: "UPDATE_CLUSTER_CONFIGURATION", Version: 7, Created: now, Due: time.Unix(0, 0).UTC(), ConfigurationARN: "configuration", ConfigurationRevision: 1, ServerProperties: "num.partitions=1\n", PendingConfigurationARN: "configuration", PendingConfigurationRevision: 2, PendingServerProperties: "num.partitions=2\n", Secrets: []string{"secret-one"}, Policy: authorization.BoundPolicy{Document: `{"Version":"2012-10-17","Statement":[]}`, PrincipalIDs: map[string]string{"principal": "immutable-id"}}, PolicyVersion: 3, Tags: map[string]string{"owner": "team"}}
	appendEvent := func(ctx context.Context) error {
		return events.AppendAPICallCompleted(ctx, journal.Envelope{At: now, Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, journal.APICallCompleted{EventID: "accepted-msk-command", EventSource: "kafka.amazonaws.com", EventName: "UpdateClusterConfiguration", Category: journal.CategoryManagement})
	}
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if e := tx.PutCluster(original); e != nil {
			return e
		}
		return appendEvent(tx.Context())
	}); e != nil {
		t.Fatal(e)
	}
	changed := original
	changed.ConfigurationRevision = 2
	changed.PendingConfigurationRevision = 0
	changed.ServerProperties = changed.PendingServerProperties
	changed.PendingServerProperties = ""
	changed.Secrets = []string{"secret-two"}
	changed.Policy = authorization.BoundPolicy{}
	changed.State = "ACTIVE"
	changed.Version++
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if e := tx.PutCluster(changed); e != nil {
			return e
		}
		return appendEvent(tx.Context())
	}); e == nil {
		t.Fatal("duplicate audit completion committed native intent")
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	db, e = sqlite.Open(t.Context(), path)
	if e != nil {
		t.Fatal(e)
	}
	repo = backend.New(db)
	if e = repo.View(t.Context(), func(r domain.Reader) error {
		got, e := r.Cluster(original.ARN)
		if e != nil {
			return e
		}
		if got.Incarnation != original.Incarnation || got.Version != 7 || got.State != "UPDATING" || got.ConfigurationRevision != 1 || got.PendingConfigurationRevision != 2 || got.ServerProperties != original.ServerProperties || got.PendingServerProperties != original.PendingServerProperties || len(got.Secrets) != 1 || got.Secrets[0] != "secret-one" || got.Policy.PrincipalIDs["principal"] != "immutable-id" || got.PolicyVersion != 3 {
			t.Fatalf("failed state transition escaped rollback/restart: %#v", got)
		}
		if !got.Created.Equal(now) || !got.Due.Equal(time.Unix(0, 0)) || got.Due.IsZero() {
			t.Fatalf("persisted lifecycle deadline lost precision: %v / %v", got.Created, got.Due)
		}
		alien := sc
		alien.AccountID = "222222222222"
		rows, e := r.Clusters(alien)
		if e == nil && len(rows) != 0 {
			t.Fatalf("cluster list crossed account scope: %#v", rows)
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
