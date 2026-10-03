package elasticache_test

import (
	"context"
	"errors"
	"path/filepath"
	engine "stackd/engine/valkey"
	"stackd/journal"
	domain "stackd/storage/elasticache"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/elasticache"
	journaldb "stackd/storage/sqlite/journal"
	"testing"
	"time"
)

func TestCredentialAndNativeIntentJoinAuditAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.sqlite")
	db, e := sqlite.Open(t.Context(), path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := backend.New(db)
	events := journaldb.New(db)
	sc := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	k := domain.Key{Scope: sc, Kind: "cluster", Name: "owned"}
	epoch := time.Unix(0, 0).UTC()
	u := domain.User{Key: domain.Key{Scope: sc, Kind: "user", Name: "reader"}, Name: "native-reader", Engine: "valkey", AccessString: "on ~app:* -@all +get", PasswordHashes: []string{"918efd96f892044b7b4c7aa658c80a5c9be1ac261467ece87254fb3052022d92"}, Status: "modifying", Tags: map[string]string{"owner": "team"}}
	v := domain.Cluster{Key: k, RuntimeID: "retained-incarnation", Status: "modifying", Operation: "acl", Engine: "valkey", EngineVersion: "8.1.6", Shards: 1, Replicas: 1, ClusterMode: true, TLSEnabled: true, MemoryBytes: 512 << 20, Version: 7, Due: epoch, Created: epoch, Nodes: []engine.Node{{ID: "primary", Endpoint: engine.Endpoint{Address: "127.0.0.1", Port: 12345}}}, AuthHashes: []string{"retained-hash"}, Parameters: map[string]string{"timeout": "20"}, Tags: map[string]string{"owner": "team"}}
	event := func(ctx context.Context) error {
		return events.AppendAPICallCompleted(ctx, journal.Envelope{At: epoch, Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, journal.APICallCompleted{EventID: "accepted-cache-command", EventSource: "elasticache.amazonaws.com", EventName: "ModifyUser", Category: journal.CategoryManagement})
	}
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if e := tx.PutCluster(v); e != nil {
			return e
		}
		if e := tx.PutUser(u); e != nil {
			return e
		}
		return event(tx.Context())
	}); e != nil {
		t.Fatal(e)
	}
	changed := v
	changed.RuntimeID = "should-not-commit"
	changed.Parameters = nil
	changed.AuthHashes = nil
	changed.Nodes = nil
	u.PasswordHashes = []string{"should-not-commit"}
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if e := tx.PutCluster(changed); e != nil {
			return e
		}
		if e := tx.PutUser(u); e != nil {
			return e
		}
		return event(tx.Context())
	}); e == nil {
		t.Fatal("duplicate event accepted a partial native credential transition")
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
		got, e := r.Cluster(k)
		if e != nil {
			return e
		}
		if got.RuntimeID != v.RuntimeID || got.Version != 7 || got.Operation != "acl" || !got.Due.Equal(epoch) || got.Due.IsZero() || got.Parameters["timeout"] != "20" || len(got.Nodes) != 1 || got.Nodes[0].Endpoint.Port != 12345 || len(got.AuthHashes) != 1 || got.AuthHashes[0] != "retained-hash" {
			t.Fatalf("retained intent escaped rollback/restart: %#v", got)
		}
		user, e := r.User(u.Key)
		if e != nil {
			return e
		}
		if user.PasswordHashes[0] == "should-not-commit" || user.Name != "native-reader" {
			t.Fatal("credential transition escaped rollback")
		}
		for _, other := range []domain.Scope{{Partition: "aws-cn", AccountID: sc.AccountID, Region: sc.Region}, {Partition: sc.Partition, AccountID: "222222222222", Region: sc.Region}, {Partition: sc.Partition, AccountID: sc.AccountID, Region: "us-west-2"}} {
			alien := k
			alien.Scope = other
			if _, e = r.Cluster(alien); !errors.Is(e, domain.ErrNotFound) {
				t.Fatalf("native resource crossed scope: %v", e)
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if e := tx.DeleteCluster(k); e != nil {
			return e
		}
		return tx.PutCluster(domain.Cluster{Key: k, RuntimeID: "replacement", Version: 1, Status: "creating"})
	}); e != nil {
		t.Fatal(e)
	}
	if e = repo.View(t.Context(), func(r domain.Reader) error {
		got, e := r.Cluster(k)
		if e != nil {
			return e
		}
		if got.RuntimeID != "replacement" || len(got.Nodes) != 0 || len(got.AuthHashes) != 0 || len(got.Parameters) != 0 || len(got.Tags) != 0 {
			t.Fatal("recreated name inherited deleted incarnation children")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
