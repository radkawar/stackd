package docdb_test

import (
	"context"
	"errors"
	"path/filepath"
	engine "stackd/engine/docdb"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	docdbservice "stackd/internal/services/docdb"
	iamservice "stackd/internal/services/iam"
	"stackd/journal"
	domain "stackd/storage/docdb"
	iamstore "stackd/storage/iam"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/docdb"
	iamdb "stackd/storage/sqlite/iam"
	journaldb "stackd/storage/sqlite/journal"
	"testing"
	"time"
)

func TestSourceIdentityAndCredentialIntentShareAuditRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docdb.sqlite")
	db, e := sqlite.Open(t.Context(), path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := backend.New(db)
	events := journaldb.New(db)
	scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	k := domain.Key{Scope: scope, Kind: "cluster", Name: "source"}
	epoch := time.Unix(0, 0).UTC()
	v := domain.Cluster{Key: k, RuntimeID: "source-incarnation", Username: "owner", EngineVersion: "5.0", Status: "modifying", Operation: "password", Ciphertext: []byte{1, 2}, PendingCiphertext: []byte{3, 4}, Endpoint: engine.Endpoint{Address: "localhost", Port: 27017, ReplicaSet: "rs0", CA: []byte("trust")}, Created: epoch, Due: epoch, Version: 7, Tags: map[string]string{"owner": "first"}}
	appendEvent := func(ctx context.Context) error {
		return events.AppendAPICallCompleted(ctx, journal.Envelope{At: epoch, Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, journal.APICallCompleted{EventID: "accepted", EventSource: "docdb.amazonaws.com", EventName: "ModifyDBCluster", Category: journal.CategoryManagement})
	}
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if e := tx.PutCluster(v); e != nil {
			return e
		}
		return appendEvent(tx.Context())
	}); e != nil {
		t.Fatal(e)
	}
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if e := tx.DeleteCluster(k); e != nil {
			return e
		}
		if e := tx.PutCluster(domain.Cluster{Key: k, RuntimeID: "replacement", Tags: map[string]string{"owner": "second"}}); e != nil {
			return e
		}
		return appendEvent(tx.Context())
	}); e == nil {
		t.Fatal("audit failure committed cluster replacement")
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
		if got.RuntimeID != v.RuntimeID || got.Version != 7 || got.Operation != "password" || string(got.PendingCiphertext) != string(v.PendingCiphertext) || string(got.Endpoint.CA) != "trust" || got.Tags["owner"] != "first" {
			t.Fatalf("source identity/authority escaped rollback: %#v", got)
		}
		if got.Due.IsZero() || !got.Due.Equal(epoch) {
			t.Fatalf("epoch deadline changed: %s", got.Due)
		}
		alien := k
		alien.AccountID = "222222222222"
		if _, e = r.Cluster(alien); !errors.Is(e, domain.ErrNotFound) {
			t.Fatalf("cross-account source lookup: %v", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if e := tx.DeleteCluster(k); e != nil {
			return e
		}
		return tx.PutCluster(domain.Cluster{Key: k, RuntimeID: "replacement"})
	}); e != nil {
		t.Fatal(e)
	}
	if e = repo.View(t.Context(), func(r domain.Reader) error {
		got, e := r.Cluster(k)
		if e != nil {
			return e
		}
		if got.RuntimeID != "replacement" || len(got.Tags) != 0 || len(got.Ciphertext) != 0 || len(got.Endpoint.CA) != 0 {
			t.Fatalf("replacement inherited old authority: %#v", got)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestSourceResolutionSharesCurrentIAMReadTransaction(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "source.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	documents := backend.New(db)
	identities := iamdb.New(db)
	scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	key := domain.Key{Scope: scope, Kind: "cluster", Name: "source"}
	endpoint := engine.Endpoint{Address: "127.0.0.1", Port: 27017, ReplicaSet: "stackd", CA: []byte("current-trust")}
	if err := documents.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutCluster(domain.Cluster{Key: key, RuntimeID: "current-incarnation", Status: "available", Endpoint: endpoint}); err != nil {
			return err
		}
		return tx.PutInstance(domain.Instance{Key: domain.Key{Scope: scope, Kind: "db", Name: "writer"}, Cluster: key.Name, Status: "available"})
	}); err != nil {
		t.Fatal(err)
	}
	role := iamstore.Role{
		RoleName: "document-source", RoleId: "AROACURRENTSOURCE",
		Arn: "arn:aws:iam::111111111111:role/document-source",
		IdentityPolicies: iamstore.IdentityPolicies{Inline: map[string]string{
			"source": `{"Statement":{"Effect":"Allow","Action":"rds:DescribeDBClusters","Resource":"` + key.ARN() + `"}}`,
		}},
	}
	identityScope := iamstore.Scope{Partition: scope.Partition, AccountID: scope.AccountID}
	if err := identities.Update(t.Context(), func(tx iamstore.WriteTx) error {
		return tx.PutRole(identityScope, role)
	}); err != nil {
		t.Fatal(err)
	}
	iam := iamservice.NewWithConfig(iamservice.Config{Repository: identities})
	source := docdbservice.New(docdbservice.Config{Repository: documents, Authorizer: authorization.New(iam, nil)})
	t.Cleanup(func() { _ = source.Close() })
	metadata := awsctx.Metadata{
		Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region,
		PrincipalARN: "arn:aws:sts::111111111111:assumed-role/document-source/consumer",
		PrincipalID:  role.RoleId + ":consumer", IssuerARN: role.Arn, IssuerID: role.RoleId,
	}
	ctx, cancel := context.WithTimeout(awsctx.WithMetadata(t.Context(), metadata), 5*time.Second)
	defer cancel()
	got, err := source.ResolveCluster(ctx, key.ARN())
	if err != nil {
		t.Fatal(err)
	}
	if got.ARN != key.ARN() || got.RuntimeID != "current-incarnation" || got.Endpoint.Address != endpoint.Address || string(got.Endpoint.CA) != string(endpoint.CA) {
		t.Fatalf("wrong source authority: %#v", got)
	}
	// A retained source identity is not cached authorization: the next lookup
	// must observe current IAM policy through the same shared SQLite database.
	role.IdentityPolicies.Inline = nil
	if err := identities.Update(t.Context(), func(tx iamstore.WriteTx) error {
		return tx.PutRole(identityScope, role)
	}); err != nil {
		t.Fatal(err)
	}
	_, err = source.ResolveCluster(ctx, key.ARN())
	var denied *awswire.Error
	if !errors.As(err, &denied) || denied.Code != "AccessDenied" {
		t.Fatalf("source retained revoked IAM authority: %v", err)
	}
}
