package rds_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	rdsapi "stackd/internal/awsapi/rds"
	"stackd/internal/awsctx"
	iamservice "stackd/internal/services/iam"
	rdsservice "stackd/internal/services/rds"
	"stackd/journal"
	iamstore "stackd/storage/iam"
	domain "stackd/storage/rds"
	"stackd/storage/sqlite"
	iamdb "stackd/storage/sqlite/iam"
	journaldb "stackd/storage/sqlite/journal"
	backend "stackd/storage/sqlite/rds"
)

func TestPendingCredentialAndParameterIntentSurvivesRollbackAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rds.sqlite")
	db, e := sqlite.Open(t.Context(), path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	repo := backend.New(db)
	events := journaldb.New(db)
	scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	key := domain.Key{Scope: scope, Kind: "db", Name: "owned"}
	created := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	due := time.Unix(0, 0).UTC()
	original := domain.Database{Key: key, RuntimeID: "original-incarnation", Engine: "postgres", EngineVersion: "17.11", Username: "owner", Status: "modifying", Desired: "running", Operation: "password", Ciphertext: []byte{0x81, 0x42}, PendingCiphertext: []byte{0x95, 0x13}, ParameterGroup: "configured", Parameters: map[string]string{"statement_timeout": "1000"}, Tags: map[string]string{"owner": "team"}, PendingParameters: true, Version: 7, Created: created, Due: due}
	original.ResourceID, original.Owner = "native-row-incarnation", domain.CloudFormationOwner{StackID: "stack", LogicalID: "Database", Token: "claim-token"}
	group := domain.ParameterGroup{Key: domain.Key{Scope: scope, Kind: "pg", Name: "configured"}, Family: "postgres17", Description: "owned", Parameters: map[string]string{"statement_timeout": "5000"}, ApplyMethods: map[string]string{"statement_timeout": "pending-reboot"}, Tags: map[string]string{}}
	group.ResourceID, group.Owner = "parameter-row-incarnation", domain.CloudFormationOwner{StackID: "stack", LogicalID: "Parameters", Token: "parameter-token"}
	appendEvent := func(ctx context.Context) error {
		return events.AppendAPICallCompleted(ctx, journal.Envelope{At: created, Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, journal.APICallCompleted{EventID: "accepted-command", EventSource: "rds.amazonaws.com", EventName: "ModifyDBInstance", Category: journal.CategoryManagement})
	}
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if e := tx.PutDatabase(original); e != nil {
			return e
		}
		if e := tx.PutParameterGroup(group); e != nil {
			return e
		}
		return appendEvent(tx.Context())
	}); e != nil {
		t.Fatal(e)
	}
	changed := original
	changed.Ciphertext = []byte{0xFF}
	changed.PendingCiphertext = nil
	changed.Parameters = nil
	changed.PendingParameters = false
	changed.Version++
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if e := tx.PutDatabase(changed); e != nil {
			return e
		}
		if e := tx.DeleteParameterGroup(group.Key); e != nil {
			return e
		}
		return appendEvent(tx.Context())
	}); e == nil {
		t.Fatal("duplicate audit event committed credential/parameter transition")
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
		got, e := r.Database(key)
		if e != nil {
			return e
		}
		if got.RuntimeID != original.RuntimeID || got.Operation != "password" || got.Status != "modifying" || got.Version != 7 || !bytes.Equal(got.Ciphertext, original.Ciphertext) || !bytes.Equal(got.PendingCiphertext, original.PendingCiphertext) || !got.PendingParameters || got.Parameters["statement_timeout"] != "1000" {
			t.Fatalf("credential/parameter intent escaped rollback or restart: %#v", got)
		}
		if got.ResourceID != original.ResourceID || got.Owner != original.Owner {
			t.Fatalf("private database authority escaped rollback or restart: %#v", got)
		}
		if !got.Created.Equal(created) || !got.Due.Equal(due) || got.Due.IsZero() {
			t.Fatalf("database deadlines lost precision or epoch identity: created=%s due=%s", got.Created, got.Due)
		}
		retained, e := r.ParameterGroup(group.Key)
		if e != nil {
			return e
		}
		if retained.Parameters["statement_timeout"] != "5000" || retained.ApplyMethods["statement_timeout"] != "pending-reboot" {
			t.Fatalf("pending parameter configuration lost: %#v", retained)
		}
		if retained.ResourceID != group.ResourceID || retained.Owner != group.Owner {
			t.Fatalf("private parameter authority escaped rollback or restart: %#v", retained)
		}
		alien := key
		alien.AccountID = "222222222222"
		if _, e = r.Database(alien); !errors.Is(e, domain.ErrNotFound) {
			t.Fatalf("database crossed account scope: %v", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	// Reusing a public name must not inherit old incarnation child rows.
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if e := tx.DeleteDatabase(key); e != nil {
			return e
		}
		return tx.PutDatabase(domain.Database{Key: key, RuntimeID: "new-incarnation", Status: "creating", Version: 1})
	}); e != nil {
		t.Fatal(e)
	}
	if e = repo.View(t.Context(), func(r domain.Reader) error {
		got, e := r.Database(key)
		if e != nil {
			return e
		}
		if got.RuntimeID != "new-incarnation" || len(got.Tags) != 0 || len(got.Parameters) != 0 || len(got.Ciphertext) != 0 || len(got.PendingCiphertext) != 0 {
			t.Fatalf("recreated name inherited previous incarnation state: %#v", got)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestPrivateRelationalObserverAndMutationRecheckCurrentIAM(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "authority.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	databases, identities := backend.New(db), iamdb.New(db)
	scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	key := domain.Key{Scope: scope, Kind: "db", Name: "private-owner"}
	owner := domain.CloudFormationOwner{StackID: "stack", LogicalID: "Database", Token: "exact-native-token"}
	if err := databases.Update(t.Context(), func(tx domain.Transaction) error {
		return tx.PutDatabase(domain.Database{Key: key, ResourceID: "native-row", RuntimeID: "native-runtime", Owner: owner, Status: "stopped", RequestedPort: 15432})
	}); err != nil {
		t.Fatal(err)
	}
	role := iamstore.Role{RoleName: "database-controller", RoleId: "AROADATABASECONTROLLER", Arn: "arn:aws:iam::111111111111:role/database-controller", IdentityPolicies: iamstore.IdentityPolicies{Inline: map[string]string{"owner": `{"Statement":{"Effect":"Allow","Action":["rds:DescribeDBInstances","rds:ModifyDBInstance"],"Resource":"` + key.ARN() + `"}}`}}}
	identityScope := iamstore.Scope{Partition: scope.Partition, AccountID: scope.AccountID}
	if err := identities.Update(t.Context(), func(tx iamstore.WriteTx) error { return tx.PutRole(identityScope, role) }); err != nil {
		t.Fatal(err)
	}
	iam := iamservice.NewWithConfig(iamservice.Config{Repository: identities})
	service := rdsservice.New(rdsservice.Config{Repository: databases, Authorizer: authorization.New(iam, nil)})
	t.Cleanup(func() { _ = service.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:sts::111111111111:assumed-role/database-controller/consumer", PrincipalID: role.RoleId + ":consumer", IssuerARN: role.Arn, IssuerID: role.RoleId})
	ctx = rdsservice.WithCloudFormationOwner(ctx, key.Kind, key.Name, owner)
	if port, err := service.CloudFormationRequestedPort(ctx, key.Kind, key.Name); err != nil || port != 15432 {
		t.Fatalf("authorized exact-incarnation observer: %d, %v", port, err)
	}
	request, err := rdsapi.DecodeRequest("ModifyDBInstance", awsapi.Request{JSON: []byte(`{"DBInstanceIdentifier":"private-owner","DeletionProtection":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, rejected := service.ExecuteCommand(ctx, request); rejected != nil {
		t.Fatal(rejected)
	}
	role.IdentityPolicies.Inline = nil
	if err := identities.Update(t.Context(), func(tx iamstore.WriteTx) error { return tx.PutRole(identityScope, role) }); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CloudFormationRequestedPort(ctx, key.Kind, key.Name); err == nil {
		t.Fatal("private observer borrowed revoked IAM authority")
	}
	request, err = rdsapi.DecodeRequest("ModifyDBInstance", awsapi.Request{JSON: []byte(`{"DBInstanceIdentifier":"private-owner","DeletionProtection":false}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, rejected := service.ExecuteCommand(ctx, request); rejected == nil || rejected.Code != "AccessDenied" {
		t.Fatalf("private mutation borrowed revoked IAM authority: %v", rejected)
	}
	if err := databases.View(t.Context(), func(r domain.Reader) error {
		v, err := r.Database(key)
		if err != nil {
			return err
		}
		if !v.DeletionProtection || v.Owner != owner || v.ResourceID != "native-row" {
			t.Fatalf("rejected native mutation changed private/live state: %#v", v)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
