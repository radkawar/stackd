package iam

import (
	"context"
	"errors"
	"testing"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

func TestServiceLinkedPolicySnapshotRequiresCurrentImmutableIdentity(t *testing.T) {
	a := newAccount()
	a.partition = "aws"
	r := &Role{RoleName: "AWSServiceRoleForExample", RoleId: "AROACURRENT", Arn: "arn:aws:iam::123456789012:role/aws-service-role/example.amazonaws.com/AWSServiceRoleForExample", IdentityPolicies: newIdentityPolicies()}
	a.roles["awsserviceroleforexample"] = r
	m := awsctx.Metadata{Partition: "aws", AccountID: "123456789012", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/AWSServiceRoleForExample/session", PrincipalID: "AROACURRENT:session", IssuerARN: r.Arn, IssuerID: r.RoleId}
	set, err := identityPolicySnapshot(a, m)
	if err != nil || set.ServiceLinkedRole {
		t.Fatalf("path conferred trusted ownership: %+v %v", set, err)
	}
	r.ServiceLinkedService = "example.amazonaws.com"
	set, err = identityPolicySnapshot(a, m)
	if err != nil || !set.ServiceLinkedRole {
		t.Fatalf("current trusted role lost ownership: %+v %v", set, err)
	}
	r.RoleId = "AROARECREATED"
	if _, err := identityPolicySnapshot(a, m); err == nil {
		t.Fatal("stale role session resolved to replacement role")
	}
}

func TestRoleSessionIssuanceRejectsDeletedOrReplacedIssuer(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository(nil)
	scope := Scope{Partition: "aws", AccountID: "123456789012"}
	role := Role{RoleName: "example", RoleId: "AROACURRENT", Arn: "arn:aws:iam::123456789012:role/path/example"}
	if err := repository.Update(ctx, func(tx WriteTx) error { return tx.PutRole(scope, role) }); err != nil {
		t.Fatal(err)
	}
	credentials := NewCredentialRepository(repository, nil)
	record := identity.Record{Credential: identity.Credential{AccessKeyID: "ASIAEXAMPLE", AccountID: scope.AccountID, PrincipalARN: "arn:aws:sts::123456789012:assumed-role/example/session", IssuerARN: role.Arn, IssuerID: role.RoleId}}
	if err := credentials.Update(ctx, func(tx identity.Transaction) error { return tx.Put(record) }); err != nil {
		t.Fatalf("valid current issuer: %v", err)
	}
	if err := repository.Update(ctx, func(tx WriteTx) error { return tx.DeleteRole(scope, role.RoleName) }); err != nil {
		t.Fatal(err)
	}
	record.Credential.AccessKeyID = "ASIAAFTERDELETION"
	if err := credentials.Update(ctx, func(tx identity.Transaction) error { return tx.Put(record) }); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("deleted issuer issuance = %v", err)
	}
	role.RoleId = "AROARECREATED"
	if err := repository.Update(ctx, func(tx WriteTx) error { return tx.PutRole(scope, role) }); err != nil {
		t.Fatal(err)
	}
	if err := credentials.Update(ctx, func(tx identity.Transaction) error { return tx.Put(record) }); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("replaced issuer issuance = %v", err)
	}
	if err := credentials.View(ctx, func(tx identity.Reader) error {
		_, err := tx.Get(record.Credential.AccessKeyID)
		return err
	}); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("failed issuance published credential: %v", err)
	}
}
