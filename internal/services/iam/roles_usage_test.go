package iam_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

func TestRoleLastUsePersistsBeyondSessionAndRollsBackAtomically(t *testing.T) {
	ctx := context.Background()
	repository := iam.NewMemoryRepository(nil)
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	service := iam.NewWithRepository(nil, repository)
	client := clientFor(t, service, scope.AccountID, "us-east-1")
	created, err := client.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("used-role"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	get := func() *sdkiam.GetRoleOutput {
		t.Helper()
		out, err := client.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: created.Role.RoleName})
		if err != nil {
			t.Fatal(err)
		}
		if out.Role.RoleLastUsed == nil {
			t.Fatal("GetRole omitted empty RoleLastUsed")
		}
		return out
	}
	if get().Role.RoleLastUsed.LastUsedDate != nil {
		t.Fatal("unused role has a use date")
	}
	credentials := iam.NewCredentialRepository(repository, nil)
	record := identity.Record{Credential: identity.Credential{AccessKeyID: "ASIAROLEUSAGE", AccountID: scope.AccountID, PrincipalARN: "arn:aws:sts::123456789012:assumed-role/used-role/session", PrincipalID: aws.ToString(created.Role.RoleId) + ":session", IssuerARN: aws.ToString(created.Role.Arn), IssuerID: aws.ToString(created.Role.RoleId)}, Status: identity.Active}
	if err := credentials.Update(ctx, func(tx identity.Transaction) error { return tx.Put(record) }); err != nil {
		t.Fatal(err)
	}
	used := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	record.LastUsed = identity.LastUsed{Date: used, Service: "sqs", Region: "eu-west-1"}
	abort := errors.New("abort usage write")
	err = credentials.Update(ctx, func(tx identity.Transaction) error {
		if err := tx.Put(record); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if get().Role.RoleLastUsed.LastUsedDate != nil {
		t.Fatal("aborted usage transaction changed role")
	}
	if err := credentials.Update(ctx, func(tx identity.Transaction) error { return tx.Put(record) }); err != nil {
		t.Fatal(err)
	}
	assertUsage := func() {
		t.Helper()
		out := get().Role.RoleLastUsed
		if out.LastUsedDate == nil || !out.LastUsedDate.Equal(used) || aws.ToString(out.Region) != "eu-west-1" {
			t.Fatalf("usage=%+v", out)
		}
	}
	assertUsage()
	record.LastUsed = identity.LastUsed{Date: used.Add(-time.Hour), Service: "iam", Region: "us-east-1"}
	if err := credentials.Update(ctx, func(tx identity.Transaction) error { return tx.Put(record) }); err != nil {
		t.Fatal(err)
	}
	assertUsage()
	if err := credentials.Update(ctx, func(tx identity.Transaction) error { return tx.Delete(record.Credential.AccessKeyID) }); err != nil {
		t.Fatal(err)
	}
	// A new provider over the same repository has no access to the expired or
	// removed session row. Role history is still part of the persisted role.
	client = clientFor(t, iam.NewWithRepository(nil, repository), scope.AccountID, "us-east-1")
	assertUsage()
	if err := repository.Update(ctx, func(tx iam.WriteTx) error {
		r, err := tx.Role(scope, aws.ToString(created.Role.RoleName))
		if err != nil {
			return err
		}
		r.LastUsed.Date = time.Now().Add(-401 * 24 * time.Hour)
		return tx.PutRole(scope, r)
	}); err != nil {
		t.Fatal(err)
	}
	if get().Role.RoleLastUsed.LastUsedDate != nil {
		t.Fatal("role use older than 400 days reported")
	}
}
