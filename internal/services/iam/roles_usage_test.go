package iam_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/clock"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
	sqlitestore "stackd/storage/sqlite"
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

func TestRoleLastUseUpdatesOnlyScalarMetadata(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			var repository iam.Repository
			var guardAggregateWrites func()
			if backend == "memory" {
				repository = iam.NewMemoryRepository(nil)
			} else {
				db, err := sqlitestore.Open(ctx, filepath.Join(t.TempDir(), "iam.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := db.Close(); err != nil {
						t.Error(err)
					}
				})
				repository = newSQLiteIAMRepository(t, db)
				guardAggregateWrites = func() {
					// A usage observation must not delete/reinsert a role or its
					// cascading children, even when their values remain identical.
					_, err := db.ExecContext(ctx, `CREATE TRIGGER reject_role_usage_rewrite BEFORE DELETE ON iam_role
BEGIN SELECT RAISE(ABORT, 'role usage rewrote the role aggregate'); END`)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			role := iam.Role{
				RoleName: "used-role", RoleId: "AROASCALAR", Arn: "arn:aws:iam::123456789012:role/path/used-role",
				Path: "/path/", CreateDate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				AssumeRolePolicyDocument: `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}}`,
				Description:              "retain all role fields", MaxSessionDuration: 7200,
				PermissionsBoundary: &iam.Boundary{PermissionsBoundaryType: "Policy", PermissionsBoundaryArn: "arn:aws:iam::123456789012:policy/boundary"},
				Tags:                []iam.Tag{{Key: "project", Value: "sample"}},
				TrustPrincipalIDs:   map[string]string{"arn:aws:iam::123456789012:root": "123456789012"},
				SourceRoleTemplate:  &iam.RoleTemplateSource{ARN: "arn:aws:iam::aws:role-template/example", MinorVersion: 1, Parameters: map[string][]string{"Name": {"example"}}},
				IdentityPolicies: iam.IdentityPolicies{
					Inline:              map[string]string{"inline": `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`},
					Attached:            map[string]struct{}{"arn:aws:iam::aws:policy/ReadOnlyAccess": {}},
					InlineOwners:        map[string]string{"inline": "inline-owner"},
					AttachedOwners:      map[string]string{"arn:aws:iam::aws:policy/ReadOnlyAccess": "attachment-owner"},
					CloudFormationOwner: "role-owner",
				},
			}
			if err := repository.Update(ctx, func(tx iam.WriteTx) error { return tx.PutRole(scope, role) }); err != nil {
				t.Fatal(err)
			}
			readRole := func() iam.Role {
				t.Helper()
				var result iam.Role
				if err := repository.View(ctx, func(tx iam.ReadTx) error {
					var err error
					result, err = tx.Role(scope, role.RoleName)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				return result
			}
			// Read back the backend's detached representation before asserting
			// that only its scalar last-use fields change.
			want := readRole()
			assertRole := func() {
				t.Helper()
				if got := readRole(); !reflect.DeepEqual(got, want) {
					t.Fatalf("role aggregate changed: got=%+v want=%+v", got, want)
				}
			}
			credentials := iam.NewCredentialRepository(repository, nil)
			record := identity.Record{Credential: identity.Credential{
				AccessKeyID: "ASIASCALAR", SessionToken: "session-token", SessionType: identity.SessionTypeAssumeRole,
				AccountID: scope.AccountID, IssuerID: role.RoleId, IssuerARN: role.Arn,
				PrincipalID: role.RoleId + ":session", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/used-role/session",
			}, Status: identity.Active}
			if err := credentials.Update(ctx, func(tx identity.Transaction) error { return tx.Put(record) }); err != nil {
				t.Fatal(err)
			}
			if guardAggregateWrites != nil {
				guardAggregateWrites()
			}
			record.LastUsed = identity.LastUsed{Service: "s3", Region: "us-east-1"}
			if err := credentials.Update(ctx, func(tx identity.Transaction) error { return tx.Put(record) }); err != nil {
				t.Fatal(err)
			}
			want.LastUsed = iam.RoleLastUse{Region: "us-east-1"}
			assertRole()
			if err := repository.Update(ctx, func(tx iam.WriteTx) error {
				return tx.RecordRoleUse(scope, role.RoleName, role.RoleId, role.Arn, iam.RoleLastUse{Region: "eu-west-1"})
			}); err != nil {
				t.Fatal(err)
			}
			assertRole()
			used := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
			record.LastUsed = identity.LastUsed{Date: used, Service: "s3", Region: "eu-west-1"}
			if err := credentials.Update(ctx, func(tx identity.Transaction) error { return tx.Put(record) }); err != nil {
				t.Fatal(err)
			}
			want.LastUsed = iam.RoleLastUse{Date: used, Region: "eu-west-1"}
			assertRole()
			abort := errors.New("abort scalar role use")
			record.LastUsed.Date = used.Add(time.Second)
			if err := credentials.Update(ctx, func(tx identity.Transaction) error {
				if err := tx.Put(record); err != nil {
					return err
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatal(err)
			}
			assertRole()
			if err := credentials.View(ctx, func(tx identity.Reader) error {
				got, err := tx.Get(record.Credential.AccessKeyID)
				if err == nil && !got.LastUsed.Date.Equal(used) {
					t.Fatalf("aborted role observation changed credential usage: %+v", got.LastUsed)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct {
				name, roleName, id, arn string
				scope                   iam.Scope
				use                     iam.RoleLastUse
			}{
				{"older", role.RoleName, role.RoleId, role.Arn, scope, iam.RoleLastUse{Date: used.Add(-time.Second), Region: "us-east-1"}},
				{"equal-different-region", role.RoleName, role.RoleId, role.Arn, scope, iam.RoleLastUse{Date: used, Region: "us-east-1"}},
				{"recreated-role", role.RoleName, "AROAREPLACED", role.Arn, scope, iam.RoleLastUse{Date: used.Add(time.Second), Region: "us-east-1"}},
				{"different-arn", role.RoleName, role.RoleId, "arn:aws:iam::123456789012:role/other-path/used-role", scope, iam.RoleLastUse{Date: used.Add(time.Second), Region: "us-east-1"}},
				{"other-account", role.RoleName, role.RoleId, role.Arn, iam.Scope{Partition: "aws", AccountID: "222222222222"}, iam.RoleLastUse{Date: used.Add(time.Second), Region: "us-east-1"}},
				{"other-partition", role.RoleName, role.RoleId, role.Arn, iam.Scope{Partition: "aws-cn", AccountID: scope.AccountID}, iam.RoleLastUse{Date: used.Add(time.Second), Region: "us-east-1"}},
				{"missing-role", "missing", role.RoleId, role.Arn, scope, iam.RoleLastUse{Date: used.Add(time.Second), Region: "us-east-1"}},
			} {
				t.Run(test.name, func(t *testing.T) {
					if err := repository.Update(ctx, func(tx iam.WriteTx) error {
						return tx.RecordRoleUse(test.scope, test.roleName, test.id, test.arn, test.use)
					}); err != nil {
						t.Fatal(err)
					}
					assertRole()
				})
			}
			want.LastUsed = iam.RoleLastUse{Date: used.Add(time.Nanosecond), Region: "ap-south-1"}
			if err := repository.Update(ctx, func(tx iam.WriteTx) error {
				return tx.RecordRoleUse(scope, "USED-ROLE", role.RoleId, role.Arn, want.LastUsed)
			}); err != nil {
				t.Fatal(err)
			}
			assertRole()
		})
	}
}

func TestCredentialUsageUpdatesOnlyScalarMetadata(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			var repository iam.Repository
			var guardAggregateWrites func()
			if backend == "memory" {
				repository = iam.NewMemoryRepository(nil)
			} else {
				db, err := sqlitestore.Open(ctx, filepath.Join(t.TempDir(), "iam.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := db.Close(); err != nil {
						t.Error(err)
					}
				})
				repository = newSQLiteIAMRepository(t, db)
				guardAggregateWrites = func() {
					_, err := db.ExecContext(ctx, `CREATE TRIGGER reject_credential_usage_rewrite BEFORE DELETE ON iam_credential
BEGIN SELECT RAISE(ABORT, 'usage rewrote the credential aggregate'); END`)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			role := iam.Role{RoleName: "credential-use", RoleId: "AROACREDENTIALUSE", Arn: "arn:aws:iam::123456789012:role/credential-use"}
			if err := repository.Update(ctx, func(tx iam.WriteTx) error { return tx.PutRole(scope, role) }); err != nil {
				t.Fatal(err)
			}
			credentials := iam.NewCredentialRepository(repository, nil)
			instant := time.Date(2037, 4, 5, 6, 7, 8, 123456789, time.UTC)
			manual := clock.NewManual(instant)
			store := identity.NewWithConfig(identity.Config{AccountID: scope.AccountID, Repository: credentials, Clock: manual})
			record := identity.Record{Credential: identity.Credential{
				AccessKeyID: "ASIACREDENTIALUSE", SecretAccessKey: "retain-secret", SessionToken: "retain-token",
				AccountID: scope.AccountID, PrincipalID: role.RoleId + ":session", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/credential-use/session",
				IssuerID: role.RoleId, IssuerARN: role.Arn, SessionType: identity.SessionTypeAssumeRole,
				CreateDate: instant.Add(-2 * time.Hour), Expiration: instant.Add(-time.Hour),
				SessionPolicies:   []string{`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`},
				SessionPolicyARNs: []string{"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"}, HasSessionPolicy: true,
				SessionContext: map[string][]string{"aws:PrincipalTag/project": {"sample"}}, SessionTags: map[string]string{"project": "sample"},
				TransitiveTagKeys: []string{"project"}, SourceIdentity: "retain-source", MFAPresent: true,
				MFAAuthenticatedAt: instant.Add(-time.Hour), RequestParentEventID: "retain-parent",
			}, Status: identity.Inactive, CloudFormationOwner: "retain-owner"}
			if err := credentials.Update(ctx, func(tx identity.Transaction) error { return tx.Put(record) }); err != nil {
				t.Fatal(err)
			}
			read := func() identity.Record {
				t.Helper()
				var result identity.Record
				if err := credentials.View(ctx, func(tx identity.Reader) error {
					var err error
					result, err = tx.Get(record.Credential.AccessKeyID)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				return result
			}
			want := read()
			if guardAggregateWrites != nil {
				guardAggregateWrites()
			}
			// Accepted work still records use after deactivation/expiry; this is
			// bookkeeping, not a second credential authentication.
			if err := store.RecordUsage(ctx, record.Credential.AccessKeyID, "s3", "eu-west-1"); err != nil {
				t.Fatal(err)
			}
			want.LastUsed = identity.LastUsed{Date: instant, Service: "s3", Region: "eu-west-1"}
			if got := read(); !reflect.DeepEqual(got, want) {
				t.Fatalf("usage changed credential/session state: got=%+v want=%+v", got, want)
			}
			assertRole := func() {
				t.Helper()
				if err := repository.View(ctx, func(tx iam.ReadTx) error {
					got, err := tx.Role(scope, role.RoleName)
					if err == nil && (got.LastUsed.Region != want.LastUsed.Region || !got.LastUsed.Date.Equal(want.LastUsed.Date)) {
						t.Fatalf("role and credential usage diverged: %+v", got.LastUsed)
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			assertRole()
			if err := manual.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			abort := errors.New("abort scalar credential use")
			err := store.WithTransaction(ctx, func(ctx context.Context, borrowed *identity.Store, _ time.Time) error {
				if err := borrowed.RecordUsage(ctx, record.Credential.AccessKeyID, "kms", "ap-south-1"); err != nil {
					return err
				}
				return abort
			})
			if !errors.Is(err, abort) {
				t.Fatal(err)
			}
			if got := read(); !reflect.DeepEqual(got, want) {
				t.Fatalf("aborted usage changed credential/session state: got=%+v want=%+v", got, want)
			}
			assertRole()
			if err := repository.Update(ctx, func(tx iam.WriteTx) error {
				return tx.PutCredentialUsage("missing-credential", want.LastUsed)
			}); !errors.Is(err, identity.ErrNotFound) {
				t.Fatalf("missing credential usage=%v", err)
			}
		})
	}
}
