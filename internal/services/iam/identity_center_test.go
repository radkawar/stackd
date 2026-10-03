package iam_test

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"stackd/internal/services/iam"
	"stackd/storage/sqlite"
	sqliteiam "stackd/storage/sqlite/iam"
)

func TestIdentityCenterRoleLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repository iam.Repository = iam.NewMemoryRepository(nil)
			reopen := func() {}
			if backend == "sqlite" {
				path := filepath.Join(t.TempDir(), "identity-center.db")
				db, err := sqlite.Open(t.Context(), path)
				if err != nil {
					t.Fatal(err)
				}
				repository = sqliteiam.New(db)
				t.Cleanup(func() { _ = db.Close() })
				reopen = func() {
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					repository = sqliteiam.New(db)
				}
			}
			spec := iam.IdentityCenterRoleSpec{
				Scope: iam.Scope{Partition: "aws", AccountID: "123456789012"}, Region: "eu-west-2",
				InstanceARN: "arn:aws:sso:::instance/ssoins-0123456789abcdef", PermissionSetARN: "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-0123456789abcdef",
				Name: "DatabaseAdministrator", Duration: 2 * time.Hour,
				InlinePolicy:            `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`,
				ManagedPolicies:         []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
				CustomerManagedPolicies: []iam.IdentityCenterPolicyReference{{Name: "Database", Path: "/access/"}},
				Boundary:                iam.IdentityCenterPolicyReference{Name: "Boundary", Path: "/access/"},
			}
			customerARN, boundaryARN := "arn:aws:iam::123456789012:policy/access/Database", "arn:aws:iam::123456789012:policy/access/Boundary"
			if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
				for name, arn := range map[string]string{"Database": customerARN, "Boundary": boundaryARN} {
					if err := tx.PutManagedPolicy(spec.Scope, iam.ManagedPolicy{Arn: arn, PolicyName: name, Path: "/access/", IsAttachable: true, DefaultVersionId: "v1", Versions: map[string]*iam.PolicyVersion{"v1": {Document: `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}}}); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			service := iam.NewWithRepository(nil, repository)
			created, err := service.ProvisionIdentityCenterRole(t.Context(), spec)
			if err != nil {
				t.Fatal(err)
			}
			if !regexp.MustCompile(`^AWSReservedSSO_DatabaseAdministrator_[0-9a-f]{16}$`).MatchString(created.RoleName) || created.Path != "/aws-reserved/sso.amazonaws.com/eu-west-2/" || created.Arn != "arn:aws:iam::123456789012:role"+created.Path+created.RoleName || created.RoleId == "" {
				t.Fatalf("incorrect reserved-role incarnation: %+v", created)
			}
			ref := iam.IdentityCenterRoleRef{Scope: spec.Scope, InstanceARN: spec.InstanceARN, PermissionSetARN: spec.PermissionSetARN, ARN: created.Arn, ID: created.RoleId, Name: created.RoleName}
			checkUsage := func(attachments, boundaries int) {
				t.Helper()
				if err := repository.View(t.Context(), func(tx iam.ReadTx) error {
					p, err := tx.ManagedPolicy(spec.Scope, customerARN)
					if err != nil {
						return err
					}
					b, err := tx.ManagedPolicy(spec.Scope, boundaryARN)
					if err != nil {
						return err
					}
					if p.AttachmentCount != attachments || b.PermissionsBoundaryUsageCount != boundaries {
						t.Fatalf("incorrect policy usage: attachment=%d boundary=%d", p.AttachmentCount, b.PermissionsBoundaryUsageCount)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			checkUsage(1, 1)
			reopen()
			service = iam.NewWithRepository(nil, repository)
			retained, err := service.IdentityCenterRole(t.Context(), ref)
			if err != nil {
				t.Fatal(err)
			}
			if retained.Inline["AwsSSOInlinePolicy"] != spec.InlinePolicy || retained.PermissionsBoundary == nil || retained.PermissionsBoundary.PermissionsBoundaryArn != boundaryARN || retained.MaxSessionDuration != 7200 {
				t.Fatalf("lost provisioned authority after reopen: %+v", retained)
			}
			bad := spec
			bad.Duration, bad.InlinePolicy = 3*time.Hour, `{"Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*"}}`
			bad.CustomerManagedPolicies = []iam.IdentityCenterPolicyReference{{Name: "Missing"}}
			if _, err := service.ProvisionIdentityCenterRole(t.Context(), bad); err == nil {
				t.Fatal("missing target-account customer policy accepted")
			}
			retained, err = service.IdentityCenterRole(t.Context(), ref)
			if err != nil || retained.MaxSessionDuration != 7200 || retained.Inline["AwsSSOInlinePolicy"] != spec.InlinePolicy {
				t.Fatalf("failed provision changed the role: %+v %v", retained, err)
			}
			checkUsage(1, 1)
			// Reconciliation retains identity but completely replaces permission-set
			// policy attachments, inline policy and boundary, without stale counters.
			spec.Duration = 4 * time.Hour
			spec.InlinePolicy, spec.ManagedPolicies, spec.CustomerManagedPolicies = "", nil, nil
			spec.Boundary = iam.IdentityCenterPolicyReference{}
			updated, err := service.ProvisionIdentityCenterRole(t.Context(), spec)
			if err != nil {
				t.Fatal(err)
			}
			if updated.RoleId != created.RoleId || updated.RoleName != created.RoleName || updated.Arn != created.Arn || !updated.CreateDate.Equal(created.CreateDate) || len(updated.Inline) != 0 || len(updated.Attached) != 0 || updated.PermissionsBoundary != nil || updated.MaxSessionDuration != 14400 {
				t.Fatalf("update replaced identity or retained obsolete authority: %+v", updated)
			}
			checkUsage(0, 0)
			// A service callback borrows the caller's transaction; aborting the parent
			// must roll back role deletion, not strand a committed IAM side effect.
			abort := errors.New("abort enclosing assignment")
			if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
				if err := service.RemoveIdentityCenterRole(tx.Context(), ref); err != nil {
					return err
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatal(err)
			}
			if _, err := service.IdentityCenterRole(t.Context(), ref); err != nil {
				t.Fatalf("parent rollback lost role: %v", err)
			}
			wrongOwner := ref
			wrongOwner.PermissionSetARN += "-other"
			if err := service.RemoveIdentityCenterRole(t.Context(), wrongOwner); err == nil {
				t.Fatal("another permission set removed the role")
			}
			if err := service.RemoveIdentityCenterRole(t.Context(), ref); err != nil {
				t.Fatal(err)
			}
			if _, err := service.IdentityCenterRole(t.Context(), ref); !errors.Is(err, iam.ErrRecordNotFound) {
				t.Fatalf("deleted role still resolves: %v", err)
			}
			recreated, err := service.ProvisionIdentityCenterRole(t.Context(), spec)
			if err != nil {
				t.Fatal(err)
			}
			if recreated.RoleName == created.RoleName || recreated.Arn == created.Arn || recreated.RoleId == created.RoleId {
				t.Fatal("recreated role reused the deleted incarnation")
			}
			if err := service.RemoveIdentityCenterRole(t.Context(), ref); err != nil {
				t.Fatal(err)
			}
			recreatedRef := ref
			recreatedRef.Name, recreatedRef.ARN, recreatedRef.ID = recreated.RoleName, recreated.Arn, recreated.RoleId
			if _, err := service.IdentityCenterRole(t.Context(), recreatedRef); err != nil {
				t.Fatalf("stale deletion affected new role: %v", err)
			}
			// An unrelated role under the old name cannot be seized by the stale ref.
			unrelated := created
			unrelated.IdentityCenterInstanceARN, unrelated.IdentityCenterPermissionSetARN = "", ""
			if err := repository.Update(t.Context(), func(tx iam.WriteTx) error { return tx.PutRole(spec.Scope, unrelated) }); err != nil {
				t.Fatal(err)
			}
			if err := service.RemoveIdentityCenterRole(t.Context(), ref); err == nil {
				t.Fatal("unrelated role collision accepted as owned")
			}
		})
	}
}

func TestIdentityCenterRoleUSEastPathAndScope(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	service := iam.NewWithRepository(nil, repository)
	spec := iam.IdentityCenterRoleSpec{Scope: iam.Scope{Partition: "aws", AccountID: "123456789012"}, Region: "us-east-1", InstanceARN: "arn:aws:sso:::instance/ssoins-0123456789abcdef", PermissionSetARN: "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-0123456789abcdef", Name: "Reader", Duration: time.Hour}
	first, err := service.ProvisionIdentityCenterRole(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if first.Path != "/aws-reserved/sso.amazonaws.com/" {
		t.Fatalf("us-east-1 role path: %s", first.Path)
	}
	spec.AccountID = "111122223333"
	second, err := service.ProvisionIdentityCenterRole(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if second.RoleId == first.RoleId || second.Arn == first.Arn || second.Arn != "arn:aws:iam::111122223333:role"+second.Path+second.RoleName {
		t.Fatal("target accounts shared a role incarnation")
	}
	spec.Region = "eu-west-2"
	if _, err := service.ProvisionIdentityCenterRole(t.Context(), spec); err == nil {
		t.Fatal("inconsistent owner region moved the reserved role")
	}
}
