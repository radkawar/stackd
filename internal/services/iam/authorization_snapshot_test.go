package iam_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
	sqlitestore "stackd/storage/sqlite"
	sqliteiam "stackd/storage/sqlite/iam"
)

func newSQLiteIAMRepository(t *testing.T, db *sql.DB) *sqliteiam.Repository {
	t.Helper()
	repository, err := sqliteiam.New(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

// Authorization must not reconstruct an account-wide IAM working set. These
// guards are deterministic: the regression fails without timing a large account.
type narrowPolicyRepository struct{ iam.Repository }

type narrowPolicyReadTx struct{ iam.ReadTx }

var errPolicyEnumeration = errors.New("identity authorization enumerated account resources")

func (r narrowPolicyRepository) View(ctx context.Context, fn func(iam.ReadTx) error) error {
	return r.Repository.View(ctx, func(tx iam.ReadTx) error { return fn(narrowPolicyReadTx{tx}) })
}

func (narrowPolicyReadTx) SigningCertificates(iam.Scope) ([]iam.SigningCertificateRecord, error) {
	return nil, errPolicyEnumeration
}
func (narrowPolicyReadTx) Users(iam.Scope) ([]iam.User, error) {
	return nil, errPolicyEnumeration
}
func (narrowPolicyReadTx) Groups(iam.Scope) ([]iam.Group, error) {
	return nil, errPolicyEnumeration
}
func (narrowPolicyReadTx) Roles(iam.Scope) ([]iam.Role, error) {
	return nil, errPolicyEnumeration
}
func (narrowPolicyReadTx) ManagedPolicies(iam.Scope) ([]iam.ManagedPolicy, error) {
	return nil, errPolicyEnumeration
}

func identitySnapshotRepository(t *testing.T, backend string) iam.Repository {
	t.Helper()
	if backend == "memory" {
		return iam.NewMemoryRepository(nil)
	}
	db, err := sqlitestore.Open(t.Context(), filepath.Join(t.TempDir(), "iam.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return newSQLiteIAMRepository(t, db)
}

func TestIdentityPolicySnapshotReadsOnlyCurrentPrincipal(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			repository := identitySnapshotRepository(t, backend)
			service := iam.NewWithRepository(nil, narrowPolicyRepository{repository})
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			accessARN := "arn:aws:iam::123456789012:policy/access"
			boundaryARN := "arn:aws:iam::123456789012:policy/limit"
			awsARN := "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
			allow := `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`
			deny := `{"Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}`
			user := iam.User{UserName: "Reader", UserId: "AIDAREADER", Arn: "arn:aws:iam::123456789012:user/path/Reader", Tags: []iam.Tag{{Key: "team", Value: "sample"}}, PermissionsBoundary: &iam.Boundary{PermissionsBoundaryArn: boundaryARN}, IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"inline": allow}, Attached: map[string]struct{}{awsARN: {}}}}
			group := iam.Group{GroupName: "Readers", GroupId: "AGPAREADERS", Arn: "arn:aws:iam::123456789012:group/path/Readers", Members: map[string]struct{}{"reader": {}}, IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"group": allow}, Attached: map[string]struct{}{accessARN: {}}}}
			access := iam.ManagedPolicy{Arn: accessARN, PolicyName: "access", DefaultVersionId: "v1", Versions: map[string]*iam.PolicyVersion{"v1": {VersionId: "v1", Document: allow}, "v2": {VersionId: "v2", Document: deny}}}
			if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
				if err := tx.PutUser(scope, user); err != nil {
					return err
				}
				if err := tx.PutGroup(scope, group); err != nil {
					return err
				}
				// Neither a nonmember nor another namespace contributes a policy.
				other := group
				other.GroupName, other.GroupId, other.Arn = "Other", "AGPAOTHER", "arn:aws:iam::123456789012:group/Other"
				other.Members = map[string]struct{}{"somebody-else": {}}
				other.Inline = map[string]string{"unrelated-deny": deny}
				if err := tx.PutGroup(scope, other); err != nil {
					return err
				}
				if err := tx.PutGroup(iam.Scope{Partition: "aws-cn", AccountID: scope.AccountID}, group); err != nil {
					return err
				}
				if err := tx.PutGroup(iam.Scope{Partition: scope.Partition, AccountID: "999999999999"}, group); err != nil {
					return err
				}
				if err := tx.PutManagedPolicy(scope, access); err != nil {
					return err
				}
				if err := tx.PutManagedPolicy(scope, iam.ManagedPolicy{Arn: boundaryARN, PolicyName: "limit", DefaultVersionId: "v1", Versions: map[string]*iam.PolicyVersion{"v1": {VersionId: "v1", Document: allow}}}); err != nil {
					return err
				}
				return tx.PutAccountSettings(scope, iam.AccountSettingsRecord{PasswordPolicy: &iam.AccountPasswordPolicy{AllowUsersToChangePassword: true}})
			}); err != nil {
				t.Fatal(err)
			}
			metadata := awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, PrincipalARN: user.Arn, PrincipalID: user.UserId, SessionPolicyARNs: []string{accessARN}}
			ctx := awsctx.WithMetadata(t.Context(), metadata)
			before, err := service.IdentityPolicies(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(before.Identity) != 5 || !before.HasBoundary || len(before.Boundary) != 1 || before.Boundary[0].Source != boundaryARN || before.PrincipalTags["team"] != "sample" || before.ServiceLinkedRole {
				t.Fatalf("user policy snapshot: %+v", before)
			}
			if !slices.IsSortedFunc(before.Identity, func(a, b iampolicy.Policy) int { return strings.Compare(a.Source, b.Source) }) {
				t.Fatal("policy sources are not sorted")
			}
			if !slices.ContainsFunc(before.Identity, func(p iampolicy.Policy) bool { return p.Source == awsARN && p.Version != "" && p.Document != "" }) || !slices.ContainsFunc(before.Identity, func(p iampolicy.Policy) bool { return p.Source == user.Arn+"#account-password-self-management" }) {
				t.Fatalf("AWS or password-self-management policy missing: %+v", before.Identity)
			}
			if len(before.ManagedSession) != 1 || before.ManagedSession[0].Version != "v1" || before.ManagedSession[0].Document != allow {
				t.Fatalf("managed session snapshot: %+v", before.ManagedSession)
			}
			abort := errors.New("abort authorization mutation")
			err = repository.Update(t.Context(), func(tx iam.WriteTx) error {
				access.DefaultVersionId = "v2"
				if err := tx.PutManagedPolicy(scope, access); err != nil {
					return err
				}
				inside, err := service.IdentityPolicies(awsctx.WithMetadata(tx.Context(), metadata))
				if err != nil {
					return err
				}
				if inside.ManagedSession[0].Version != "v2" || inside.ManagedSession[0].Document != deny || !slices.ContainsFunc(inside.Identity, func(p iampolicy.Policy) bool { return p.Source == accessARN && p.Version == "v2" && p.Document == deny }) {
					t.Fatalf("borrowed transaction mixed policy versions: %+v", inside)
				}
				return abort
			})
			if !errors.Is(err, abort) {
				t.Fatal(err)
			}
			after, err := service.IdentityPolicies(ctx)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("rolled-back policy snapshot changed: %+v, %v", after, err)
			}
			if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
				if err := tx.PutManagedPolicy(scope, access); err != nil {
					return err
				}
				group.Members = nil
				return tx.PutGroup(scope, group)
			}); err != nil {
				t.Fatal(err)
			}
			after, err = service.IdentityPolicies(ctx)
			if err != nil || len(after.Identity) != 3 || after.ManagedSession[0].Version != "v2" || after.ManagedSession[0].Document != deny {
				t.Fatalf("current membership/session policy not observed: %+v, %v", after, err)
			}
			after.PrincipalTags["team"] = "changed"
			after.Identity[0].Document = "changed"
			again, err := service.IdentityPolicies(ctx)
			if err != nil || again.PrincipalTags["team"] != "sample" || again.Identity[0].Document == "changed" {
				t.Fatalf("snapshot aliases repository state: %+v, %v", again, err)
			}
			metadata.PrincipalID = "AIDARECREATED"
			if _, err := service.IdentityPolicies(awsctx.WithMetadata(t.Context(), metadata)); err == nil {
				t.Fatal("stale user identity was accepted")
			}
		})
	}
}

func TestIdentityPolicySnapshotRoleRootAndMissingPolicies(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			repository := identitySnapshotRepository(t, backend)
			service := iam.NewWithRepository(nil, narrowPolicyRepository{repository})
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			policyARN := "arn:aws:iam::123456789012:policy/read"
			role := iam.Role{RoleName: "Reader", RoleId: "AROAREADER", Arn: "arn:aws:iam::123456789012:role/path/Reader", ServiceLinkedService: "example.amazonaws.com", Tags: []iam.Tag{{Key: "team", Value: "sample"}}, PermissionsBoundary: &iam.Boundary{PermissionsBoundaryArn: policyARN}, IdentityPolicies: iam.IdentityPolicies{Attached: map[string]struct{}{policyARN: {}}}}
			policy := iam.ManagedPolicy{Arn: policyARN, PolicyName: "read", DefaultVersionId: "v1", Versions: map[string]*iam.PolicyVersion{"v1": {Document: `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`}}}
			if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
				if err := tx.PutRole(scope, role); err != nil {
					return err
				}
				return tx.PutManagedPolicy(scope, policy)
			}); err != nil {
				t.Fatal(err)
			}
			// Issuer resolution follows the STS ARN, not a SessionType shortcut.
			metadata := awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, PrincipalARN: "arn:aws:sts::123456789012:federated-user/session", PrincipalID: "session", IssuerARN: role.Arn, IssuerID: role.RoleId}
			ctx := awsctx.WithMetadata(t.Context(), metadata)
			set, err := service.IdentityPolicies(ctx)
			if err != nil || len(set.Identity) != 1 || len(set.Boundary) != 1 || !set.HasBoundary || !set.ServiceLinkedRole || set.PrincipalTags["team"] != "sample" {
				t.Fatalf("role snapshot: %+v, %v", set, err)
			}
			direct := metadata
			direct.PrincipalARN, direct.PrincipalID = role.Arn, role.RoleId
			direct.IssuerARN, direct.IssuerID = "", ""
			if actual, err := service.IdentityPolicies(awsctx.WithMetadata(t.Context(), direct)); err != nil || !reflect.DeepEqual(set, actual) {
				t.Fatalf("direct role snapshot differs from STS issuer: %+v, %v", actual, err)
			}
			for _, mutation := range []func(*awsctx.Metadata){
				func(m *awsctx.Metadata) { m.IssuerID = "AROARECREATED" },
				func(m *awsctx.Metadata) { m.IssuerARN = "arn:aws:iam::123456789012:role/other/Reader" },
				func(m *awsctx.Metadata) { m.Partition = "aws-cn" },
				func(m *awsctx.Metadata) { m.AccountID = "999999999999" },
			} {
				changed := metadata
				mutation(&changed)
				if _, err := service.IdentityPolicies(awsctx.WithMetadata(t.Context(), changed)); err == nil {
					t.Fatalf("mismatched identity accepted: %+v", changed)
				}
			}
			root, err := service.IdentityPolicies(authRootContext("aws"))
			if err != nil || len(root.Identity) != 1 || root.HasBoundary || root.ServiceLinkedRole {
				t.Fatalf("root snapshot: %+v, %v", root, err)
			}
			for _, changed := range []awsctx.Metadata{
				{Partition: scope.Partition, AccountID: scope.AccountID, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "999999999999"},
				{Partition: scope.Partition, AccountID: scope.AccountID, PrincipalARN: "arn:aws:iam::999999999999:root", PrincipalID: scope.AccountID},
			} {
				if _, err := service.IdentityPolicies(awsctx.WithMetadata(t.Context(), changed)); err == nil {
					t.Fatalf("mismatched root accepted: %+v", changed)
				}
			}
			chinaRoot := awsctx.FromContext(authRootContext("aws-cn"))
			chinaRoot.SessionPolicyARNs = []string{"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"}
			if _, err := service.IdentityPolicies(awsctx.WithMetadata(t.Context(), chinaRoot)); err == nil {
				t.Fatal("AWS-managed fallback crossed partitions")
			}
			chinaRoot.SessionPolicyARNs = []string{"arn:aws-cn:iam::aws:policy/AmazonS3ReadOnlyAccess"}
			if _, err := service.IdentityPolicies(awsctx.WithMetadata(t.Context(), chinaRoot)); err == nil {
				t.Fatal("an uncaptured partition received a fabricated managed policy")
			}
			policy.DefaultVersionId = "missing"
			if err := repository.Update(t.Context(), func(tx iam.WriteTx) error { return tx.PutManagedPolicy(scope, policy) }); err != nil {
				t.Fatal(err)
			}
			if _, err := service.IdentityPolicies(ctx); err == nil || !strings.Contains(err.Error(), "default version") {
				t.Fatalf("missing default policy version: %v", err)
			}
			if err := repository.Update(t.Context(), func(tx iam.WriteTx) error { return tx.DeleteManagedPolicy(scope, policyARN) }); err != nil {
				t.Fatal(err)
			}
			if _, err := service.IdentityPolicies(ctx); err == nil || !strings.Contains(err.Error(), "managed policy does not exist") {
				t.Fatalf("missing attached policy: %v", err)
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if _, err := service.IdentityPolicies(canceled); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled snapshot: %v", err)
			}
		})
	}
}

var _ authorization.IdentitySource = (*iam.Service)(nil)
