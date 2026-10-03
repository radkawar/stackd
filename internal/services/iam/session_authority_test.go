package iam

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

type sessionAuthorityRepository struct {
	Repository
	beforeUpdate func()
	beforeCommit func() error
}

func (r *sessionAuthorityRepository) Attempt(ctx context.Context, fn func(WriteTx) error) error {
	if r.beforeUpdate != nil {
		r.beforeUpdate()
	}
	return r.Repository.Attempt(ctx, func(tx WriteTx) error {
		if err := fn(tx); err != nil {
			return err
		}
		if r.beforeCommit != nil {
			return r.beforeCommit()
		}
		return nil
	})
}

type sessionAuthorityClock struct {
	*clock.Manual
	reads atomic.Int32
}

func (c *sessionAuthorityClock) Now() time.Time { c.reads.Add(1); return c.Manual.Now() }

type sessionAuthorityFixture struct {
	service                               *Service
	repository                            *sessionAuthorityRepository
	store                                 *identity.Store
	source                                *sessionAuthorityClock
	ctx                                   context.Context
	scope, targetScope                    Scope
	user                                  User
	role                                  Role
	device                                MFADevice
	parent                                identity.Credential
	policyARN, sessionPolicyARN, document string
}

func newSessionAuthorityFixture(t *testing.T, partition string, epoch time.Time) sessionAuthorityFixture {
	t.Helper()
	f := sessionAuthorityFixture{repository: &sessionAuthorityRepository{Repository: NewMemoryRepository(nil)}, source: &sessionAuthorityClock{Manual: clock.NewManual(epoch)}, scope: Scope{Partition: partition, AccountID: "123456789012"}, targetScope: Scope{Partition: partition, AccountID: "999999999999"}}
	f.policyARN = "arn:" + partition + ":iam::" + f.scope.AccountID + ":policy/current"
	f.sessionPolicyARN = "arn:" + partition + ":iam::" + f.targetScope.AccountID + ":policy/session"
	f.document = `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`
	f.user = User{Arn: "arn:" + partition + ":iam::" + f.scope.AccountID + ":user/caller", UserId: "AIDASESSIONCALLER", UserName: "caller", IdentityPolicies: IdentityPolicies{Attached: map[string]struct{}{f.policyARN: {}}}}
	f.role = Role{Arn: "arn:" + partition + ":iam::" + f.targetScope.AccountID + ":role/target", RoleId: "AROASESSIONTARGET", RoleName: "target", MaxSessionDuration: 3600, AssumeRolePolicyDocument: fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":"sts:AssumeRole"}}`, f.user.Arn), Tags: []Tag{{Key: "team", Value: "original"}}}
	f.device = MFADevice{SerialNumber: "arn:" + partition + ":iam::" + f.scope.AccountID + ":mfa/caller", Binding: Propagated[MFABinding]{Value: MFABinding{UserID: f.user.UserId, Seed: "12345678901234567890"}, VisibleValue: MFABinding{UserID: f.user.UserId, Seed: "12345678901234567890"}}}
	f.parent = identity.Credential{AccessKeyID: "AKIASESSIONAUTHORITY", SecretAccessKey: "test-only-secret", AccountID: f.scope.AccountID, PrincipalARN: f.user.Arn, PrincipalID: f.user.UserId, UserName: f.user.UserName, CreateDate: epoch}
	f.ctx = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: partition, AccountID: f.scope.AccountID, Region: "eu-west-1", PrincipalARN: f.user.Arn, PrincipalID: f.user.UserId, UserName: f.user.UserName, AccessKeyID: f.parent.AccessKeyID, SourceIdentity: "preserved-source", TransportKnown: true, SourceIP: "192.0.2.1", SecureTransport: true})
	f.store = identity.NewWithConfig(identity.Config{AccountID: f.scope.AccountID, Repository: NewCredentialRepository(f.repository, nil), Clock: f.source})
	if err := f.repository.Update(f.ctx, func(tx WriteTx) error {
		if err := tx.PutUser(f.scope, f.user); err != nil {
			return err
		}
		if err := tx.PutRole(f.targetScope, f.role); err != nil {
			return err
		}
		if err := tx.PutMFADevice(f.scope, f.device); err != nil {
			return err
		}
		for _, policy := range []struct {
			scope Scope
			arn   string
		}{{f.scope, f.policyARN}, {f.targetScope, f.sessionPolicyARN}} {
			if err := tx.PutManagedPolicy(policy.scope, ManagedPolicy{Arn: policy.arn, DefaultVersionId: "v2", Versions: map[string]*PolicyVersion{"v1": {Document: "old document"}, "v2": {Document: f.document}}}); err != nil {
				return err
			}
		}
		return tx.PutCredential(identity.Record{Credential: f.parent, Status: identity.Active})
	}); err != nil {
		t.Fatal(err)
	}
	f.service = NewWithConfig(Config{Repository: f.repository, Credentials: f.store, Clock: f.source})
	f.source.reads.Store(0)
	return f
}

func TestIAMSessionAuthorityBorrowedStateAndMetadata(t *testing.T) {
	for _, partition := range []string{"aws", "aws-cn"} {
		for _, epoch := range []time.Time{time.Date(2035, 2, 3, 4, 5, 0, 0, time.UTC), {}} {
			t.Run(partition+"/"+epoch.Format(time.RFC3339), func(t *testing.T) {
				f := newSessionAuthorityFixture(t, partition, epoch)
				var issued []identity.Credential
				err := f.service.WithSession(f.ctx, func(ctx context.Context, repository identity.Repository, now time.Time) error {
					if !reflect.DeepEqual(awsctx.FromContext(ctx), awsctx.FromContext(f.ctx)) || !now.Equal(epoch) {
						t.Fatal("callback changed caller metadata or transaction time")
					}
					if err := f.source.Advance(time.Hour); err != nil {
						return err
					}
					policies, err := f.service.IdentityPolicies(ctx)
					if err != nil {
						return err
					}
					if len(policies.Identity) != 1 || policies.Identity[0].Document != f.document {
						t.Fatal("current attached policy default not used")
					}
					role, err := f.service.RoleForAssumption(ctx, f.role.Arn)
					if err != nil {
						return err
					}
					if role.ID != f.role.RoleId || role.TrustPolicy != f.role.AssumeRolePolicyDocument {
						t.Fatal("cross-account current role not resolved")
					}
					role.Tags["team"] = "detached mutation"
					metadata := awsctx.FromContext(ctx)
					metadata.AccountID = f.targetScope.AccountID
					documents, err := f.service.ResolveManagedPolicyDocuments(awsctx.WithMetadata(ctx, metadata), []string{f.sessionPolicyARN})
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(documents, []string{f.document}) {
						t.Fatal("destination session policy did not share transaction")
					}
					at, err := f.service.VerifyMFA(ctx, f.device.SerialNumber, totp([]byte(f.device.Binding.Value.Seed), epoch.Unix()/30))
					if err != nil {
						return err
					}
					if !at.Equal(now) {
						t.Fatal("MFA sampled a different instant")
					}
					store := f.store.WithRepositoryAt(repository, now)
					parent, err := store.Resolve(ctx, f.parent.AccessKeyID)
					if err != nil {
						return err
					}
					mfa, err := store.IssueSession(ctx, parent, identity.SessionSpec{Duration: time.Hour, MFAPresent: true, MFAAuthenticatedAt: at})
					if err != nil {
						return err
					}
					roleSession, err := store.IssueRoleSession(ctx, parent, identity.RoleSessionSpec{Role: identity.Principal{AccountID: f.targetScope.AccountID, ARN: role.ARN, ID: role.ID}, SessionName: "authority", Duration: time.Hour, MaxSessionDuration: role.MaxSessionDuration, Policies: documents})
					if err != nil {
						return err
					}
					federated, err := store.IssueFederation(ctx, parent, identity.FederationSpec{Name: "authority", Duration: time.Hour, Policies: documents})
					if err != nil {
						return err
					}
					issued = []identity.Credential{mfa, roleSession, federated}
					for _, credential := range issued {
						if !credential.CreateDate.Equal(now) || !credential.Expiration.Equal(now.Add(time.Hour)) {
							t.Fatal("credential issuance did not share captured instant")
						}
					}
					if !mfa.MFAPresent || !mfa.MFAAuthenticatedAt.Equal(epoch) {
						t.Fatal("explicit MFA instant lost")
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := f.repository.View(f.ctx, func(tx ReadTx) error {
					for _, credential := range issued {
						if _, err := tx.Credential(credential.AccessKeyID); err != nil {
							return err
						}
					}
					role, err := tx.Role(f.targetScope, f.role.RoleName)
					if err == nil && role.Tags[0].Value != "original" {
						t.Fatal("borrowed role snapshot leaked mutation")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestIAMSessionAuthorityLifetimeAndReentry(t *testing.T) {
	f := newSessionAuthorityFixture(t, "aws", time.Time{})
	var retainedContext context.Context
	var retainedRepository identity.Repository
	var retainedReader identity.Reader
	var retainedWriter identity.Transaction
	err := f.service.WithSession(f.ctx, func(ctx context.Context, repository identity.Repository, _ time.Time) error {
		retainedContext, retainedRepository = ctx, repository
		if err := f.service.WithSession(ctx, func(context.Context, identity.Repository, time.Time) error {
			t.Fatal("nested session callback ran")
			return nil
		}); err == nil {
			t.Fatal("nested authority accepted")
		}
		if err := repository.Update(ctx, func(tx identity.Transaction) error { retainedWriter = tx; return nil }); err != nil {
			return err
		}
		return repository.View(ctx, func(tx identity.Reader) error { retainedReader = tx; return nil })
	})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(retainedContext.Err(), context.Canceled) {
		t.Fatal("authority context remained live")
	}
	if err := retainedRepository.View(context.Background(), func(identity.Reader) error { t.Fatal("escaped repository view ran"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := retainedRepository.Update(context.Background(), func(identity.Transaction) error { t.Fatal("escaped repository write ran"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := retainedReader.Get(f.parent.AccessKeyID); !errors.Is(err, ErrClosedTransaction) {
		t.Fatal(err)
	}
	if err := retainedWriter.Delete(f.parent.AccessKeyID); !errors.Is(err, ErrClosedTransaction) {
		t.Fatal(err)
	}
	if _, err := f.service.RoleForAssumption(retainedContext, f.role.Arn); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := f.service.WithSession(f.ctx, nil); err == nil {
		t.Fatal("nil callback accepted")
	}
}

func TestIAMSessionAuthorityCredentialPartitionRemainsBound(t *testing.T) {
	f := newSessionAuthorityFixture(t, "aws", time.Time{})
	foreign := f.parent
	foreign.AccessKeyID = "AKIAFOREIGNPARTITION"
	foreign.PrincipalARN = "arn:aws-cn:iam::123456789012:user/caller"
	if err := f.repository.Update(f.ctx, func(tx WriteTx) error {
		return tx.PutCredential(identity.Record{Credential: foreign, Status: identity.Active})
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.service.WithSession(f.ctx, func(ctx context.Context, repository identity.Repository, now time.Time) error {
		metadata := awsctx.FromContext(ctx)
		metadata.Partition = "aws-cn"
		otherPartition := awsctx.WithMetadata(ctx, metadata)
		store := f.store.WithRepositoryAt(repository, now)
		if _, err := store.Resolve(otherPartition, foreign.AccessKeyID); !errors.Is(err, identity.ErrNotFound) {
			t.Fatalf("derived context changed borrowed credential partition: %v", err)
		}
		if _, err := store.Resolve(context.Background(), foreign.AccessKeyID); !errors.Is(err, identity.ErrNotFound) {
			t.Fatalf("empty context escaped borrowed credential partition: %v", err)
		}
		_, err := store.Resolve(otherPartition, f.parent.AccessKeyID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
