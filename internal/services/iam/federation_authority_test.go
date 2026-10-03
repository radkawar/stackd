package iam_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

type federationAuthorityFixture struct {
	service    *iam.Service
	repository iam.Repository
	scope      iam.Scope
	ctx        context.Context
	provider   iam.OIDCProviderRecord
	role       iam.Role
}

func newFederationAuthorityFixture(t *testing.T, repository iam.Repository) federationAuthorityFixture {
	t.Helper()
	if repository == nil {
		repository = iam.NewMemoryRepository(nil)
	}
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	provider := iam.OIDCProviderRecord{ARN: "arn:aws:iam::123456789012:oidc-provider/issuer.test", ID: "AOIDoriginal", URL: "issuer.test", ClientIDs: []string{"audience"}, Thumbprints: []string{"thumbprint"}}
	role := iam.Role{Arn: "arn:aws:iam::123456789012:role/federation/target", RoleId: "AROAoriginal", RoleName: "target", Path: "/federation/", MaxSessionDuration: 3600, AssumeRolePolicyDocument: `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"` + provider.ARN + `"}}}`, TrustPrincipalIDs: map[string]string{provider.ARN: provider.ID}, Tags: []iam.Tag{{Key: "team", Value: "federation"}}}
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: scope.Partition, AccountID: "999999999999", Region: "us-east-1"})
	if err := repository.Update(ctx, func(tx iam.WriteTx) error {
		if err := tx.PutOIDCProvider(scope, provider); err != nil {
			return err
		}
		return tx.PutRole(scope, role)
	}); err != nil {
		t.Fatal(err)
	}
	return federationAuthorityFixture{service: iam.NewWithRepository(nil, repository), repository: repository, scope: scope, ctx: ctx, provider: provider, role: role}
}

func (f federationAuthorityFixture) reference() iam.FederationProviderReference {
	return iam.FederationProviderReference{ARN: f.provider.ARN, ID: f.provider.ID, Version: iam.OIDCProviderVersion(f.provider)}
}

func federationAuthorityCredential(role iam.RoleSnapshot) identity.Record {
	return identity.Record{Status: identity.Active, Credential: identity.Credential{AccessKeyID: "ASIAFEDERATIONTESTKEY", SecretAccessKey: "test-only-secret", SessionToken: "test-only-token", AccountID: "123456789012", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/target/session", PrincipalID: role.ID + ":session", IssuerARN: role.ARN, IssuerID: role.ID, SessionType: identity.SessionTypeAssumeRole, Expiration: time.Now().Add(time.Hour)}}
}

func TestIAMFederationAuthorityAtomicCommitAndBorrowedViews(t *testing.T) {
	f := newFederationAuthorityFixture(t, nil)
	policyARN := "arn:aws:iam::123456789012:policy/Session"
	document := `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}}`
	if err := f.repository.Update(f.ctx, func(tx iam.WriteTx) error {
		return tx.PutManagedPolicy(f.scope, iam.ManagedPolicy{Arn: policyARN, PolicyName: "Session", DefaultVersionId: "v1", Versions: map[string]*iam.PolicyVersion{"v1": {Document: document}}})
	}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	var retainedRepository identity.Repository
	var retainedContext context.Context
	var retainedReader identity.Reader
	var retainedWriter identity.Transaction
	err := f.service.WithFederationSession(f.ctx, f.reference(), f.role.Arn, func(ctx context.Context, role iam.RoleSnapshot, repository identity.Repository) error {
		calls++
		retainedRepository, retainedContext = repository, ctx
		metadata := awsctx.FromContext(ctx)
		if metadata.AccountID != f.scope.AccountID || metadata.Partition != f.scope.Partition || metadata.PrincipalARN != "" {
			t.Fatal("callback account scope or synthetic principal is incorrect")
		}
		current, err := f.service.RoleForAssumption(ctx, f.role.Arn)
		if err != nil {
			return err
		}
		if current.ID != role.ID || current.TrustPolicy != role.TrustPolicy {
			t.Fatal("borrowed role view differs")
		}
		policies, err := f.service.ResolveManagedPolicyDocuments(ctx, []string{policyARN})
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(policies, []string{document}) {
			t.Fatal("managed policies did not use role account transaction")
		}
		role.Tags["team"] = "caller mutation"
		role.TrustPrincipalIDs[f.provider.ARN] = "caller mutation"
		if err := repository.Update(context.Background(), func(tx identity.Transaction) error {
			retainedWriter = tx
			return tx.Put(federationAuthorityCredential(current))
		}); err != nil {
			return err
		}
		return repository.View(context.Background(), func(reader identity.Reader) error {
			retainedReader = reader
			_, err := reader.Get("ASIAFEDERATIONTESTKEY")
			return err
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("callback ran %d times", calls)
	}
	if err := f.repository.View(f.ctx, func(tx iam.ReadTx) error {
		if _, err := tx.Credential("ASIAFEDERATIONTESTKEY"); err != nil {
			return err
		}
		role, err := tx.Role(f.scope, f.role.RoleName)
		if err != nil {
			return err
		}
		if role.Tags[0].Value != "federation" || role.TrustPrincipalIDs[f.provider.ARN] != f.provider.ID {
			t.Fatal("snapshot mutation reached state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(retainedContext.Err(), context.Canceled) {
		t.Fatal("callback context remained live")
	}
	if err := retainedRepository.Update(context.Background(), func(identity.Transaction) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("expired empty Update accepted: %v", err)
	}
	if err := retainedRepository.View(context.Background(), func(identity.Reader) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("expired empty View accepted: %v", err)
	}
	if _, err := retainedReader.Get("ASIAFEDERATIONTESTKEY"); !errors.Is(err, iam.ErrClosedTransaction) {
		t.Fatalf("escaped reader accepted: %v", err)
	}
	if err := retainedWriter.Delete("ASIAFEDERATIONTESTKEY"); !errors.Is(err, iam.ErrClosedTransaction) {
		t.Fatalf("escaped writer accepted: %v", err)
	}
}

func TestIAMFederationAuthorityRollbackAndCancellation(t *testing.T) {
	failure := errors.New("callback failure")
	for _, kind := range []string{"callback", "cancellation", "commit", "pre-canceled"} {
		t.Run(kind, func(t *testing.T) {
			repository := &failingIAMRepository{Repository: iam.NewMemoryRepository(nil)}
			f := newFederationAuthorityFixture(t, repository)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			if kind == "pre-canceled" {
				cancel()
			}
			if kind == "commit" {
				repository.fail = true
			}
			calls := 0
			err := f.service.WithFederationSession(ctx, f.reference(), f.role.Arn, func(ctx context.Context, role iam.RoleSnapshot, borrowed identity.Repository) error {
				calls++
				if err := borrowed.Update(ctx, func(tx identity.Transaction) error { return tx.Put(federationAuthorityCredential(role)) }); err != nil {
					return err
				}
				if kind == "callback" {
					return failure
				}
				if kind == "cancellation" {
					cancel()
				}
				return nil
			})
			if err == nil {
				t.Fatal("failure committed")
			}
			if kind == "callback" && !errors.Is(err, failure) {
				t.Fatal(err)
			}
			if (kind == "pre-canceled" || kind == "cancellation") && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if (kind == "pre-canceled" && calls != 0) || (kind != "pre-canceled" && calls != 1) {
				t.Fatalf("wrong callback count %d", calls)
			}
			repository.fail = false
			if err := repository.View(f.ctx, func(tx iam.ReadTx) error {
				_, err := tx.Credential("ASIAFEDERATIONTESTKEY")
				if !errors.Is(err, identity.ErrNotFound) {
					t.Fatalf("uncommitted session visible: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIAMFederationAuthorityIssuedSessionContextAndExpiry(t *testing.T) {
	for _, kind := range []string{"commit", "expired", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			f := newFederationAuthorityFixture(t, nil)
			store := identity.NewWithRepository(f.scope.AccountID, iam.NewCredentialRepository(f.repository, nil))
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			notAfter := time.Now().Add(time.Minute)
			if kind == "expired" {
				notAfter = time.Now().Add(-time.Minute)
			}
			inputContext := map[string][]string{"issuer.test:aud": {"audience"}, "issuer.test:amr": {"pwd", "mfa"}}
			var issued identity.Credential
			err := f.service.WithFederationSession(ctx, f.reference(), f.role.Arn, func(ctx context.Context, role iam.RoleSnapshot, borrowed identity.Repository) error {
				var err error
				issued, err = store.WithRepository(borrowed).IssueFederatedRoleSession(ctx, identity.RoleSessionSpec{
					Role:        identity.Principal{AccountID: f.scope.AccountID, ARN: role.ARN, ID: role.ID},
					SessionName: "verified", Duration: time.Hour, MaxSessionDuration: role.MaxSessionDuration,
					NotAfter: notAfter, SessionContext: inputContext,
				})
				if err != nil {
					return err
				}
				if !issued.Expiration.Equal(notAfter) {
					t.Fatal("federation expiry was not capped by the verified assertion")
				}
				inputContext["issuer.test:aud"][0] = "input mutation"
				if issued.SessionContext["issuer.test:aud"][0] != "audience" {
					t.Fatal("issued credential shares nested claim input")
				}
				issued.SessionContext["issuer.test:amr"][0] = "output mutation"
				if kind == "canceled" {
					cancel()
				}
				return nil
			})
			switch kind {
			case "commit":
				if err != nil {
					t.Fatal(err)
				}
				current, err := store.Resolve(f.ctx, issued.AccessKeyID)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(current.SessionContext, map[string][]string{"issuer.test:aud": {"audience"}, "issuer.test:amr": {"pwd", "mfa"}}) {
					t.Fatal("input or output claim mutation reached committed credentials")
				}
				current.SessionContext["issuer.test:aud"][0] = "read mutation"
				current, err = store.Resolve(f.ctx, issued.AccessKeyID)
				if err != nil || current.SessionContext["issuer.test:aud"][0] != "audience" {
					t.Fatal("credential reads share nested session claims", err)
				}
			case "expired":
				if !errors.Is(err, identity.ErrExpired) || issued.AccessKeyID != "" {
					t.Fatalf("expired verified session was not rejected: %v", err)
				}
			case "canceled":
				if !errors.Is(err, context.Canceled) || issued.AccessKeyID == "" {
					t.Fatalf("post-issuance cancellation did not fail commit: %v", err)
				}
			}
			if kind != "commit" {
				if err := f.repository.View(f.ctx, func(tx iam.ReadTx) error {
					records, err := tx.PrincipalCredentials(f.scope.AccountID, f.role.RoleId)
					if len(records) != 0 {
						t.Fatal("failed issuance persisted credentials")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestIAMFederationAuthorityProviderFences(t *testing.T) {
	for _, kind := range []string{"deleted", "recreated", "configuration", "missing-role", "other-account", "other-partition", "bad-arn", "builtin-invalid-id", "builtin-invalid-version"} {
		t.Run(kind, func(t *testing.T) {
			f := newFederationAuthorityFixture(t, nil)
			reference := f.reference()
			roleARN := f.role.Arn
			expected := iam.ErrRecordNotFound
			switch kind {
			case "deleted":
				if err := f.repository.Update(f.ctx, func(tx iam.WriteTx) error { return tx.DeleteOIDCProvider(f.scope, f.provider.ARN) }); err != nil {
					t.Fatal(err)
				}
			case "recreated", "configuration":
				expected = iam.ErrFederationProviderChanged
				p := f.provider
				if kind == "recreated" {
					p.ID = "AOIDnew-incarnation"
				} else {
					p.ClientIDs = []string{"changed-audience"}
				}
				if err := f.repository.Update(f.ctx, func(tx iam.WriteTx) error {
					if err := tx.DeleteOIDCProvider(f.scope, p.ARN); err != nil {
						return err
					}
					return tx.PutOIDCProvider(f.scope, p)
				}); err != nil {
					t.Fatal(err)
				}
			case "missing-role":
				roleARN = "arn:aws:iam::123456789012:role/missing"
				expected = iam.ErrFederationRoleNotFound
			case "other-account":
				reference.ARN = "arn:aws:iam::999999999999:oidc-provider/issuer.test"
			case "other-partition":
				reference.ARN = "arn:aws-cn:iam::123456789012:oidc-provider/issuer.test"
			case "bad-arn":
				roleARN = "notarn:aws:iam::123456789012:role/federation/target"
			case "builtin-invalid-id":
				reference = iam.FederationProviderReference{ARN: "accounts.google.com", ID: "wrong", Version: "builtin-v1"}
				expected = iam.ErrFederationProviderChanged
			case "builtin-invalid-version":
				reference = iam.FederationProviderReference{ARN: "accounts.google.com", ID: "accounts.google.com", Version: "wrong"}
				expected = iam.ErrFederationProviderChanged
			}
			calls := 0
			err := f.service.WithFederationSession(f.ctx, reference, roleARN, func(context.Context, iam.RoleSnapshot, identity.Repository) error { calls++; return nil })
			if !errors.Is(err, expected) || calls != 0 {
				t.Fatalf("stale/missing trust reached callback: %v calls=%d", err, calls)
			}
		})
	}
	for _, builtin := range []string{"accounts.google.com", "cognito-identity.amazonaws.com", "www.amazon.com", "graph.facebook.com"} {
		f := newFederationAuthorityFixture(t, nil)
		ref := iam.FederationProviderReference{ARN: builtin, ID: builtin, Version: "builtin-v1"}
		if err := f.service.WithFederationSession(f.ctx, ref, f.role.Arn, func(context.Context, iam.RoleSnapshot, identity.Repository) error { return nil }); err != nil {
			t.Fatalf("built-in %s rejected: %v", builtin, err)
		}
	}
}

func TestIAMFederationAuthorityUsesCurrentRoleAndFencesWriters(t *testing.T) {
	f := newFederationAuthorityFixture(t, nil)
	updated := f.role
	updated.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Deny","Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"` + f.provider.ARN + `"}}}`
	updated.TrustPrincipalIDs = map[string]string{}
	updated.MaxSessionDuration = 7200
	if err := f.repository.Update(f.ctx, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, updated) }); err != nil {
		t.Fatal(err)
	}
	if err := f.service.WithFederationSession(f.ctx, f.reference(), f.role.Arn, func(_ context.Context, current iam.RoleSnapshot, _ identity.Repository) error {
		if current.TrustPolicy != updated.AssumeRolePolicyDocument || current.MaxSessionDuration != 2*time.Hour {
			t.Fatal("stale role snapshot reached callback")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- f.service.WithFederationSession(f.ctx, f.reference(), f.role.Arn, func(ctx context.Context, role iam.RoleSnapshot, repository identity.Repository) error {
			close(entered)
			<-release
			return repository.Update(ctx, func(tx identity.Transaction) error { return tx.Put(federationAuthorityCredential(role)) })
		})
	}()
	<-entered
	blocked, cancel := context.WithTimeout(f.ctx, 50*time.Millisecond)
	defer cancel()
	err := f.repository.Update(blocked, func(tx iam.WriteTx) error { return tx.DeleteOIDCProvider(f.scope, f.provider.ARN) })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("provider changed during issuance transaction: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := f.repository.Update(f.ctx, func(tx iam.WriteTx) error { return tx.DeleteOIDCProvider(f.scope, f.provider.ARN) }); err != nil {
		t.Fatal(err)
	}
	if err := f.service.WithFederationSession(f.ctx, f.reference(), f.role.Arn, func(context.Context, iam.RoleSnapshot, identity.Repository) error { return nil }); !errors.Is(err, iam.ErrRecordNotFound) {
		t.Fatal("post-commit provider deletion not observed")
	}
}

func TestIAMFederationProviderVersions(t *testing.T) {
	p := iam.OIDCProviderRecord{ARN: "arn", ID: "id", URL: "issuer", ClientIDs: []string{"client"}, Thumbprints: []string{"thumbprint"}}
	base := iam.OIDCProviderVersion(p)
	if len(base) != 64 || base != iam.OIDCProviderVersion(p) {
		t.Fatal("unstable OIDC version")
	}
	p.Tags = []iam.Tag{{Key: "tag", Value: "value"}}
	p.CreatedAt = time.Now()
	if base != iam.OIDCProviderVersion(p) {
		t.Fatal("administrative changes invalidated OIDC auth configuration")
	}
	for _, mutate := range []func(*iam.OIDCProviderRecord){func(p *iam.OIDCProviderRecord) { p.ID += "new" }, func(p *iam.OIDCProviderRecord) { p.URL += "new" }, func(p *iam.OIDCProviderRecord) { p.ClientIDs = []string{"new"} }, func(p *iam.OIDCProviderRecord) { p.Thumbprints = []string{"new"} }} {
		copy := p
		mutate(&copy)
		if base == iam.OIDCProviderVersion(copy) {
			t.Fatal("OIDC trust change left version unchanged")
		}
	}
	saml := iam.SAMLProviderRecord{ARN: "saml-arn", UUID: "uuid", AssertionEncryptionMode: "Allowed", Issuers: []iam.SAMLIssuerRecord{{EntityID: "issuer", SigningCertificates: [][]byte{{1, 2, 3}}}}, PrivateKeys: []iam.SAMLPrivateKeyRecord{{ID: "key", CreatedAt: time.Unix(1, 0), PKCS8DER: []byte{4, 5, 6}}}}
	base = iam.SAMLProviderVersion(saml)
	copy := saml
	copy.MetadataDocument = "unrelated XML whitespace"
	copy.Tags = []iam.Tag{{Key: "tag", Value: "value"}}
	copy.CreatedAt = time.Now()
	copy.ValidUntil = time.Now().Add(time.Hour)
	if base != iam.SAMLProviderVersion(copy) {
		t.Fatal("non-auth metadata changed SAML version")
	}
	for _, mutate := range []func(*iam.SAMLProviderRecord){func(p *iam.SAMLProviderRecord) { p.UUID += "new" }, func(p *iam.SAMLProviderRecord) { p.AssertionEncryptionMode = "Required" }, func(p *iam.SAMLProviderRecord) {
		p.Issuers = []iam.SAMLIssuerRecord{{EntityID: "other", SigningCertificates: [][]byte{{1, 2, 3}}}}
	}, func(p *iam.SAMLProviderRecord) {
		p.Issuers = []iam.SAMLIssuerRecord{{EntityID: "issuer", SigningCertificates: [][]byte{{9, 2, 3}}}}
	}, func(p *iam.SAMLProviderRecord) {
		p.PrivateKeys = []iam.SAMLPrivateKeyRecord{{ID: "key", CreatedAt: time.Unix(1, 0), PKCS8DER: []byte{9, 5, 6}}}
	}, func(p *iam.SAMLProviderRecord) {
		p.PrivateKeys = []iam.SAMLPrivateKeyRecord{{ID: "key", CreatedAt: time.Unix(2, 0), PKCS8DER: []byte{4, 5, 6}}}
	}} {
		copy := saml
		mutate(&copy)
		if base == iam.SAMLProviderVersion(copy) {
			t.Fatal("SAML trust/key change left version unchanged")
		}
	}
}

// Multiple callers can independently use the authority; storage serializes
// publication while each callback receives a detached current role snapshot.
func TestIAMFederationAuthorityConcurrentCallers(t *testing.T) {
	f := newFederationAuthorityFixture(t, nil)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			results <- f.service.WithFederationSession(f.ctx, f.reference(), f.role.Arn, func(ctx context.Context, role iam.RoleSnapshot, _ identity.Repository) error {
				role.Tags["team"] = "private"
				_, err := f.service.RoleForAssumption(ctx, f.role.Arn)
				return err
			})
		})
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestIAMFederationAuthoritySAMLKeyVersionAndDetachment(t *testing.T) {
	f := newFederationAuthorityFixture(t, nil)
	provider := iam.SAMLProviderRecord{ARN: "arn:aws:iam::123456789012:saml-provider/provider", UUID: "SAMLoriginal", AssertionEncryptionMode: "Required", Issuers: []iam.SAMLIssuerRecord{{EntityID: "issuer", SigningCertificates: [][]byte{{1, 2, 3}}}}, PrivateKeys: []iam.SAMLPrivateKeyRecord{{ID: "key", CreatedAt: time.Unix(1, 0), PKCS8DER: []byte{4, 5, 6}}}}
	if err := f.repository.Update(f.ctx, func(tx iam.WriteTx) error { return tx.PutSAMLProvider(f.scope, provider) }); err != nil {
		t.Fatal(err)
	}
	reference := iam.FederationProviderReference{ARN: provider.ARN, ID: provider.UUID, Version: iam.SAMLProviderVersion(provider)}
	if err := f.service.WithFederationSession(f.ctx, reference, f.role.Arn, func(ctx context.Context, _ iam.RoleSnapshot, _ identity.Repository) error {
		first, err := f.service.SAMLProviderForFederation(ctx, provider.ARN)
		if err != nil {
			return err
		}
		first.PrivateKeys[0].PKCS8DER[0] = 99
		first.Issuers[0].SigningCertificates[0][0] = 99
		again, err := f.service.SAMLProviderForFederation(ctx, provider.ARN)
		if err != nil {
			return err
		}
		if iam.SAMLProviderVersion(again) != reference.Version {
			t.Fatal("borrowed private material was not detached")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	provider.PrivateKeys[0].PKCS8DER[0] = 7
	if err := f.repository.Update(f.ctx, func(tx iam.WriteTx) error { return tx.PutSAMLProvider(f.scope, provider) }); err != nil {
		t.Fatal(err)
	}
	called := false
	err := f.service.WithFederationSession(f.ctx, reference, f.role.Arn, func(context.Context, iam.RoleSnapshot, identity.Repository) error { called = true; return nil })
	if !errors.Is(err, iam.ErrFederationProviderChanged) || called {
		t.Fatal("SAML private key mutation failed to fence stale token verification", err)
	}
	reference.Version = iam.SAMLProviderVersion(provider)
	provider.UUID = "SAMLrecreated"
	if err := f.repository.Update(f.ctx, func(tx iam.WriteTx) error {
		if err := tx.DeleteSAMLProvider(f.scope, provider.ARN); err != nil {
			return err
		}
		return tx.PutSAMLProvider(f.scope, provider)
	}); err != nil {
		t.Fatal(err)
	}
	err = f.service.WithFederationSession(f.ctx, reference, f.role.Arn, func(context.Context, iam.RoleSnapshot, identity.Repository) error { called = true; return nil })
	if !errors.Is(err, iam.ErrFederationProviderChanged) || called {
		t.Fatal("same-ARN SAML recreation failed to fence stale verification", err)
	}
}
