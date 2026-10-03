package sts_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd/clock"
	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/sts"
)

type clockSessionAuthority struct {
	store  *identity.Store
	before func() error
}

func (a clockSessionAuthority) WithSession(ctx context.Context, _ string, fn func(context.Context, sts.CredentialStore, time.Time) error) error {
	if a.before != nil {
		if err := a.before(); err != nil {
			return err
		}
	}
	return a.store.WithTransaction(ctx, func(ctx context.Context, store *identity.Store, instant time.Time) error {
		return fn(ctx, store, instant)
	})
}

type signedClockRoles struct{ role sts.RoleSnapshot }

func (r signedClockRoles) RoleForAssumption(context.Context, string) (sts.RoleSnapshot, error) {
	return r.role, nil
}
func (r signedClockRoles) ResolveManagedPolicyDocuments(context.Context, []string) ([]string, error) {
	return nil, nil
}

type signedClockPolicies struct{ document string }

func (p signedClockPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{Identity: []iampolicy.Policy{{Document: p.document}}}, nil
}

type signedClockAuthorizer struct {
	clock    *clock.Manual
	delegate authorization.Authorizer
	mu       sync.Mutex
	times    []time.Time
}

func (a *signedClockAuthorizer) Authorize(ctx context.Context, request authorization.Request) *awswire.Error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if request.EvaluationTime == nil {
		return &awswire.Error{Code: "AccessDenied", Message: "missing captured authorization instant", StatusCode: 403}
	}
	a.times = append(a.times, *request.EvaluationTime)
	if err := a.clock.Advance(time.Hour); err != nil {
		return &awswire.Error{Code: "InternalFailure", Message: err.Error(), StatusCode: 500}
	}
	return a.delegate.Authorize(ctx, request)
}

func TestSignedSTSClockCoherentPermissionChecks(t *testing.T) {
	for _, epoch := range []time.Time{time.Date(2035, 2, 3, 4, 5, 6, 0, time.UTC), {}} {
		for _, action := range []string{"AssumeRole", "GetFederationToken"} {
			t.Run(action+"/"+epoch.Format(time.RFC3339), func(t *testing.T) {
				source := clock.NewManual(epoch)
				repository := identity.NewMemoryRepository()
				store := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: repository, Clock: source})
				parent, err := store.CreateAccessKey(identity.Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/caller", ID: "AIDACLOCKCALLER", UserName: "caller"})
				if err != nil {
					t.Fatal(err)
				}
				condition := fmt.Sprintf(`{"DateLessThan":{"aws:CurrentTime":%q}}`, epoch.Add(time.Minute).Format(time.RFC3339))
				policies := signedClockPolicies{`{"Statement":{"Effect":"Allow","Action":"sts:*","Resource":"*","Condition":` + condition + `}}`}
				authorizer := &signedClockAuthorizer{clock: source, delegate: authorization.NewWithClock(policies, nil, source)}
				role := sts.RoleSnapshot{ARN: "arn:aws:iam::123456789012:role/target", ID: "AROATARGET", Name: "target", MaxSessionDuration: time.Hour, TrustPolicy: `{"Statement":{"Effect":"Allow","Principal":{"AWS":"` + parent.PrincipalARN + `"},"Action":["sts:AssumeRole","sts:TagSession","sts:SetSourceIdentity"],"Condition":` + condition + `}}`}
				service := sts.NewWithDependencies(sts.Dependencies{Credentials: store, Sessions: clockSessionAuthority{store: store}, Roles: signedClockRoles{role}, Authorizer: authorizer, Clock: source})
				client := clientFor(t, service, parent, "us-east-1")
				var credential *ststypes.Credentials
				wantChecks := 2
				if action == "AssumeRole" {
					wantChecks = 3
					out, err := client.AssumeRole(t.Context(), &sdksts.AssumeRoleInput{RoleArn: aws.String(role.ARN), RoleSessionName: aws.String("clock-session"), DurationSeconds: aws.Int32(900), SourceIdentity: aws.String("clock-source"), Tags: []ststypes.Tag{{Key: aws.String("team"), Value: aws.String("test")}}})
					if err != nil {
						t.Fatal(err)
					}
					credential = out.Credentials
				} else {
					out, err := client.GetFederationToken(t.Context(), &sdksts.GetFederationTokenInput{Name: aws.String("clock-session"), DurationSeconds: aws.Int32(900), Tags: []ststypes.Tag{{Key: aws.String("team"), Value: aws.String("test")}}})
					if err != nil {
						t.Fatal(err)
					}
					credential = out.Credentials
				}
				authorizer.mu.Lock()
				defer authorizer.mu.Unlock()
				if len(authorizer.times) != wantChecks {
					t.Fatal("dependent permission checks missing")
				}
				for _, at := range authorizer.times {
					if !at.Equal(epoch) {
						t.Fatal("checks evaluated different instants")
					}
				}
				if err := repository.View(t.Context(), func(reader identity.Reader) error {
					issued, err := reader.Get(aws.ToString(credential.AccessKeyId))
					if err != nil {
						return err
					}
					if !issued.Credential.CreateDate.Equal(epoch) || !issued.Credential.Expiration.Equal(epoch.Add(15*time.Minute)) {
						t.Error("credential issuance diverged from its authorization transaction instant")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestSignedSTSClockExpiredParentCannotMintSession(t *testing.T) {
	epoch := time.Date(2035, 2, 3, 4, 5, 6, 0, time.UTC)
	source := clock.NewManual(epoch)
	repository := identity.NewMemoryRepository()
	store := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: repository, Clock: source})
	parent, err := store.CreateAccessKey(identity.Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/caller", ID: "AIDACLOCKCALLER", UserName: "caller"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.IssueSession(t.Context(), parent, identity.SessionSpec{Duration: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	role := sts.RoleSnapshot{ARN: "arn:aws:iam::123456789012:role/target", ID: "AROATARGET", Name: "target", MaxSessionDuration: time.Hour, TrustPolicy: `{"Statement":{"Effect":"Allow","Principal":{"AWS":"` + parent.PrincipalARN + `"},"Action":"sts:AssumeRole"}}`}
	policies := signedClockPolicies{`{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`}
	authorizer := &signedClockAuthorizer{clock: source, delegate: authorization.NewWithClock(policies, nil, source)}
	service := sts.NewWithDependencies(sts.Dependencies{Credentials: store, Sessions: clockSessionAuthority{store: store, before: func() error { return source.Advance(time.Hour) }}, Roles: signedClockRoles{role}, Authorizer: authorizer, Clock: source})
	out, err := clientFor(t, service, session, "us-east-1").AssumeRole(t.Context(), &sdksts.AssumeRoleInput{RoleArn: aws.String(role.ARN), RoleSessionName: aws.String("expired-parent")})
	requireCode(t, err, "ExpiredToken")
	if out != nil && out.Credentials != nil {
		t.Fatal("expired parent returned credentials")
	}
	if err := repository.View(t.Context(), func(reader identity.Reader) error {
		records, err := reader.FindPrincipal(parent.AccountID, role.ID)
		if len(records) != 0 {
			t.Fatal("expired parent persisted a role session")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

type zeroClockMFA struct{}

func (zeroClockMFA) VerifyMFA(context.Context, string, string) (time.Time, error) {
	return time.Time{}, nil
}

func TestSignedSTSClockZeroMFAIsExplicit(t *testing.T) {
	source := clock.NewManual(time.Time{})
	store := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: identity.NewMemoryRepository(), Clock: source})
	parent, err := store.CreateAccessKey(identity.Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/caller", ID: "AIDACLOCKCALLER", UserName: "caller"})
	if err != nil {
		t.Fatal(err)
	}
	role := sts.RoleSnapshot{ARN: "arn:aws:iam::123456789012:role/target", ID: "AROATARGET", Name: "target", MaxSessionDuration: time.Hour, TrustPolicy: `{"Statement":{"Effect":"Allow","Principal":{"AWS":"` + parent.PrincipalARN + `"},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"},"NumericEquals":{"aws:MultiFactorAuthAge":"0"}}}}`}
	policies := signedClockPolicies{`{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`}
	service := sts.NewWithDependencies(sts.Dependencies{Credentials: store, Sessions: clockSessionAuthority{store: store}, Roles: signedClockRoles{role}, Authorizer: authorization.NewWithClock(policies, nil, source), MFA: zeroClockMFA{}, Clock: source})
	client := clientFor(t, service, parent, "us-east-1")
	for _, withMFA := range []bool{false, true} {
		input := &sdksts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)}
		if withMFA {
			input.SerialNumber, input.TokenCode = aws.String("arn:aws:iam::123456789012:mfa/caller"), aws.String("123456")
		}
		out, err := client.GetSessionToken(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		issued, err := store.Resolve(t.Context(), aws.ToString(out.Credentials.AccessKeyId))
		if err != nil || issued.MFAPresent != withMFA || !issued.MFAAuthenticatedAt.IsZero() {
			t.Fatal("zero MFA timestamp lost explicit authentication presence", err)
		}
	}
	input := &sdksts.AssumeRoleInput{RoleArn: aws.String(role.ARN), RoleSessionName: aws.String("clock-mfa"), DurationSeconds: aws.Int32(900)}
	_, err = client.AssumeRole(t.Context(), input)
	requireCode(t, err, "AccessDenied")
	input.SerialNumber, input.TokenCode = aws.String("arn:aws:iam::123456789012:mfa/caller"), aws.String("123456")
	if _, err := client.AssumeRole(t.Context(), input); err != nil {
		t.Fatal("verified MFA at zero epoch failed trust conditions", err)
	}
}
