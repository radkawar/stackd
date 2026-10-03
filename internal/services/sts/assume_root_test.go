package sts_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/sts"
)

const auditTaskARN = "arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials"
const rootMemberAccount = "999999999999"
const rootMemberARN = "arn:aws:iam::999999999999:root"

type rootTaskPolicySource struct {
	documents map[string]string
	mu        sync.Mutex
	accounts  []string
}

func (*rootTaskPolicySource) RoleForAssumption(context.Context, string) (sts.RoleSnapshot, error) {
	return sts.RoleSnapshot{}, errors.New("role not found")
}
func (p *rootTaskPolicySource) ResolveManagedPolicyDocuments(ctx context.Context, arns []string) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.accounts = append(p.accounts, awsctx.FromContext(ctx).AccountID)
	var result []string
	for _, arn := range arns {
		doc, ok := p.documents[arn]
		if !ok {
			return nil, errors.New("task policy not found")
		}
		result = append(result, doc)
	}
	return result, nil
}

type rootMembership struct {
	mu      sync.Mutex
	enabled bool
	caller  string
	calls   int
	advance func()
}

func (s *rootMembership) CheckRootSession(ctx context.Context, target, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.advance != nil {
		s.advance()
	}
	if !s.enabled || target != rootMemberAccount || awsctx.FromContext(ctx).AccountID != s.caller {
		return &awswire.Error{Code: "AccessDenied", Message: "Root session target is not an active eligible member.", StatusCode: 403}
	}
	return nil
}

func capturedRootTaskDocuments(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/iam/root_access.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		CleanupVerified bool `json:"cleanup_verified"`
		Observations    []struct {
			Case  string `json:"case"`
			Input struct {
				PolicyARN string `json:"PolicyArn"`
			} `json:"input"`
			Output struct {
				Version struct {
					Document json.RawMessage `json:"Document"`
				} `json:"PolicyVersion"`
			} `json:"output"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil || !fixture.CleanupVerified {
		t.Fatal("invalid or unclean AWS fixture", err)
	}
	result := make(map[string]string)
	for _, row := range fixture.Observations {
		if strings.HasPrefix(row.Case, "public_policy_version_") {
			result[row.Input.PolicyARN] = string(row.Output.Version.Document)
		}
	}
	if len(result) != 5 {
		t.Fatal("fixture must contain all five current root-task policies")
	}
	return result
}

type rootSTSFixture struct {
	store      *identity.Store
	repository identity.Repository
	clock      *clock.Manual
	parent     identity.Credential
	membership *rootMembership
	policies   *rootTaskPolicySource
	service    *sts.Service
}

func newRootSTSFixture(t *testing.T) *rootSTSFixture {
	t.Helper()
	epoch := time.Date(2035, 2, 3, 4, 5, 6, 0, time.UTC)
	manual := clock.NewManual(epoch)
	repository := identity.NewMemoryRepository()
	store := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: repository, Clock: manual})
	parent, err := store.CreateAccessKey(identity.Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/observer", ID: "AIDAROOTOBSERVER", UserName: "observer"})
	if err != nil {
		t.Fatal(err)
	}
	membership := &rootMembership{enabled: true, caller: parent.AccountID}
	policies := &rootTaskPolicySource{documents: capturedRootTaskDocuments(t)}
	f := &rootSTSFixture{store: store, repository: repository, clock: manual, parent: parent, membership: membership, policies: policies}
	f.service = f.sessionService(clockSessionAuthority{store: store}, "")
	return f
}

func (f *rootSTSFixture) sessionService(authority sts.SessionAuthority, document string) *sts.Service {
	if document == "" {
		document = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRoot","Resource":"` + rootMemberARN + `","Condition":{"ArnLike":{"sts:TaskPolicyArn":"arn:aws:iam::aws:policy/root-task/*"}}}}`
	}
	return sts.NewWithDependencies(sts.Dependencies{Credentials: f.store, Sessions: authority, Roles: f.policies,
		RootSessions: f.membership, Authorizer: authorization.NewWithClock(signedClockPolicies{document}, nil, f.clock), Clock: f.clock})
}

func TestAssumeRootSDKScopePoliciesAndSourceIdentity(t *testing.T) {
	f := newRootSTSFixture(t)
	role, err := f.store.IssueRoleSession(t.Context(), f.parent, identity.RoleSessionSpec{Role: identity.Principal{AccountID: f.parent.AccountID, ARN: "arn:aws:iam::123456789012:role/operator", ID: "AROAOPERATOR"}, SessionName: "source", SourceIdentity: "original-person", Duration: time.Hour, MaxSessionDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, parent := range []identity.Credential{f.parent, role} {
		for arn, document := range f.policies.documents {
			t.Run(string(parent.SessionType)+"/"+arn, func(t *testing.T) {
				out, err := clientFor(t, f.service, parent, "us-east-1").AssumeRoot(t.Context(), &sdksts.AssumeRootInput{TargetPrincipal: aws.String(rootMemberAccount), TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String(arn)}})
				if err != nil {
					t.Fatal(err)
				}
				stored, err := f.store.Resolve(t.Context(), aws.ToString(out.Credentials.AccessKeyId))
				if err != nil {
					t.Fatal(err)
				}
				if stored.SessionType != identity.SessionTypeAssumeRoot || stored.PrincipalARN != rootMemberARN || stored.PrincipalID != rootMemberAccount || stored.AccountID != rootMemberAccount || !stored.HasSessionPolicy || len(stored.SessionPolicies) != 1 || stored.SessionPolicies[0] != document || len(stored.SessionPolicyARNs) != 1 || stored.SessionPolicyARNs[0] != arn {
					t.Fatal("issued token does not retain the exact target/task scope")
				}
				if stored.SourceIdentity != parent.SourceIdentity || aws.ToString(out.SourceIdentity) != parent.SourceIdentity || !out.Credentials.Expiration.Equal(f.clock.Now().Add(15*time.Minute)) {
					t.Fatal("source identity or default duration differs")
				}
				who, err := clientFor(t, f.service, stored, "eu-west-1").GetCallerIdentity(t.Context(), &sdksts.GetCallerIdentityInput{})
				if err != nil || aws.ToString(who.Arn) != rootMemberARN || aws.ToString(who.UserId) != rootMemberAccount {
					t.Fatal("root session identity differs", err)
				}
			})
		}
	}
	for _, account := range f.policies.accounts {
		if account != rootMemberAccount {
			t.Fatal("task policy resolved in the caller account instead of target account")
		}
	}
}

func TestAssumeRootSDKValidationAndEligibility(t *testing.T) {
	f := newRootSTSFixture(t)
	client := clientFor(t, f.service, f.parent, "us-east-1")
	for _, tc := range []struct {
		name, target, task, code string
		duration                 *int32
	}{
		{"bad target", "arn:aws:iam::999999999999:user/not-root", auditTaskARN, "ValidationError", nil},
		{"foreign partition", "arn:aws-cn:iam::999999999999:root", auditTaskARN, "ValidationError", nil},
		{"foreign task partition", rootMemberARN, "arn:aws-cn:iam::aws:policy/root-task/IAMAuditRootUserCredentials", "ValidationError", nil},
		{"ordinary managed policy", rootMemberARN, "arn:aws:iam::aws:policy/ReadOnlyAccess", "ValidationError", nil},
		{"missing task arn", rootMemberARN, "", "ValidationError", nil},
		{"negative duration", rootMemberARN, auditTaskARN, "ValidationError", aws.Int32(-1)},
		{"long duration", rootMemberARN, auditTaskARN, "ValidationError", aws.Int32(901)},
		{"other target", "888888888888", auditTaskARN, "AccessDenied", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := client.AssumeRoot(t.Context(), &sdksts.AssumeRootInput{TargetPrincipal: aws.String(tc.target), TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String(tc.task)}, DurationSeconds: tc.duration})
			requireCode(t, err, tc.code)
			if out != nil && out.Credentials != nil {
				t.Fatal("rejected request returned credentials")
			}
		})
	}
	f.membership.mu.Lock()
	f.membership.enabled = false
	f.membership.mu.Unlock()
	_, err := client.AssumeRoot(t.Context(), &sdksts.AssumeRootInput{TargetPrincipal: aws.String(rootMemberARN), TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String(auditTaskARN)}})
	requireCode(t, err, "AccessDenied")
	assertNoRootSessions(t, f)
}

func assertNoRootSessions(t *testing.T, f *rootSTSFixture) {
	t.Helper()
	if err := f.repository.View(t.Context(), func(reader identity.Reader) error {
		rows, err := reader.FindPrincipal(rootMemberAccount, rootMemberAccount)
		if len(rows) != 0 {
			t.Error("rejected request persisted root credentials")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

type globalRootTransport struct {
	base http.RoundTripper
	host string
}

func (t globalRootTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = t.host
	return t.base.RoundTrip(r)
}

func TestAssumeRootSDKGlobalEndpointAndUnsupportedCallers(t *testing.T) {
	f := newRootSTSFixture(t)
	input := &sdksts.AssumeRootInput{TargetPrincipal: aws.String(rootMemberARN), TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String(auditTaskARN)}}
	client := clientFor(t, f.service, f.parent, "us-east-1")
	for _, host := range []string{"sts.amazonaws.com", "sts.amazonaws.com:443", "STS.AMAZONAWS.COM.", "STS.AMAZONAWS.COM.:443"} {
		_, err := client.AssumeRoot(t.Context(), input, func(o *sdksts.Options) {
			o.HTTPClient = &http.Client{Transport: globalRootTransport{base: http.DefaultTransport, host: host}}
		})
		requireCode(t, err, "InvalidAction")
	}
	if _, err := client.GetCallerIdentity(t.Context(), &sdksts.GetCallerIdentityInput{}, func(o *sdksts.Options) {
		o.HTTPClient = &http.Client{Transport: globalRootTransport{base: http.DefaultTransport, host: "sts.amazonaws.com"}}
	}); err != nil {
		t.Fatal("global STS endpoint rejected an existing supported action", err)
	}
	root, err := f.store.Resolve(t.Context(), "test")
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.store.IssueSession(t.Context(), f.parent, identity.SessionSpec{Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, parent := range []identity.Credential{root, token} {
		_, err := clientFor(t, f.service, parent, "us-east-1").AssumeRoot(t.Context(), input)
		requireCode(t, err, "AccessDenied")
	}
	assertNoRootSessions(t, f)
}

func TestAssumeRootSDKTransactionTimeAndZeroDuration(t *testing.T) {
	for _, seconds := range []int32{0, 1, 900} {
		t.Run(fmt.Sprint(seconds), func(t *testing.T) {
			f := newRootSTSFixture(t)
			instant := f.clock.Now()
			f.membership.advance = func() {
				if err := f.clock.Advance(time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			out, err := clientFor(t, f.service, f.parent, "us-east-1").AssumeRoot(t.Context(), &sdksts.AssumeRootInput{TargetPrincipal: aws.String(rootMemberAccount), TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String(auditTaskARN)}, DurationSeconds: aws.Int32(seconds)})
			if err != nil {
				t.Fatal(err)
			}
			if !out.Credentials.Expiration.Equal(instant.Add(time.Duration(seconds) * time.Second)) {
				t.Fatal("root issuance did not retain the transaction's initial instant")
			}
			if _, err := f.store.Resolve(t.Context(), aws.ToString(out.Credentials.AccessKeyId)); !errors.Is(err, identity.ErrExpired) {
				t.Fatalf("root credential after advanced clock: %v", err)
			}
		})
	}
}

func TestAssumeRootSDKCurrentCallerAtAuthorityEntry(t *testing.T) {
	for _, change := range []string{"inactive", "deleted", "expired", "different identity"} {
		t.Run(change, func(t *testing.T) {
			f := newRootSTSFixture(t)
			parent := f.parent
			before := func() error { return nil }
			want := "InvalidClientTokenId"
			switch change {
			case "inactive":
				before = func() error {
					return f.store.UpdateAccessKey(parent.AccountID, parent.PrincipalID, parent.AccessKeyID, identity.Inactive)
				}
			case "deleted":
				before = func() error { return f.store.DeleteAccessKey(parent.AccountID, parent.PrincipalID, parent.AccessKeyID) }
			case "expired":
				var err error
				parent, err = f.store.IssueRoleSession(t.Context(), parent, identity.RoleSessionSpec{Role: identity.Principal{AccountID: parent.AccountID, ARN: "arn:aws:iam::123456789012:role/operator", ID: "AROAOPERATOR"}, SessionName: "expiring", Duration: time.Hour, MaxSessionDuration: time.Hour})
				if err != nil {
					t.Fatal(err)
				}
				before = func() error { return f.clock.Advance(time.Hour) }
				want = "ExpiredToken"
			case "different identity":
				parent.PrincipalID = "AIDAUNRELATED"
			}
			service := f.sessionService(clockSessionAuthority{store: f.store, before: before}, "")
			out, err := clientFor(t, service, parent, "us-east-1").AssumeRoot(t.Context(), &sdksts.AssumeRootInput{TargetPrincipal: aws.String(rootMemberARN), TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String(auditTaskARN)}})
			requireCode(t, err, want)
			if out != nil && out.Credentials != nil {
				t.Fatal("stale or unrelated caller returned root credentials")
			}
			if f.membership.calls != 0 {
				t.Fatal("invalid caller reached Organizations dependency")
			}
			assertNoRootSessions(t, f)
		})
	}
}

func TestAssumeRootSDKRenamedCallerPermissionContext(t *testing.T) {
	for _, expectedName := range []string{"renamed", "observer"} {
		t.Run(expectedName, func(t *testing.T) {
			f := newRootSTSFixture(t)
			before := func() error {
				return f.store.RenamePrincipal(identity.Principal{AccountID: f.parent.AccountID, ID: f.parent.PrincipalID, ARN: "arn:aws:iam::123456789012:user/new-path/renamed", UserName: "renamed"})
			}
			document := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRoot","Resource":"` + rootMemberARN + `","Condition":{"StringEquals":{"aws:username":"` + expectedName + `"}}}}`
			service := f.sessionService(clockSessionAuthority{store: f.store, before: before}, document)
			out, err := clientFor(t, service, f.parent, "us-east-1").AssumeRoot(t.Context(), &sdksts.AssumeRootInput{TargetPrincipal: aws.String(rootMemberAccount), TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String(auditTaskARN)}})
			if expectedName == "observer" {
				requireCode(t, err, "AccessDenied")
				assertNoRootSessions(t, f)
			} else if err != nil || out.Credentials == nil {
				t.Fatal("current renamed caller was not used for permission checks", err)
			}
		})
	}
}

type failingRootAuthority struct {
	store  *identity.Store
	cancel bool
	issued int
}

func (a *failingRootAuthority) WithSession(ctx context.Context, _ string, fn func(context.Context, sts.CredentialStore, time.Time) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	return a.store.WithTransaction(ctx, func(ctx context.Context, store *identity.Store, instant time.Time) error {
		if err := fn(ctx, store, instant); err != nil {
			return err
		}
		a.issued++
		if a.cancel {
			cancel()
			return nil
		}
		return errors.New("injected authority commit failure")
	})
}

func TestAssumeRootSDKAuthorityRollback(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprint(canceled), func(t *testing.T) {
			f := newRootSTSFixture(t)
			authority := &failingRootAuthority{store: f.store, cancel: canceled}
			service := f.sessionService(authority, "")
			out, err := clientFor(t, service, f.parent, "us-east-1").AssumeRoot(t.Context(), &sdksts.AssumeRootInput{TargetPrincipal: aws.String(rootMemberAccount), TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String(auditTaskARN)}})
			requireCode(t, err, "InternalFailure")
			if authority.issued != 1 {
				t.Fatal("rollback test did not reach successful credential issuance")
			}
			if out != nil && out.Credentials != nil {
				t.Fatal("uncommitted root credentials escaped in SDK output")
			}
			assertNoRootSessions(t, f)
		})
	}
}
