package gateway

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
)

type requestOriginFunc func(string) string

func (f requestOriginFunc) InvocationParent(accessKeyID string) string { return f(accessKeyID) }

type originProvider struct {
	calls    int
	metadata awsctx.Metadata
}

func (*originProvider) Operations() []string { return []string{"Known", "AssumeRoleWithSAML"} }
func (p *originProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.calls++
	p.metadata = awsctx.FromContext(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func TestRequestOriginRequiresAuthenticatedRuntimeCredential(t *testing.T) {
	const account = "123456789012"
	const parent = "committed-invocation"
	const taskParent = "committed-task"
	store := identity.NewStore(account)
	runtime, err := store.IssueServiceRoleSession(t.Context(), identity.RoleSessionSpec{
		Role:        identity.Principal{AccountID: account, ARN: "arn:aws:iam::123456789012:role/worker", ID: "AROAWORKER"},
		SessionName: "runtime", Duration: time.Hour, MaxSessionDuration: time.Hour,
		SourceIdentity: "job-source", Tags: map[string]string{"job": "trusted"},
		RequestParentEventID: taskParent,
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := store.Resolve(t.Context(), "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		credential    identity.Credential
		badSecret     bool
		badToken      bool
		unsigned      bool
		health        bool
		noInvocation  bool
		wantStatus    int
		wantCalls     int
		wantLookup    []string
		wantParent    string
		wantPrincipal string
	}{
		{name: "runtime", credential: runtime, wantStatus: 204, wantCalls: 1, wantLookup: []string{runtime.AccessKeyID}, wantParent: parent, wantPrincipal: "arn:aws:sts::123456789012:assumed-role/worker/runtime"},
		{name: "retained task", credential: runtime, noInvocation: true, wantStatus: 204, wantCalls: 1, wantLookup: []string{runtime.AccessKeyID}, wantParent: taskParent, wantPrincipal: "arn:aws:sts::123456789012:assumed-role/worker/runtime"},
		{name: "unrelated credential", credential: root, wantStatus: 204, wantCalls: 1, wantLookup: []string{root.AccessKeyID}, wantPrincipal: "arn:aws:iam::123456789012:root"},
		{name: "invalid signature", credential: runtime, badSecret: true, wantStatus: 403},
		{name: "invalid session token", credential: runtime, badToken: true, wantStatus: 403},
		{name: "unsigned federation", unsigned: true, wantStatus: 204, wantCalls: 1},
		{name: "unauthenticated health", health: true, wantStatus: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &originProvider{}
			registry := &Registry{}
			if err := registry.Register(Service{Name: "sts", SigningName: "sts", Protocol: Query, QueryVersion: "2011-06-15", Namespace: "urn:sts", Provider: provider}); err != nil {
				t.Fatal(err)
			}
			var lookups []string
			g, err := New(registry, Config{
				Credentials: store,
				Origin: requestOriginFunc(func(accessKeyID string) string {
					lookups = append(lookups, accessKeyID)
					if accessKeyID == runtime.AccessKeyID && !tc.noInvocation {
						return parent
					}
					return ""
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			body := "Action=Known&Version=2011-06-15"
			method, path := http.MethodPost, "http://localhost/"
			if tc.unsigned {
				body = "Action=AssumeRoleWithSAML&Version=2011-06-15"
			}
			if tc.health {
				method, path, body = http.MethodGet, "http://localhost/_stackd/health", ""
			}
			r := httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("X-Stackd-Parent-Event-Id", "forged-header")
			r.Header.Set("X-Amzn-Trace-Id", "Root=forged-trace")
			r.Header.Set("X-Amz-Access-Key-Id", runtime.AccessKeyID)
			r = r.WithContext(awsctx.WithMetadata(r.Context(), awsctx.Metadata{
				ParentEventID: "forged-context", AccessKeyID: runtime.AccessKeyID,
				AccountID: "999999999999", Region: "us-west-2", PrincipalARN: "arn:aws:iam::999999999999:root",
				PrincipalID: "forged-principal", SessionType: "forged-session", IssuerARN: "forged-issuer",
				SourceIdentity: "forged-source", SessionTags: map[string]string{"job": "forged"},
				CalledVia: []string{"lambda.amazonaws.com"}, InvokedBy: "lambda.amazonaws.com",
				ServicePrincipal: awsctx.ServicePrincipal{Name: "lambda.amazonaws.com"},
			}))
			if !tc.unsigned && !tc.health {
				credentials := aws.Credentials{AccessKeyID: tc.credential.AccessKeyID, SecretAccessKey: tc.credential.SecretAccessKey, SessionToken: tc.credential.SessionToken}
				if tc.badSecret {
					credentials.SecretAccessKey = "wrong"
				}
				if tc.badToken {
					credentials.SessionToken = "wrong"
				}
				if err := v4.NewSigner().SignHTTP(t.Context(), credentials, r, hashHex([]byte(body)), "sts", "eu-west-1", time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code != tc.wantStatus || provider.calls != tc.wantCalls || !slices.Equal(lookups, tc.wantLookup) {
				t.Fatalf("status=%d provider calls=%d origin lookups=%v body=%s", w.Code, provider.calls, lookups, w.Body.String())
			}
			if provider.calls == 0 {
				return
			}
			m := provider.metadata
			if m.ParentEventID != tc.wantParent || m.PrincipalARN != tc.wantPrincipal || m.AccessKeyID != tc.credential.AccessKeyID {
				t.Fatalf("provider received wrong origin or caller: %+v", m)
			}
			if m.InvokedBy != "" || m.ServicePrincipal.Name != "" || m.ServicePrincipal.SourceARN != "" || m.ServicePrincipal.Type != "" || len(m.ServicePrincipal.Aliases) != 0 || len(m.CalledVia) != 0 {
				t.Fatalf("origin supplied service authority: %+v", m)
			}
			if tc.unsigned {
				if m.AccountID != "" || m.PrincipalID != "" || m.SessionType != "" || m.IssuerARN != "" || m.SourceIdentity != "" || len(m.SessionTags) != 0 {
					t.Fatalf("unsigned caller inherited identity: %+v", m)
				}
				return
			}
			if m.AccountID != account || m.Region != "eu-west-1" || m.Partition != "aws" {
				t.Fatalf("origin changed authenticated scope: %+v", m)
			}
			if tc.credential.AccessKeyID == runtime.AccessKeyID {
				if m.PrincipalID != "AROAWORKER:runtime" || m.SessionType != string(identity.SessionTypeAssumeRole) || m.IssuerARN != "arn:aws:iam::123456789012:role/worker" || m.IssuerID != "AROAWORKER" || m.SourceIdentity != "job-source" || len(m.SessionTags) != 1 || m.SessionTags["job"] != "trusted" {
					t.Fatalf("origin changed runtime session authority: %+v", m)
				}
			} else if m.PrincipalID != account || m.SessionType != "" || m.IssuerARN != "" || m.IssuerID != "" || m.SourceIdentity != "" || len(m.SessionTags) != 0 {
				t.Fatalf("unrelated caller inherited runtime authority: %+v", m)
			}
		})
	}
}
