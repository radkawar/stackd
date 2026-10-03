package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"stackd/internal/identity"
)

// The native authenticator accepts STS presigns for 15 minutes even though AWS CLI
// signs X-Amz-Expires=60. Ordinary service presigns must not inherit this policy.
func TestEKSTokenExpiryAndClusterBinding(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	creds := aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}
	request := httptest.NewRequest(http.MethodGet, "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Expires=60", nil)
	request.Header.Set("x-k8s-aws-id", "workloads")
	uri, headers, e := v4.NewSigner().PresignHTTP(t.Context(), creds, request, hashHex(nil), "sts", "us-east-1", now)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name    string
		age     time.Duration
		cluster string
		eks     bool
		code    string
	}{
		{"cached CLI token", 2 * time.Minute, "workloads", true, ""},
		{"ordinary presign still expires", 2 * time.Minute, "workloads", false, "RequestExpired"},
		{"cluster binding", time.Second, "another", true, "SignatureDoesNotMatch"},
		{"expired Kubernetes token", 15*time.Minute + time.Second, "workloads", true, "RequestExpired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := http.NewRequestWithContext(t.Context(), http.MethodGet, uri, nil)
			if e != nil {
				t.Fatal(e)
			}
			r.Header = headers.Clone()
			r.Header.Set("x-k8s-aws-id", tc.cluster)
			scope, e := parseCredential(r)
			if e != nil {
				t.Fatal(e)
			}
			rejected := verifySignaturePolicy(r, nil, scope, identity.Credential{SecretAccessKey: "test"}, now.Add(tc.age), false, tc.eks)
			if tc.code == "" {
				if rejected != nil {
					t.Fatal(rejected)
				}
			} else if rejected == nil || rejected.Code != tc.code {
				t.Fatalf("got %v, want %s", rejected, tc.code)
			}
		})
	}
}
