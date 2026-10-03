package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"stackd/internal/identity"
)

func TestSignatureAgainstSDKSigner(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, path string
		presign    bool
		age        time.Duration
		wantCode   string
	}{
		{name: "headers", path: "/"},
		{name: "encoded query", path: "/?a=a%20b&a=a%2Bb&z=%26"},
		{name: "query key prefixes", path: "/?select&select-type=2"},
		{name: "escaped path", path: "/hello%20world/path"},
		{name: "presigned", path: "/?X-Amz-Expires=60", presign: true},
		{name: "expired headers", path: "/", age: 16 * time.Minute, wantCode: "RequestExpired"},
		{name: "expired presign", path: "/?X-Amz-Expires=60", presign: true, age: 61 * time.Second, wantCode: "RequestExpired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := "Action=GetCallerIdentity&Version=2011-06-15"
			r := httptest.NewRequest(http.MethodPost, "http://localhost:4566"+test.path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			signer := v4.NewSigner()
			creds := aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}
			if test.presign {
				uri, headers, err := signer.PresignHTTP(context.Background(), creds, r, hashHex([]byte(body)), "sts", "us-east-1", now)
				if err != nil {
					t.Fatal(err)
				}
				r = httptest.NewRequest(http.MethodPost, uri, strings.NewReader(body))
				r.Header = headers
			} else if err := signer.SignHTTP(context.Background(), creds, r, hashHex([]byte(body)), "sts", "us-east-1", now); err != nil {
				t.Fatal(err)
			}
			scope, err := parseCredential(r)
			if err != nil {
				t.Fatal(err)
			}
			apiErr := verifySignature(r, scope, identity.Credential{SecretAccessKey: "test"}, now.Add(test.age), false)
			if test.wantCode == "" && apiErr != nil {
				t.Fatal(apiErr)
			}
			if test.wantCode != "" && (apiErr == nil || apiErr.Code != test.wantCode) {
				t.Fatalf("got %v; want %s", apiErr, test.wantCode)
			}
		})
	}
}

func TestUnsignedPayloadSignature(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	r := httptest.NewRequest(http.MethodPut, "http://localhost:4566/snapshots/snap-0123456789abcdef0/blocks/0", strings.NewReader("snapshot block"))
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	r.Header.Set("X-Amz-Checksum", "signed checksum")
	if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, r, "UNSIGNED-PAYLOAD", "ebs", "us-east-1", now); err != nil {
		t.Fatal(err)
	}
	scope, err := parseCredential(r)
	if err != nil {
		t.Fatal(err)
	}
	credential := identity.Credential{SecretAccessKey: "test"}
	if rejected := verifySignature(r, scope, credential, now, true); rejected != nil {
		t.Fatalf("modeled unsigned payload rejected: %v", rejected)
	}
	if rejected := verifySignature(r, scope, credential, now, false); rejected == nil || rejected.Code != "SignatureDoesNotMatch" {
		t.Fatalf("unmodeled unsigned payload accepted: %v", rejected)
	}
	r.Header.Set("X-Amz-Checksum", "tampered checksum")
	if rejected := verifySignature(r, scope, credential, now, true); rejected == nil || rejected.Code != "SignatureDoesNotMatch" {
		t.Fatalf("tampered signed checksum accepted: %v", rejected)
	}
}
