package s3

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

func anonymousPolicyBucket(statements string) BucketRecord {
	return BucketRecord{
		Key:    BucketKey{Partition: "aws", Name: "grant-bucket"},
		Policy: authorization.BoundPolicy{Document: `{"Version":"2012-10-17","Statement":` + statements + `}`},
	}
}

func TestBucketPolicyAnonymousGrant(t *testing.T) {
	const objectAllow = `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}`
	const prefixAllow = `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/public/*"}`
	tests := []struct {
		name, statements string
		want, wantError  bool
	}{
		{"object read", objectAllow, true, false},
		{"bucket list", `{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::grant-bucket"}`, true, false},
		{"object upload", `{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::grant-bucket/uploads/*"}`, true, false},
		{"version read", `{"Effect":"Allow","Principal":"*","Action":"s3:GetObjectVersion","Resource":"arn:aws:s3:::grant-bucket/history"}`, true, false},
		{"AWS wildcard array", `{"Effect":"Allow","Principal":{"AWS":["111111111111","*"]},"Action":"S3:getobject","Resource":"arn:aws:s3:::grant-bucket/public/*"}`, true, false},
		{"fixed account", `{"Effect":"Allow","Principal":{"AWS":"111111111111"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}`, false, false},
		{"fixed service", `{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}`, false, false},
		{"API outside proved unsigned domain", `{"Effect":"Allow","Principal":"*","Action":"s3:GetBucketPolicy","Resource":"arn:aws:s3:::grant-bucket"}`, false, false},
		{"action complement", `{"Effect":"Allow","Principal":"*","NotAction":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}`, true, false},
		{"action complement excludes S3", `{"Effect":"Allow","Principal":"*","NotAction":"s3:*","Resource":"arn:aws:s3:::grant-bucket/*"}`, false, false},
		{"resource complement", `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","NotResource":"arn:aws:s3:::grant-bucket/private/*"}`, true, false},
		{"unrelated bucket", `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::another-bucket/*"}`, false, false},
		{"unrelated action", `{"Effect":"Allow","Principal":"*","Action":"iam:GetUser","Resource":"arn:aws:s3:::grant-bucket/*"}`, false, false},
		{"wrong resource type", `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket"}`, false, false},
		{"empty object key", `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/"}`, false, false},
		{"unsupported principal", `{"Effect":"Allow","Principal":{"CanonicalUser":"65a011a29cdf8ec533ec3d1ccaae921c"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}`, false, false},
		{"invalid action selector", `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","NotAction":"s3:PutObject","Resource":"arn:aws:s3:::grant-bucket/*"}`, false, true},
		{"unknown condition operator", `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*","Condition":{"Unknown":{"aws:SourceIp":"192.0.2.1"}}}`, false, false},
		{"conditional allow unproved", `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*","Condition":{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}}`, false, false},
		{"variable allow unproved", `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/${aws:username}/*"}`, false, false},
		{"same permission denied", `[` + objectAllow + `,{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}]`, false, false},
		{"partial prefix denial", `[` + objectAllow + `,{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/private/*"}]`, true, false},
		{"deny different action", `[` + objectAllow + `,{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::grant-bucket/*"}]`, true, false},
		{"deny different resource", `[` + prefixAllow + `,{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/private/*"}]`, true, false},
		{"deny union coverage", `[` + objectAllow + `,{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/public/*"},{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","NotResource":"arn:aws:s3:::grant-bucket/public/*"}]`, false, false},
		{"deny NotAction excludes grant", `[` + objectAllow + `,{"Effect":"Deny","Principal":"*","NotAction":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}]`, true, false},
		{"deny NotAction includes grant", `[` + objectAllow + `,{"Effect":"Deny","Principal":"*","NotAction":"s3:PutObject","Resource":"arn:aws:s3:::grant-bucket/*"}]`, false, false},
		{"fixed principal denial does not select anonymous", `[` + objectAllow + `,{"Effect":"Deny","Principal":{"AWS":"111111111111"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}]`, true, false},
		{"NotPrincipal fixed identity denies anonymous", `[` + objectAllow + `,{"Effect":"Deny","NotPrincipal":{"AWS":"111111111111"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}]`, false, false},
		{"NotPrincipal universal excludes anonymous", `[` + objectAllow + `,{"Effect":"Deny","NotPrincipal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}]`, true, false},
		{"conditional denial cannot be ignored", `[` + objectAllow + `,{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*","Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}]`, false, false},
		{"conditional denial disjoint from grant", `[` + prefixAllow + `,{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/private/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]`, true, false},
		{"variable denial cannot be ignored", `[` + objectAllow + `,{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/${aws:username}/*"}]`, false, false},
		{"unsupported denial cannot be ignored", `[` + objectAllow + `,{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*","Condition":{"Unknown":{"aws:SourceIp":"192.0.2.1"}}}]`, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BucketPolicyAnonymousGrant(t.Context(), anonymousPolicyBucket(tt.statements))
			if got != tt.want || (err != nil) != tt.wantError {
				t.Fatalf("grant=%v err=%v; want grant=%v error=%v", got, err, tt.want, tt.wantError)
			}
		})
	}
}

func TestBucketPolicyAnonymousGrantKeepsActionResourcePairs(t *testing.T) {
	const grants = `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/a"},{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::grant-bucket/b"}`
	for _, tt := range []struct {
		name, readKey, writeKey string
		want                    bool
	}{
		{"covered pairs", "a", "b", false},
		{"crossed denies", "b", "a", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			denies := fmt.Sprintf(`,{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/%s"},{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::grant-bucket/%s"}`, tt.readKey, tt.writeKey)
			got, err := BucketPolicyAnonymousGrant(t.Context(), anonymousPolicyBucket("["+grants+denies+"]"))
			if err != nil || got != tt.want {
				t.Fatalf("grant=%v err=%v; want %v", got, err, tt.want)
			}
		})
	}
}

func TestBucketPolicyAnonymousGrantValidKeyLanguage(t *testing.T) {
	for _, tt := range []struct {
		name, key string
		want      bool
	}{
		{"ASCII boundary", strings.Repeat("a", 1024), true},
		{"ASCII over limit", strings.Repeat("a", 1025), false},
		{"UTF-8 boundary", strings.Repeat("é", 512), true},
		{"UTF-8 over limit", strings.Repeat("é", 512) + "a", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			statement := fmt.Sprintf(`{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":%q}`, "arn:aws:s3:::grant-bucket/"+tt.key)
			got, err := BucketPolicyAnonymousGrant(t.Context(), anonymousPolicyBucket(statement))
			if err != nil || got != tt.want {
				t.Fatalf("grant=%v err=%v; want %v", got, err, tt.want)
			}
		})
	}
	tooLong := "arn:aws:s3:::grant-bucket/" + strings.Repeat("a", 1025)
	statements := fmt.Sprintf(`[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"},{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/a"},{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","NotResource":["arn:aws:s3:::grant-bucket/a",%q]}]`, tooLong)
	if got, err := BucketPolicyAnonymousGrant(t.Context(), anonymousPolicyBucket(statements)); err != nil || got {
		t.Fatalf("deny union left only an invalid key: grant=%v err=%v", got, err)
	}
}

func TestBucketPolicyAnonymousGrantRequestIndependent(t *testing.T) {
	const allow = `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}`
	const deny = `{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*","Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}`
	contexts := []context.Context{
		t.Context(),
		awsctx.WithMetadata(t.Context(), awsctx.Metadata{AccountID: "111111111111", SourceIP: "192.0.2.4", TransportKnown: true, SecureTransport: true}),
		awsctx.WithMetadata(t.Context(), awsctx.Metadata{AccountID: "anonymous", SourceIP: "198.51.100.4", TransportKnown: true}),
	}
	for _, tt := range []struct {
		statements string
		want       bool
	}{{allow, true}, {"[" + allow + "," + deny + "]", false}} {
		bucket := anonymousPolicyBucket(tt.statements)
		masks := PublicAccessBlock{BlockPublicACLs: true, IgnorePublicACLs: true, BlockPublicPolicy: true, RestrictPublicBuckets: true}
		bucket.PublicAccess = &masks
		before := bucket.Policy.Document
		for _, ctx := range contexts {
			if got, err := BucketPolicyAnonymousGrant(ctx, bucket); err != nil || got != tt.want {
				t.Fatalf("request-independent proof: grant=%v err=%v; want %v", got, err, tt.want)
			}
		}
		if bucket.Policy.Document != before || !bucket.PublicAccess.BlockPublicPolicy || !bucket.PublicAccess.RestrictPublicBuckets {
			t.Fatal("proof changed admitted bucket state")
		}
	}
}

func TestBucketPolicyAnonymousGrantMissingMalformedAndCanceled(t *testing.T) {
	bucket := BucketRecord{Key: BucketKey{Partition: "aws", Name: "grant-bucket"}}
	if got, err := BucketPolicyAnonymousGrant(t.Context(), bucket); err != nil || got {
		t.Fatalf("absent policy: grant=%v err=%v", got, err)
	}
	for _, document := range []string{"{", `{}`, `{"Statement":[]}`, `{"Statement":{"Effect":"Allow","Principal":"*","Principal":{"AWS":"111111111111"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}}`} {
		bucket.Policy.Document = document
		if got, err := BucketPolicyAnonymousGrant(t.Context(), bucket); err == nil || got {
			t.Fatalf("malformed policy %s: grant=%v err=%v", document, got, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := BucketPolicyAnonymousGrant(ctx, bucket); got || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled proof: grant=%v err=%v", got, err)
	}
}
