package authorization_test

import (
	"context"
	"fmt"
	"testing"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

func TestTransportConditions(t *testing.T) {
	for _, tc := range []struct {
		name, condition, ip, userAgent string
		known, secure, allowed         bool
	}{
		{name: "IPv4 permitted", condition: `"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}`, ip: "192.0.2.1", known: true, allowed: true},
		{name: "IPv4 outside range", condition: `"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}`, ip: "198.51.100.1", known: true},
		{name: "IPv6 permitted", condition: `"IpAddress":{"aws:SourceIp":"2001:db8::/32"}`, ip: "2001:db8::1", known: true, allowed: true},
		{name: "TLS permitted", condition: `"Bool":{"aws:SecureTransport":"true"}`, known: true, secure: true, allowed: true},
		{name: "plaintext rejected", condition: `"Bool":{"aws:SecureTransport":"true"}`, known: true},
		{name: "plaintext observed", condition: `"Bool":{"aws:SecureTransport":"false"}`, known: true, allowed: true},
		{name: "unknown is not plaintext", condition: `"Bool":{"aws:SecureTransport":"false"}`},
		{name: "unknown transport is absent", condition: `"Null":{"aws:SecureTransport":"true","aws:SourceIp":"true","aws:UserAgent":"true"}`, allowed: true},
		{name: "unobserved values ignored", condition: `"Null":{"aws:SecureTransport":"true","aws:SourceIp":"true","aws:UserAgent":"true"}`, ip: "192.0.2.1", secure: true, userAgent: "stackd/1", allowed: true},
		{name: "user agent matched", condition: `"StringLike":{"aws:UserAgent":"stackd/*"}`, known: true, userAgent: "stackd/1", allowed: true},
		{name: "empty user agent observed", condition: `"StringEquals":{"aws:UserAgent":""}`, known: true, allowed: true},
		{name: "peer without IP", condition: `"Null":{"aws:SourceIp":"true"}`, known: true, allowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := metadata(false)
			m.TransportKnown, m.SourceIP, m.SecureTransport, m.UserAgent = tc.known, tc.ip, tc.secure, tc.userAgent
			doc := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*","Condition":{%s}}}`, tc.condition)
			evaluator := authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: doc}}}}, nil)
			err := evaluator.Authorize(awsctx.WithMetadata(context.Background(), m), authorization.Request{Action: "iam:ListUsers", ResourceARN: "*"})
			if (err == nil) != tc.allowed {
				t.Fatalf("Authorize = %v; want allowed %t", err, tc.allowed)
			}
		})
	}
}

func TestTransportContextCannotBeFabricated(t *testing.T) {
	for _, known := range []bool{false, true} {
		for key, forged := range map[string]string{"AWS:SourceIp": "203.0.113.1", "aws:SecureTransport": "true", "aws:UserAgent": "forged"} {
			t.Run(fmt.Sprintf("%s/known=%t", key, known), func(t *testing.T) {
				m := metadata(false)
				m.TransportKnown, m.SourceIP, m.UserAgent = known, "192.0.2.1", "actual"
				evaluator := authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}}}}, nil)
				err := evaluator.Authorize(awsctx.WithMetadata(context.Background(), m), authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN, Context: map[string][]string{key: {forged}}})
				if err == nil {
					t.Fatal("service context fabricated transport information")
				}
			})
		}
	}
}
