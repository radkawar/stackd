package s3

import (
	"fmt"
	"testing"

	"stackd/internal/awsctx"
)

func TestAnonymousPolicyPrincipalConditions(t *testing.T) {
	statement := func(effect, condition string) string {
		return fmt.Sprintf(`{"Effect":%q,"Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*","Condition":%s}`, effect, condition)
	}
	const allow = `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/*"}`
	for _, tt := range []struct {
		name, statements string
		want             bool
	}{
		{"anonymous account allow", statement("Allow", `{"StringEquals":{"aws:PrincipalAccount":"anonymous"}}`), true},
		{"writer account excluded", statement("Allow", `{"StringEquals":{"aws:PrincipalAccount":"123456789012"}}`), false},
		{"anonymous account deny", "[" + allow + "," + statement("Deny", `{"StringEquals":{"aws:PrincipalAccount":"anonymous"}}`) + "]", false},
		{"signed account deny irrelevant", "[" + allow + "," + statement("Deny", `{"StringNotEquals":{"aws:PrincipalAccount":"anonymous"}}`) + "]", true},
		{"account always present", statement("Allow", `{"Null":{"aws:PrincipalAccount":"true"}}`), false},
		{"service flag absent", statement("Allow", `{"Null":{"aws:PrincipalIsAWSService":"true"}}`), true},
		{"service flag not false", statement("Allow", `{"Bool":{"aws:PrincipalIsAWSService":"false"}}`), false},
		{"missing flag plain deny irrelevant", "[" + allow + "," + statement("Deny", `{"Bool":{"aws:PrincipalIsAWSService":"false"}}`) + "]", true},
		{"missing flag ifexists deny applies", "[" + allow + "," + statement("Deny", `{"BoolIfExists":{"aws:PrincipalIsAWSService":"false"}}`) + "]", false},
		{"account and HTTPS", statement("Allow", `{"StringEquals":{"AWS:PrincipalAccount":"anonymous"},"Bool":{"aws:SecureTransport":"true"}}`), true},
		{"unknown context stays conservative", statement("Allow", `{"StringEquals":{"aws:PrincipalAccount":"anonymous","aws:Referer":"public"}}`), false},
		{"unknown deny stays conservative", "[" + allow + "," + statement("Deny", `{"StringEquals":{"aws:PrincipalAccount":"123456789012","aws:Referer":"public"}}`) + "]", false},
		{"variable comparison still unsupported", statement("Allow", `{"StringEquals":{"aws:PrincipalAccount":"${aws:PrincipalAccount}"}}`), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, secure := range []bool{false, true} {
				ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{AccountID: "123456789012", TransportKnown: true, SecureTransport: secure})
				got, err := BucketPolicyAnonymousGrant(ctx, anonymousPolicyBucket(tt.statements))
				if err != nil || got != tt.want {
					t.Fatalf("writer TLS=%v grant=%v err=%v; want %v", secure, got, err, tt.want)
				}
			}
		})
	}
}
