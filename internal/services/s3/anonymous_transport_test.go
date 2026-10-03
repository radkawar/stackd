package s3

import (
	"fmt"
	"testing"

	"stackd/internal/awsctx"
)

func TestAnonymousPolicyTransportConditions(t *testing.T) {
	statement := func(effect, key, condition string) string {
		return fmt.Sprintf(`{"Effect":%q,"Principal":"*","Action":"s3:GetObject","Resource":%q,"Condition":%s}`, effect, "arn:aws:s3:::grant-bucket/"+key, condition)
	}
	http := `{"Bool":{"aws:SecureTransport":"false"}}`
	https := `{"Bool":{"aws:SecureTransport":"true"}}`
	allowHTTP := statement("Allow", "proof", http)
	allowHTTPS := statement("Allow", "proof", https)
	denyHTTP := statement("Deny", "proof", http)
	denyHTTPS := statement("Deny", "proof", https)
	unconditional := `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::grant-bucket/proof"}`
	for _, tt := range []struct {
		name, statements string
		want             bool
	}{
		{"HTTP permission", allowHTTP, true},
		{"HTTPS permission", allowHTTPS, true},
		{"same HTTP branch denied", "[" + allowHTTP + "," + denyHTTP + "]", false},
		{"same HTTPS branch denied", "[" + allowHTTPS + "," + denyHTTPS + "]", false},
		{"HTTP denial leaves HTTPS permission", "[" + allowHTTPS + "," + denyHTTP + "]", true},
		{"HTTPS denial leaves HTTP permission", "[" + allowHTTP + "," + denyHTTPS + "]", true},
		{"union covers both transports", "[" + unconditional + "," + denyHTTP + "," + denyHTTPS + "]", false},
		{"denied grants cannot mix transports", "[" + allowHTTP + "," + denyHTTP + "," + allowHTTPS + "," + denyHTTPS + "]", false},
		{"different resource deny", "[" + allowHTTPS + "," + statement("Deny", "other", https) + "]", true},
		{"inconsistent conjunction", statement("Allow", "proof", `{"Bool":{"aws:SecureTransport":"true"},"StringEquals":{"aws:SecureTransport":"false"}}`), false},
		{"case insensitive context key", statement("Allow", "proof", `{"Bool":{"AWS:SECURETRANSPORT":"true"}}`), true},
		{"transport is present", statement("Allow", "proof", `{"Null":{"aws:SecureTransport":"true"}}`), false},
		{"other condition not proven", statement("Allow", "proof", `{"Bool":{"aws:SecureTransport":"false"},"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}`), false},
		{"variable condition not proven", statement("Allow", "proof", `{"StringEquals":{"aws:SecureTransport":"${aws:username}"}}`), false},
		{"variable deny conservatively covers both", "[" + unconditional + "," + statement("Deny", "proof", `{"StringEquals":{"aws:SecureTransport":"\u0024{aws:username}"}}`) + "]", false},
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
