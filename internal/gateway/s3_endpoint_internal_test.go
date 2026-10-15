package gateway

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"stackd/internal/awsctx"
)

func TestS3CustomAccessPointRequestPath(t *testing.T) {
	for _, test := range []struct {
		name, host, region, bucket string
	}{
		{"ipv4", "reports-123456789012.127.0.0.1:4566", "us-west-2", "arn:aws:s3:us-west-2:123456789012:accesspoint/reports"},
		{"private-endpoint", "reports-123456789012.192.0.2.9:4566", "us-east-1", "arn:aws:s3:us-east-1:123456789012:accesspoint/reports"},
		{"partition", "reports-123456789012.127.0.0.1:4566", "us-gov-west-1", "arn:aws-us-gov:s3:us-gov-west-1:123456789012:accesspoint/reports"},
		{"missing-region", "reports-123456789012.127.0.0.1:4566", "", ""},
		{"invalid-account", "reports-12345678901.127.0.0.1:4566", "us-east-1", ""},
		{"unknown-region", "reports-123456789012.127.0.0.1:4566", "unknown-region", ""},
		{"ordinary-localhost-bucket", "reports-123456789012.localhost:4566", "us-west-2", "reports-123456789012"},
		{"ordinary-native-bucket", "reports-123456789012.s3.us-west-2.amazonaws.com", "us-west-2", "reports-123456789012"},
		{"custom-dns-not-inferred", "reports-123456789012.example.test:4566", "us-west-2", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "http://"+test.host+"/nested/a%20b%252Fc", nil)
			request = request.WithContext(awsctx.WithMetadata(request.Context(), awsctx.Metadata{Region: test.region, AccountID: "999999999999"}))
			originalHost, originalPath := request.Host, request.URL.EscapedPath()
			want := originalPath
			if test.bucket != "" {
				want = "/" + url.PathEscape(test.bucket) + want
			}
			if got := S3RequestPath(request); got != want {
				t.Fatalf("route = %q; want %q", got, want)
			}
			if request.Host != originalHost || request.URL.EscapedPath() != originalPath {
				t.Fatal("routing changed the signed host or escaped object path")
			}
		})
	}
}
