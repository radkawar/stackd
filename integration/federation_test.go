package stackd_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd"
)

func TestSAMLMetadataLargeEncodedQueryAndConfiguredBodyLimit(t *testing.T) {
	// '<' inside an XML comment is legal metadata and expands threefold on
	// the Query wire. This document is below IAM's 10 MB metadata constraint.
	document := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.test/idp"><!--` + strings.Repeat("<", 6<<20) + `--><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>`
	for _, tc := range []struct {
		name        string
		limit       int64
		wantSuccess bool
	}{
		{name: "default supports encoded metadata", wantSuccess: true},
		{name: "configured limit retained", limit: 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, err := stackd.New(stackd.Config{MaxBodyBytes: tc.limit})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = handler.Close() })
			server := httptest.NewServer(handler)
			t.Cleanup(server.Close)
			client := iam.New(iam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
			result, err := client.CreateSAMLProvider(context.Background(), &iam.CreateSAMLProviderInput{Name: aws.String("large-metadata"), SAMLMetadataDocument: aws.String(document)})
			if tc.wantSuccess {
				if err != nil {
					t.Fatal(err)
				}
				got, err := client.GetSAMLProvider(context.Background(), &iam.GetSAMLProviderInput{SAMLProviderArn: result.SAMLProviderArn})
				if err != nil {
					t.Fatal(err)
				}
				if aws.ToString(got.SAMLMetadataDocument) != document {
					t.Fatal("stored metadata changed")
				}
			} else if err == nil {
				t.Fatal("configured body limit was bypassed")
			}
		})
	}
}
