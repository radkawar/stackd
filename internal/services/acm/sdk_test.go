package acm_test

import (
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
	"io"
	"net/http"
	"net/http/httptest"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/acm"
	"stackd/internal/awswire"
	"strings"
	"testing"
)

// IAM/SigV4 verification is exercised by integration; this HTTP boundary verifies
// that actual SDK clients decode the service's modeled rejection contracts.
func TestSDKDecodesUnsupportedValidationAndPendingMaterialErrors(t *testing.T) {
	s, _, _, _ := newService()
	ctx := owner("111111111111", "us-east-1")
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "CertificateManager.")
		body, e := io.ReadAll(r.Body)
		if e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		request, e := api.DecodeRequest(operation, awsapi.Request{JSON: body})
		if e != nil {
			awswire.JSONError(w, r, s.RequestError(operation, e))
			return
		}
		s.ServeHTTP(w, r.WithContext(awsapi.WithDecodedRequest(ctx, request)))
	}))
	defer endpoint.Close()
	client := sdk.New(sdk.Options{Region: "us-east-1", BaseEndpoint: aws.String(endpoint.URL), Credentials: credentials.NewStaticCredentialsProvider("sdk-test", "sdk-secret", "")})
	_, e := client.RequestCertificate(t.Context(), &sdk.RequestCertificateInput{DomainName: aws.String("unsupported.example.test"), ValidationMethod: types.ValidationMethodEmail})
	var unsupported *types.InvalidParameterException
	if !errors.As(e, &unsupported) {
		t.Fatalf("email validation modeled error: %T %v", e, e)
	}
	requested, e := client.RequestCertificate(t.Context(), &sdk.RequestCertificateInput{DomainName: aws.String("pending.example.test"), ValidationMethod: types.ValidationMethodDns})
	if e != nil {
		t.Fatal(e)
	}
	_, e = client.GetCertificate(t.Context(), &sdk.GetCertificateInput{CertificateArn: requested.CertificateArn})
	var pending *types.RequestInProgressException
	if !errors.As(e, &pending) {
		t.Fatalf("pending get modeled error: %T %v", e, e)
	}
	_, e = client.RenewCertificate(t.Context(), &sdk.RenewCertificateInput{CertificateArn: requested.CertificateArn})
	if !errors.As(e, &pending) {
		t.Fatalf("pending renew modeled error: %T %v", e, e)
	}
	_, e = client.DeleteCertificate(t.Context(), &sdk.DeleteCertificateInput{CertificateArn: requested.CertificateArn})
	if e != nil {
		t.Fatal(e)
	}
	_, e = client.DescribeCertificate(t.Context(), &sdk.DescribeCertificateInput{CertificateArn: requested.CertificateArn})
	var missing *types.ResourceNotFoundException
	if !errors.As(e, &missing) {
		t.Fatalf("deleted describe modeled error: %T %v", e, e)
	}
}
