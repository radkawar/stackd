package awsapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"

	iamapi "stackd/internal/awsapi/iam"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awswire"
)

func TestGeneratedQueryResponseCollectionsEscapingAndCredentials(t *testing.T) {
	stamp := time.Date(2026, 9, 11, 12, 0, 0, 123000000, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		action := r.Form.Get("Action")
		var body []byte
		var err error
		switch action {
		case "ListUsers":
			body, err = iamapi.EncodeResponse(action, &iamapi.ListUsersOutput{Users: iamapi.UserListType{{Arn: awsapiPtr(iamapi.ArnType("arn:aws:iam::123456789012:user/alice")), CreateDate: &stamp, Path: awsapiPtr(iamapi.PathType("/")), UserName: awsapiPtr(iamapi.UserNameType("alice")), UserId: awsapiPtr(iamapi.IdType("AIDAALICE"))}}, Marker: awsapiPtr(iamapi.ResponseMarkerType("a<&b")), IsTruncated: awsapiPtr(iamapi.BooleanType(true))})
		case "GetSessionToken":
			body, err = stsapi.EncodeResponse(action, &stsapi.GetSessionTokenOutput{Credentials: &stsapi.Credentials{AccessKeyId: awsapiPtr(stsapi.AccessKeyIdType("ASIATESTKEY1234567890")), SecretAccessKey: awsapiPtr(stsapi.AccessKeySecretType("secret<&value")), SessionToken: awsapiPtr(stsapi.TokenType("token<&value")), Expiration: &stamp}})
		}
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		awswire.WriteQueryBytes(w, r, "https://example.test/", action, body)
	}))
	defer server.Close()
	provider := credentials.NewStaticCredentialsProvider("test", "test", "")
	iamClient := sdkiam.New(sdkiam.Options{BaseEndpoint: aws.String(server.URL), Region: "us-east-1", Credentials: provider, RetryMaxAttempts: 1})
	users, err := iamClient.ListUsers(context.Background(), &sdkiam.ListUsersInput{})
	if err != nil || len(users.Users) != 1 || aws.ToString(users.Marker) != "a<&b" || !users.IsTruncated || !aws.ToTime(users.Users[0].CreateDate).Equal(stamp) {
		t.Fatalf("decoded generated Query users: %#v %v", users, err)
	}
	stsClient := sdksts.New(sdksts.Options{BaseEndpoint: aws.String(server.URL), Region: "us-east-1", Credentials: provider, RetryMaxAttempts: 1})
	session, err := stsClient.GetSessionToken(context.Background(), &sdksts.GetSessionTokenInput{})
	if err != nil || aws.ToString(session.Credentials.SessionToken) != "token<&value" || aws.ToString(session.Credentials.SecretAccessKey) != "secret<&value" || !aws.ToTime(session.Credentials.Expiration).Equal(stamp) {
		t.Fatalf("decoded generated Query credentials: %#v %v", session, err)
	}
	empty, err := iamapi.EncodeResponse("ListUsers", &iamapi.ListUsersOutput{Users: iamapi.UserListType{}})
	if err != nil || !strings.Contains(string(empty), "<Users></Users>") {
		t.Fatalf("required empty collection: %s %v", empty, err)
	}
	if _, err := iamapi.EncodeResponse("ListUsers", &stsapi.GetSessionTokenOutput{}); err == nil {
		t.Fatal("wrong service DTO serialized successfully")
	}
}

func awsapiPtr[T any](value T) *T { return &value }
