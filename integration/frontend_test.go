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

func TestGeneratedFrontendRejectsInvalidShapeBeforeMutation(t *testing.T) {
	handler, err := stackd.New(stackd.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := iam.New(iam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	for _, name := range []string{strings.Repeat("x", 65), "invalid user"} {
		_, err := client.CreateUser(context.Background(), &iam.CreateUserInput{UserName: aws.String(name)})
		assertAPIError(t, err, "ValidationError")
	}
	users, err := client.ListUsers(context.Background(), &iam.ListUsersInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(users.Users) != 0 {
		t.Fatalf("invalid generated input reached state mutation: %#v", users.Users)
	}
}
