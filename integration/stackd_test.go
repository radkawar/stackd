package stackd_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	organizationtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd"
)

func TestSDKServiceRoutingAndInstanceIsolation(t *testing.T) {
	ctx := context.Background()
	newInstance := func() *httptest.Server {
		handler, err := stackd.New(stackd.Config{})
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(handler)
		t.Cleanup(func() {
			if err := handler.Close(); err != nil {
				t.Error(err)
			}
			server.Close()
		})
		return server
	}
	server := newInstance()
	iamClient := func(server *httptest.Server, key, region string) *iam.Client {
		return iam.New(iam.Options{Region: region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	}
	client := iamClient(server, "test", "us-east-1")
	user, err := client.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("alice"), Path: aws.String("/engineering/")})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(user.User.Arn) != "arn:aws:iam::000000000000:user/engineering/alice" {
		t.Fatalf("unexpected user: %#v", user.User)
	}
	_, err = iamClient(server, "test", "eu-west-2").GetUser(ctx, &iam.GetUserInput{UserName: aws.String("alice")})
	if err != nil {
		t.Fatalf("global IAM state not shared across regions: %v", err)
	}
	for _, isolated := range []*iam.Client{iamClient(server, "123456789012", "us-east-1"), iamClient(newInstance(), "test", "us-east-1")} {
		_, err := isolated.GetUser(ctx, &iam.GetUserInput{UserName: aws.String("alice")})
		var missing *iamtypes.NoSuchEntityException
		if !errors.As(err, &missing) {
			t.Fatalf("state leaked or error malformed: %v", err)
		}
	}
	orgClient := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	org, err := orgClient.CreateOrganization(ctx, &organizations.CreateOrganizationInput{FeatureSet: organizationtypes.OrganizationFeatureSetAll})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(org.Organization.MasterAccountId) != "000000000000" {
		t.Fatalf("unexpected organization: %#v", org.Organization)
	}
	roots, err := orgClient.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(roots.Roots) != 1 {
		t.Fatalf("roots: %#v", roots.Roots)
	}
	_, err = orgClient.CreateOrganizationalUnit(ctx, &organizations.CreateOrganizationalUnitInput{ParentId: roots.Roots[0].Id, Name: aws.String("engineering")})
	if err != nil {
		t.Fatal(err)
	}
}
