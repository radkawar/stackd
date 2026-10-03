package iam_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
	"stackd/internal/services/organizations"
)

func loginPartitionClient(t *testing.T, service *iam.Service, scope iam.Scope) *sdkiam.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: "us-east-1", PrincipalARN: "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":root", PrincipalID: scope.AccountID, RequestID: "partition-test"}
		service.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), m)))
	}))
	t.Cleanup(server.Close)
	return sdkiam.New(sdkiam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), Retryer: aws.NopRetryer{}})
}

func TestAccountAliasesPartitionUniquenessAndReplacement(t *testing.T) {
	ctx := context.Background()
	service := iam.New()
	first := clientFor(t, service, "123456789012", "us-east-1")
	second := clientFor(t, service, "999999999999", "us-west-2")
	china := loginPartitionClient(t, service, iam.Scope{Partition: "aws-cn", AccountID: "123456789012"})
	aliases, err := first.ListAccountAliases(ctx, &sdkiam.ListAccountAliasesInput{})
	if err != nil || len(aliases.AccountAliases) != 0 || aliases.IsTruncated {
		t.Fatalf("empty aliases: %+v %v", aliases, err)
	}
	for _, alias := range []string{"UPPER", "-starting", "ending-", "two--hyphens", "xy", "123456789012"} {
		_, err = first.CreateAccountAlias(ctx, &sdkiam.CreateAccountAliasInput{AccountAlias: aws.String(alias)})
		requireCode(t, err, "ValidationError")
	}
	_, err = first.CreateAccountAlias(ctx, &sdkiam.CreateAccountAliasInput{AccountAlias: aws.String("example-company")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = second.CreateAccountAlias(ctx, &sdkiam.CreateAccountAliasInput{AccountAlias: aws.String("example-company")})
	requireCode(t, err, "EntityAlreadyExists")
	_, err = china.CreateAccountAlias(ctx, &sdkiam.CreateAccountAliasInput{AccountAlias: aws.String("example-company")})
	if err != nil {
		t.Fatalf("partition alias namespaces overlap: %v", err)
	}
	_, err = first.CreateAccountAlias(ctx, &sdkiam.CreateAccountAliasInput{AccountAlias: aws.String("replacement")})
	if err != nil {
		t.Fatal(err)
	}
	aliases, err = first.ListAccountAliases(ctx, &sdkiam.ListAccountAliasesInput{MaxItems: aws.Int32(1)})
	if err != nil || len(aliases.AccountAliases) != 1 || aliases.AccountAliases[0] != "replacement" || aliases.IsTruncated || aliases.Marker != nil {
		t.Fatalf("one alias replacement: %+v %v", aliases, err)
	}
	if _, err := service.ResolveAccountAlias(ctx, "aws", "example-company"); !errors.Is(err, iam.ErrRecordNotFound) {
		t.Fatalf("old alias still resolves: %v", err)
	}
	if accountID, err := service.ResolveAccountAlias(ctx, "aws-cn", "example-company"); err != nil || accountID != "123456789012" {
		t.Fatalf("China alias affected by AWS replacement: %s %v", accountID, err)
	}
	_, err = second.DeleteAccountAlias(ctx, &sdkiam.DeleteAccountAliasInput{AccountAlias: aws.String("replacement")})
	requireCode(t, err, "NoSuchEntity")
	_, err = first.DeleteAccountAlias(ctx, &sdkiam.DeleteAccountAliasInput{AccountAlias: aws.String("replacement")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = first.DeleteAccountAlias(ctx, &sdkiam.DeleteAccountAliasInput{AccountAlias: aws.String("replacement")})
	requireCode(t, err, "NoSuchEntity")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, client := range []*sdkiam.Client{first, second} {
		wg.Go(func() {
			_, err := client.CreateAccountAlias(ctx, &sdkiam.CreateAccountAliasInput{AccountAlias: aws.String("contended")})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			requireCode(t, err, "EntityAlreadyExists")
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent alias claims yielded %d successes", successes)
	}
}

type testPasswordIdentity struct{ name, email string }

func (s testPasswordIdentity) AccountIdentity(context.Context, string, string) (organizations.AccountRecord, error) {
	return organizations.AccountRecord{Name: s.name, Email: s.email}, nil
}

func TestDefaultPasswordRejectsAccountIdentityAndCustomPolicyReplacesRule(t *testing.T) {
	ctx := context.Background()
	service := iam.New()
	service.SetAccountIdentitySource(testPasswordIdentity{name: loginPasswordA, email: "Admin12@example.com"})
	root := clientFor(t, service, "123456789012", "us-east-1")
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("default")})
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{loginPasswordA, "Admin12@example.com"} {
		_, err = root.CreateLoginProfile(ctx, &sdkiam.CreateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(password)})
		requireCode(t, err, "PasswordPolicyViolation")
	}
	_, err = root.UpdateAccountPasswordPolicy(ctx, &sdkiam.UpdateAccountPasswordPolicyInput{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.CreateLoginProfile(ctx, &sdkiam.CreateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(loginPasswordA)})
	if err != nil {
		t.Fatalf("custom policy did not replace AWS defaults: %v", err)
	}
}
