package stackd_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

func TestIAMDefaultPasswordPolicyUsesRegisteredAccountIdentity(t *testing.T) {
	ctx := context.Background()
	c := newCloudClients(t)
	org := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	if _, err := org.CreateOrganization(ctx, &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll}); err != nil {
		t.Fatal(err)
	}
	const accountName = "RegisteredAccount!92"
	const accountEmail = "account-123@example.test"
	account, err := org.CreateAccount(ctx, &organizations.CreateAccountInput{AccountName: aws.String(accountName), Email: aws.String(accountEmail)})
	if err != nil {
		t.Fatal(err)
	}
	account.CreateAccountStatus = waitAccountCreation(t, org, account.CreateAccountStatus, nil)
	root := c.iam(aws.ToString(account.CreateAccountStatus.AccountId), "test", "")
	u, err := root.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("console-user")})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{accountName, accountEmail} {
		_, err := root.CreateLoginProfile(ctx, &iam.CreateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(forbidden)})
		assertAPIError(t, err, "PasswordPolicyViolation")
	}
	if _, err := root.CreateLoginProfile(ctx, &iam.CreateLoginProfileInput{UserName: u.User.UserName, Password: aws.String("SeparatePassword!92")}); err != nil {
		t.Fatal(err)
	}
	_, err = root.UpdateLoginProfile(ctx, &iam.UpdateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(accountEmail)})
	assertAPIError(t, err, "PasswordPolicyViolation")
	if _, err := root.UpdateAccountPasswordPolicy(ctx, &iam.UpdateAccountPasswordPolicyInput{MinimumPasswordLength: aws.Int32(6)}); err != nil {
		t.Fatal(err)
	}
	if _, err := root.UpdateLoginProfile(ctx, &iam.UpdateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(accountEmail)}); err != nil {
		t.Fatal(err)
	}
	// The registry restriction is account-scoped; the same string is a valid
	// default-policy password for an unrelated account with different metadata.
	other := c.iam("test", "test", "")
	v, err := other.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("other-console-user")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.CreateLoginProfile(ctx, &iam.CreateLoginProfileInput{UserName: v.User.UserName, Password: aws.String(accountName)}); err != nil {
		t.Fatal(err)
	}
}
