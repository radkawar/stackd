package iam_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/services/iam"
)

func TestPasswordPolicyReplacementHistoryAndExpiry(t *testing.T) {
	ctx := context.Background()
	repository := iam.NewMemoryRepository(nil)
	service := iam.NewWithRepository(nil, repository)
	root := clientFor(t, service, "123456789012", "us-east-1")
	_, err := root.GetAccountPasswordPolicy(ctx, &sdkiam.GetAccountPasswordPolicyInput{})
	requireCode(t, err, "NoSuchEntity")
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("policy-user")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.CreateLoginProfile(ctx, &sdkiam.CreateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(loginPasswordA)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.UpdateAccountPasswordPolicy(ctx, &sdkiam.UpdateAccountPasswordPolicyInput{MinimumPasswordLength: aws.Int32(12), RequireNumbers: true, RequireSymbols: true, RequireLowercaseCharacters: true, RequireUppercaseCharacters: true, PasswordReusePrevention: aws.Int32(2), MaxPasswordAge: aws.Int32(1), HardExpiry: aws.Bool(true), AllowUsersToChangePassword: true})
	if err != nil {
		t.Fatal(err)
	}
	user := clientForIAMPrincipal(t, service, u.User)
	policy, err := user.GetAccountPasswordPolicy(ctx, &sdkiam.GetAccountPasswordPolicyInput{})
	if err != nil || !policy.PasswordPolicy.AllowUsersToChangePassword || !policy.PasswordPolicy.ExpirePasswords || aws.ToInt32(policy.PasswordPolicy.PasswordReusePrevention) != 2 {
		t.Fatalf("self-service policy read: %+v %v", policy, err)
	}
	_, err = user.ChangePassword(ctx, &sdkiam.ChangePasswordInput{OldPassword: aws.String(loginPasswordA), NewPassword: aws.String("alllowercasewords")})
	requireCode(t, err, "PasswordPolicyViolation")
	_, err = user.ChangePassword(ctx, &sdkiam.ChangePasswordInput{OldPassword: aws.String(loginPasswordA), NewPassword: aws.String(loginPasswordB)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.UpdateLoginProfile(ctx, &sdkiam.UpdateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(loginPasswordA)})
	requireCode(t, err, "PasswordPolicyViolation")
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	err = repository.Update(ctx, func(tx iam.WriteTx) error {
		profile, err := tx.LoginProfile(scope, aws.ToString(u.User.UserId))
		if err != nil {
			return err
		}
		profile.PasswordChangedAt = time.Now().Add(-48 * time.Hour)
		return tx.PutLoginProfile(scope, profile)
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := service.VerifyPassword(ctx, scope, "policy-user", loginPasswordB)
	if err != nil || !status.PasswordExpired || !status.PasswordChangeRequired || !status.AdministratorResetRequired || status.PasswordExpiresAt == nil {
		t.Fatalf("hard expiry: %+v %v", status, err)
	}
	_, err = user.ChangePassword(ctx, &sdkiam.ChangePasswordInput{OldPassword: aws.String(loginPasswordB), NewPassword: aws.String(loginPasswordC)})
	if err != nil {
		t.Fatalf("signed API cannot reset hard-expired password: %v", err)
	}
	status, err = service.VerifyPassword(ctx, scope, "policy-user", loginPasswordC)
	if err != nil || status.PasswordExpired || status.PasswordChangeRequired {
		t.Fatalf("password change did not reset expiry: %+v %v", status, err)
	}
	_, err = root.UpdateLoginProfile(ctx, &sdkiam.UpdateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(loginPasswordA)})
	if err != nil {
		t.Fatalf("password outside last two remains blocked: %v", err)
	}
	_, err = root.UpdateAccountPasswordPolicy(ctx, &sdkiam.UpdateAccountPasswordPolicyInput{RequireNumbers: true})
	if err != nil {
		t.Fatal(err)
	}
	policy, err = root.GetAccountPasswordPolicy(ctx, &sdkiam.GetAccountPasswordPolicyInput{})
	if err != nil || aws.ToInt32(policy.PasswordPolicy.MinimumPasswordLength) != 6 || !policy.PasswordPolicy.RequireNumbers || policy.PasswordPolicy.RequireSymbols || policy.PasswordPolicy.AllowUsersToChangePassword || policy.PasswordPolicy.ExpirePasswords || policy.PasswordPolicy.PasswordReusePrevention != nil {
		t.Fatalf("update did not replace omitted settings with defaults: %+v %v", policy, err)
	}
	_, err = user.GetAccountPasswordPolicy(ctx, &sdkiam.GetAccountPasswordPolicyInput{})
	requireCode(t, err, "AccessDenied")
	_, err = root.DeleteAccountPasswordPolicy(ctx, &sdkiam.DeleteAccountPasswordPolicyInput{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.GetAccountPasswordPolicy(ctx, &sdkiam.GetAccountPasswordPolicyInput{})
	requireCode(t, err, "NoSuchEntity")
	_, err = root.DeleteAccountPasswordPolicy(ctx, &sdkiam.DeleteAccountPasswordPolicyInput{})
	requireCode(t, err, "NoSuchEntity")
}

type passwordDenyControls struct{}

func (passwordDenyControls) ServiceControlPolicies(context.Context) ([]iampolicy.PolicyLevel, error) {
	return []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:ChangePassword","Resource":"*"}]}`}}}}, nil
}

func TestPasswordSelfServiceHonorsIdentityBoundaryAndSCPDenies(t *testing.T) {
	for _, layer := range []string{"identity", "boundary", "scp"} {
		t.Run(layer, func(t *testing.T) {
			ctx := context.Background()
			service := iam.New()
			root := clientFor(t, service, "123456789012", "us-east-1")
			u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("limited")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.CreateLoginProfile(ctx, &sdkiam.CreateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(loginPasswordA)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.UpdateAccountPasswordPolicy(ctx, &sdkiam.UpdateAccountPasswordPolicyInput{AllowUsersToChangePassword: true})
			if err != nil {
				t.Fatal(err)
			}
			switch layer {
			case "identity":
				_, err = root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: u.User.UserName, PolicyName: aws.String("deny"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Deny","Action":"iam:ChangePassword","Resource":"*"}}`)})
			case "boundary":
				var boundaryARN string
				boundaryARN = mustCreatePolicy(t, root, "read-only-boundary")
				_, err = root.PutUserPermissionsBoundary(ctx, &sdkiam.PutUserPermissionsBoundaryInput{UserName: u.User.UserName, PermissionsBoundary: aws.String(boundaryARN)})
			case "scp":
				service.SetAuthorizer(authorization.New(service, passwordDenyControls{}))
			}
			if err != nil {
				t.Fatal(err)
			}
			user := clientForIAMPrincipal(t, service, u.User)
			_, err = user.ChangePassword(ctx, &sdkiam.ChangePasswordInput{OldPassword: aws.String(loginPasswordA), NewPassword: aws.String(loginPasswordB)})
			requireCode(t, err, "AccessDenied")
			status, err := service.VerifyPassword(ctx, iam.Scope{Partition: "aws", AccountID: "123456789012"}, "limited", loginPasswordA)
			if err != nil || status.Principal.ID != aws.ToString(u.User.UserId) {
				t.Fatalf("denied operation changed password: %+v %v", status, err)
			}
		})
	}
}

func TestPasswordPolicyGeneratedInputConstraints(t *testing.T) {
	root := clientFor(t, iam.New(), "123456789012", "us-east-1")
	for _, input := range []*sdkiam.UpdateAccountPasswordPolicyInput{{MinimumPasswordLength: aws.Int32(5)}, {MinimumPasswordLength: aws.Int32(129)}, {MaxPasswordAge: aws.Int32(0)}, {MaxPasswordAge: aws.Int32(1096)}, {PasswordReusePrevention: aws.Int32(0)}, {PasswordReusePrevention: aws.Int32(25)}} {
		t.Run(fmt.Sprintf("%+v", input), func(t *testing.T) {
			_, err := root.UpdateAccountPasswordPolicy(context.Background(), input)
			requireCode(t, err, "ValidationError")
		})
	}
}
