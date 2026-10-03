package iam_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/services/iam"
)

const loginPasswordA = "FirstPassword12!"
const loginPasswordB = "SecondPassword34!"
const loginPasswordC = "ThirdPassword56!"

func TestLoginProfileReplaysAWSObservations(t *testing.T) {
	data, err := os.ReadFile("testdata/login_profile_aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case                  string `json:"case"`
			Code                  string `json:"code"`
			PasswordResetRequired bool   `json:"password_reset_required"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	check := func(name string, err error) {
		t.Helper()
		for _, observation := range fixture.Observations {
			if observation.Case != name {
				continue
			}
			if observation.Code == "Success" {
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
			} else {
				requireCode(t, err, observation.Code)
			}
			return
		}
		t.Fatalf("missing AWS observation %q", name)
	}
	ctx := context.Background()
	service := iam.New()
	root := clientFor(t, service, "123456789012", "us-east-1")
	created, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("login-user"), Path: aws.String("/engineers/")})
	check("create_user", err)
	u := created.User
	_, err = root.CreateLoginProfile(ctx, &sdkiam.CreateLoginProfileInput{UserName: u.UserName, Password: aws.String("abc123")})
	check("default_policy_weak_password", err)
	var violation *types.PasswordPolicyViolationException
	if !errors.As(err, &violation) {
		t.Fatalf("not a modeled password policy error: %v", err)
	}
	profile, err := root.CreateLoginProfile(ctx, &sdkiam.CreateLoginProfileInput{UserName: u.UserName, Password: aws.String(loginPasswordA), PasswordResetRequired: true})
	check("create_strong_password", err)
	if profile.LoginProfile.CreateDate == nil || aws.ToString(profile.LoginProfile.UserName) != "login-user" || !profile.LoginProfile.PasswordResetRequired {
		t.Fatalf("invalid typed profile output: %+v", profile.LoginProfile)
	}
	_, err = root.CreateLoginProfile(ctx, &sdkiam.CreateLoginProfileInput{UserName: u.UserName, Password: aws.String(loginPasswordA)})
	check("duplicate_login_profile", err)
	_, err = root.UpdateLoginProfile(ctx, &sdkiam.UpdateLoginProfileInput{UserName: u.UserName})
	check("update_no_fields", err)
	_, err = root.UpdateLoginProfile(ctx, &sdkiam.UpdateLoginProfileInput{UserName: u.UserName, Password: aws.String(loginPasswordB)})
	check("password_update_omitting_reset_flag", err)
	got, err := root.GetLoginProfile(ctx, &sdkiam.GetLoginProfileInput{UserName: u.UserName})
	check("get_after_password_update", err)
	if !got.LoginProfile.PasswordResetRequired || !got.LoginProfile.CreateDate.Equal(*profile.LoginProfile.CreateDate) {
		t.Fatal("updating password lost reset state or changed profile creation time")
	}
	policy := `{"Statement":{"Effect":"Allow","Action":"iam:ChangePassword","Resource":"` + aws.ToString(u.Arn) + `"}}`
	_, err = root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: u.UserName, PolicyName: aws.String("self-change"), PolicyDocument: aws.String(policy)})
	check("grant_self_change", err)
	user := clientForIAMPrincipal(t, service, u)
	_, err = user.ChangePassword(ctx, &sdkiam.ChangePasswordInput{OldPassword: aws.String(loginPasswordB), NewPassword: aws.String(loginPasswordA)})
	check("change_correct_password", err)
	_, err = user.ChangePassword(ctx, &sdkiam.ChangePasswordInput{OldPassword: aws.String(loginPasswordB), NewPassword: aws.String(loginPasswordC)})
	check("change_incorrect_old_password", err)
	_, err = user.ChangePassword(ctx, &sdkiam.ChangePasswordInput{OldPassword: aws.String(loginPasswordA), NewPassword: aws.String(loginPasswordA)})
	check("change_to_same_password", err)
	got, err = root.GetLoginProfile(ctx, &sdkiam.GetLoginProfileInput{UserName: u.UserName})
	check("get_after_self_change", err)
	if got.LoginProfile.PasswordResetRequired {
		t.Fatal("self change did not clear reset requirement")
	}
}

func TestLoginProfileIdentityLifecycleAndVerification(t *testing.T) {
	ctx := context.Background()
	repository := iam.NewMemoryRepository(nil)
	service := iam.NewWithRepository(nil, repository)
	root := clientFor(t, service, "123456789012", "us-east-1")
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("password-user")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.CreateLoginProfile(ctx, &sdkiam.CreateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(loginPasswordA), PasswordResetRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	for _, name := range []string{"missing", "password-user"} {
		if _, err := service.VerifyPassword(ctx, scope, name, "wrong-password"); !errors.Is(err, iam.ErrInvalidPassword) {
			t.Fatalf("wrong password error differs for %s: %v", name, err)
		}
	}
	verified, err := service.VerifyPassword(ctx, scope, "PASSWORD-USER", loginPasswordA)
	if err != nil || !verified.PasswordChangeRequired || verified.Principal.ID != aws.ToString(u.User.UserId) {
		t.Fatalf("verified reset-required password: %+v %v", verified, err)
	}
	_, err = root.UpdateLoginProfile(ctx, &sdkiam.UpdateLoginProfileInput{UserName: u.User.UserName, PasswordResetRequired: aws.Bool(false)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.UpdateUser(ctx, &sdkiam.UpdateUserInput{UserName: u.User.UserName, NewUserName: aws.String("renamed"), NewPath: aws.String("/staff/")})
	if err != nil {
		t.Fatal(err)
	}
	verified, err = service.VerifyPassword(ctx, scope, "renamed", loginPasswordA)
	if err != nil || verified.PasswordChangeRequired || !strings.HasSuffix(verified.Principal.ARN, "/staff/renamed") {
		t.Fatalf("renamed profile: %+v %v", verified, err)
	}
	got, err := root.GetUser(ctx, &sdkiam.GetUserInput{UserName: aws.String("renamed")})
	if err != nil || got.User.PasswordLastUsed == nil {
		t.Fatalf("password use not recorded: %+v %v", got, err)
	}
	other := clientFor(t, service, "999999999999", "us-east-1")
	_, err = other.GetLoginProfile(ctx, &sdkiam.GetLoginProfileInput{UserName: aws.String("renamed")})
	requireCode(t, err, "NoSuchEntity")
	if _, err := service.VerifyPassword(ctx, iam.Scope{Partition: "aws-cn", AccountID: scope.AccountID}, "renamed", loginPasswordA); !errors.Is(err, iam.ErrInvalidPassword) {
		t.Fatalf("cross-partition password verification succeeded: %v", err)
	}
	_, err = root.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String("renamed")})
	requireCode(t, err, "DeleteConflict")
	_, err = root.DeleteLoginProfile(ctx, &sdkiam.DeleteLoginProfileInput{UserName: aws.String("renamed")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String("renamed")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("renamed")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyPassword(ctx, scope, "renamed", loginPasswordA); !errors.Is(err, iam.ErrInvalidPassword) {
		t.Fatalf("recreated user inherited old password: %v", err)
	}
}
