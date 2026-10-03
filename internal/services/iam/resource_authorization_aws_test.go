package iam_test

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/internal/awstest"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

func TestIAMResourceAuthorizationReplayAWS(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/iam/resource_authorization.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Operation, Phase, Code, ARN string
			HTTPStatus                        int    `json:"http_status"`
			UserName                          string `json:"user_name"`
			Input                             map[string]string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"standalone", "gateway"} {
		t.Run(endpoint, func(t *testing.T) {
			var root, actor *sdkiam.Client
			var service *iam.Service
			var gateway *activityFixture
			if endpoint == "gateway" {
				gateway = newActivityFixture(t, nil, time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
				root = gateway.root
			} else {
				service = iam.New()
				t.Cleanup(func() { _ = service.Close() })
				root = clientFor(t, service, "123456789012", "us-east-1")
			}
			const path = "/stackd-probes/resource-auth/"
			user, err := root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("resource-auth-User"), Path: aws.String(path)})
			if err != nil {
				t.Fatal(err)
			}
			caller, err := root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("resource-auth-Actor"), Path: aws.String(path)})
			if err != nil {
				t.Fatal(err)
			}
			if gateway != nil {
				key, err := root.CreateAccessKey(t.Context(), &sdkiam.CreateAccessKeyInput{UserName: caller.User.UserName})
				if err != nil {
					t.Fatal(err)
				}
				actor = gateway.client("us-east-1", identity.Credential{AccessKeyID: aws.ToString(key.AccessKey.AccessKeyId), SecretAccessKey: aws.ToString(key.AccessKey.SecretAccessKey)})
			} else {
				actor = clientForIAMPrincipal(t, service, caller.User)
			}
			key, err := root.CreateAccessKey(t.Context(), &sdkiam.CreateAccessKeyInput{UserName: user.User.UserName})
			if err != nil {
				t.Fatal(err)
			}
			group, err := root.CreateGroup(t.Context(), &sdkiam.CreateGroupInput{GroupName: aws.String("resource-auth-Group"), Path: aws.String(path)})
			if err != nil {
				t.Fatal(err)
			}
			role, err := root.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("resource-auth-Role"), Path: aws.String(path), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::123456789012:root"}}}`)})
			if err != nil {
				t.Fatal(err)
			}
			profile, err := root.CreateInstanceProfile(t.Context(), &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String("resource-auth-Profile"), Path: aws.String(path)})
			if err != nil {
				t.Fatal(err)
			}
			policy, err := root.CreatePolicy(t.Context(), &sdkiam.CreatePolicyInput{PolicyName: aws.String("resource-auth-Policy"), Path: aws.String(path), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			document := `{"Version":"2012-10-17","Statement":[
{"Effect":"Allow","Action":["iam:GetUser","iam:ListAccessKeys","iam:GetAccessKeyLastUsed","iam:GetContextKeysForPrincipalPolicy","iam:SimulatePrincipalPolicy"],"Resource":"` + aws.ToString(user.User.Arn) + `"},
{"Effect":"Allow","Action":"iam:GetUser","Resource":"` + aws.ToString(caller.User.Arn) + `"},
{"Effect":"Allow","Action":"iam:GetGroup","Resource":"` + aws.ToString(group.Group.Arn) + `"},
{"Effect":"Allow","Action":"iam:GetRole","Resource":"` + aws.ToString(role.Role.Arn) + `"},
{"Effect":"Allow","Action":"iam:GetInstanceProfile","Resource":"` + aws.ToString(profile.InstanceProfile.Arn) + `"},
{"Effect":"Allow","Action":"iam:GetPolicy","Resource":"` + aws.ToString(policy.Policy.Arn) + `"},
{"Effect":"Allow","Action":"iam:CreateUser","Resource":"arn:aws:iam::123456789012:user` + path + `created/*"}]}`
			if _, err := root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: caller.User.UserName, PolicyName: aws.String("ResourceInputs"), PolicyDocument: &document}); err != nil {
				t.Fatal(err)
			}
			moved := false
			for _, row := range fixture.Observations {
				if row.Phase == "moved" && !moved {
					if _, err := root.UpdateUser(t.Context(), &sdkiam.UpdateUserInput{UserName: user.User.UserName, NewPath: aws.String(path + "moved/")}); err != nil {
						t.Fatal(err)
					}
					moved = true
				}
				t.Run(row.Operation+"/"+row.Case, func(t *testing.T) {
					var options []func(*sdkiam.Options)
					unknown := url.Values{}
					if path, present := row.Input["Path"]; present && row.Operation != "create-user" {
						unknown.Set("Path", path)
					}
					if row.Operation == "get-access-key-last-used" {
						if name, present := row.Input["UserName"]; present {
							unknown.Set("UserName", name)
						}
					}
					if len(unknown) > 0 {
						options = append(options, func(options *sdkiam.Options) {
							options.APIOptions = append(options.APIOptions, awstest.QueryValues(unknown))
						})
					}
					var arn, userName string
					var err error
					switch row.Operation {
					case "get-user":
						input := &sdkiam.GetUserInput{}
						if name, present := row.Input["UserName"]; present {
							input.UserName = &name
						}
						var out *sdkiam.GetUserOutput
						out, err = actor.GetUser(t.Context(), input, options...)
						if err == nil {
							arn = aws.ToString(out.User.Arn)
						}
					case "get-group":
						var out *sdkiam.GetGroupOutput
						out, err = actor.GetGroup(t.Context(), &sdkiam.GetGroupInput{GroupName: aws.String(row.Input["GroupName"])}, options...)
						if err == nil {
							arn = aws.ToString(out.Group.Arn)
						}
					case "get-role":
						var out *sdkiam.GetRoleOutput
						out, err = actor.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: aws.String(row.Input["RoleName"])}, options...)
						if err == nil {
							arn = aws.ToString(out.Role.Arn)
						}
					case "get-instance-profile":
						var out *sdkiam.GetInstanceProfileOutput
						out, err = actor.GetInstanceProfile(t.Context(), &sdkiam.GetInstanceProfileInput{InstanceProfileName: aws.String(row.Input["InstanceProfileName"])}, options...)
						if err == nil {
							arn = aws.ToString(out.InstanceProfile.Arn)
						}
					case "get-policy":
						var out *sdkiam.GetPolicyOutput
						out, err = actor.GetPolicy(t.Context(), &sdkiam.GetPolicyInput{PolicyArn: aws.String(row.Input["PolicyArn"])}, options...)
						if err == nil {
							arn = aws.ToString(out.Policy.Arn)
						}
					case "get-access-key-last-used":
						var out *sdkiam.GetAccessKeyLastUsedOutput
						out, err = actor.GetAccessKeyLastUsed(t.Context(), &sdkiam.GetAccessKeyLastUsedInput{AccessKeyId: key.AccessKey.AccessKeyId}, options...)
						if err == nil {
							userName = aws.ToString(out.UserName)
						}
					case "get-context-keys-for-principal-policy":
						_, err = actor.GetContextKeysForPrincipalPolicy(t.Context(), &sdkiam.GetContextKeysForPrincipalPolicyInput{PolicySourceArn: aws.String(row.Input["PolicySourceArn"])}, options...)
					case "simulate-principal-policy":
						_, err = actor.SimulatePrincipalPolicy(t.Context(), &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: aws.String(row.Input["PolicySourceArn"]), ActionNames: []string{row.Input["ActionNames.member.1"]}}, options...)
					case "create-user":
						var out *sdkiam.CreateUserOutput
						out, err = actor.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String(row.Input["UserName"]), Path: aws.String(row.Input["Path"])}, options...)
						if err == nil {
							arn = aws.ToString(out.User.Arn)
						}
					default:
						t.Fatalf("unknown captured operation %q", row.Operation)
					}
					requireCode(t, err, row.Code)
					if err != nil {
						var response interface{ HTTPStatusCode() int }
						if !errors.As(err, &response) || response.HTTPStatusCode() != row.HTTPStatus {
							t.Fatalf("HTTP status differs from AWS %d: %v", row.HTTPStatus, err)
						}
					} else if arn != row.ARN || userName != row.UserName {
						t.Fatalf("resolved ARN/name = %q, %q; AWS = %q, %q", arn, userName, row.ARN, row.UserName)
					}
					if row.Operation == "create-user" && row.Code == "AccessDenied" {
						_, err := root.GetUser(t.Context(), &sdkiam.GetUserInput{UserName: aws.String(row.Input["UserName"])})
						requireCode(t, err, "NoSuchEntity")
					}
				})
			}
		})
	}
}
