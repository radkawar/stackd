package iam_test

import (
	"encoding/json"
	"errors"
	"fmt"
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

func TestIAMCredentialQueryInputsReplayAWS(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/iam/credential_inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	type observation struct {
		Value             string
		Code              string
		HTTPStatus        int   `json:"http_status"`
		ExpirationSeconds int64 `json:"expiration_seconds"`
	}
	var fixture struct {
		NumericInputs   []observation `json:"numeric_inputs"`
		ConditionInputs []observation `json:"condition_inputs"`
		BooleanInputs   []observation `json:"boolean_inputs"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, err error, row observation) {
		t.Helper()
		requireCode(t, err, row.Code)
		if err != nil {
			var response interface{ HTTPStatusCode() int }
			if !errors.As(err, &response) || response.HTTPStatusCode() != row.HTTPStatus {
				t.Fatalf("HTTP status differs from AWS %d: %v", row.HTTPStatus, err)
			}
		}
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
			ctx := t.Context()
			user, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("query-user"), Path: aws.String("/managed/")})
			if err != nil {
				t.Fatal(err)
			}
			if gateway != nil {
				key, err := root.CreateAccessKey(ctx, &sdkiam.CreateAccessKeyInput{UserName: user.User.UserName})
				if err != nil {
					t.Fatal(err)
				}
				actor = gateway.client("us-east-1", identity.Credential{AccessKeyID: aws.ToString(key.AccessKey.AccessKeyId), SecretAccessKey: aws.ToString(key.AccessKey.SecretAccessKey)})
			} else {
				actor = clientForIAMPrincipal(t, service, user.User)
			}
			policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListServiceSpecificCredentials","Resource":"` + aws.ToString(user.User.Arn) + `"},{"Effect":"Allow","Action":"iam:CreateServiceSpecificCredential","Resource":"` + aws.ToString(user.User.Arn) + `","Condition":{"StringEquals":{"iam:ServiceSpecificCredentialAgeDays":"1","iam:ServiceSpecificCredentialServiceName":"bedrock.amazonaws.com"}}}]}`
			if _, err := root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("credential-inputs"), PolicyDocument: &policy}); err != nil {
				t.Fatal(err)
			}
			for _, group := range []struct {
				name   string
				client *sdkiam.Client
				rows   []observation
			}{{"numeric", root, fixture.NumericInputs}, {"condition", actor, fixture.ConditionInputs}} {
				for i, row := range group.rows {
					t.Run(fmt.Sprintf("%s_%d", group.name, i), func(t *testing.T) {
						out, err := group.client.CreateServiceSpecificCredential(ctx, &sdkiam.CreateServiceSpecificCredentialInput{UserName: user.User.UserName, ServiceName: aws.String("bedrock.amazonaws.com"), CredentialAgeDays: aws.Int32(1)}, func(options *sdkiam.Options) {
							options.APIOptions = append(options.APIOptions, awstest.QueryValues(url.Values{"CredentialAgeDays": {row.Value}}))
						})
						check(t, err, row)
						if err == nil {
							credential := out.ServiceSpecificCredential
							if credential.ExpirationDate == nil || credential.CreateDate == nil || int64(credential.ExpirationDate.Sub(*credential.CreateDate)/time.Second) != row.ExpirationSeconds {
								t.Fatal("credential lifetime differs from AWS")
							}
							if _, err := root.DeleteServiceSpecificCredential(ctx, &sdkiam.DeleteServiceSpecificCredentialInput{UserName: user.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId}); err != nil {
								t.Fatal(err)
							}
						}
						remaining, err := root.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{UserName: user.User.UserName})
						if err != nil || len(remaining.ServiceSpecificCredentials) != 0 {
							t.Fatalf("rejected or deleted credential remains: %+v, %v", remaining, err)
						}
					})
				}
			}
			for i, row := range fixture.BooleanInputs {
				t.Run(fmt.Sprintf("boolean_%d", i), func(t *testing.T) {
					out, err := actor.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{}, func(options *sdkiam.Options) {
						options.APIOptions = append(options.APIOptions, awstest.QueryValues(url.Values{"AllUsers": {row.Value}}))
					})
					check(t, err, row)
					if err == nil && len(out.ServiceSpecificCredentials) != 0 {
						t.Fatal("unexpected credential in own listing")
					}
				})
			}
		})
	}
}
