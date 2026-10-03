package iam_test

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/awstest"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

func TestIAMTagInputsReplayAWS(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/iam/tag_inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Actor, Code string
			HTTPStatus        int `json:"http_status"`
			Query             map[string]string
			Tags              []types.Tag
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
			target, err := root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("tag-target"), Path: aws.String("/stackd-probes/")})
			if err != nil {
				t.Fatal(err)
			}
			user, err := root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("tag-actor"), Path: aws.String("/stackd-probes/")})
			if err != nil {
				t.Fatal(err)
			}
			if gateway != nil {
				key, err := root.CreateAccessKey(t.Context(), &sdkiam.CreateAccessKeyInput{UserName: user.User.UserName})
				if err != nil {
					t.Fatal(err)
				}
				actor = gateway.client("us-east-1", identity.Credential{AccessKeyID: aws.ToString(key.AccessKey.AccessKeyId), SecretAccessKey: aws.ToString(key.AccessKey.SecretAccessKey)})
			} else {
				actor = clientForIAMPrincipal(t, service, user.User)
			}
			policy := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:TagUser","Resource":"` + aws.ToString(target.User.Arn) + `","Condition":{"StringEquals":{"aws:RequestTag/team":"approved"},"ForAllValues:StringEquals":{"aws:TagKeys":["team"]}}}}`
			if _, err := root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("TagInputs"), PolicyDocument: &policy}); err != nil {
				t.Fatal(err)
			}
			for _, row := range fixture.Observations {
				t.Run(row.Actor+"/"+row.Case, func(t *testing.T) {
					client := root
					if row.Actor == "conditional" {
						client = actor
					}
					fields := url.Values{"Tags": nil}
					for name, value := range row.Query {
						fields.Set(name, value)
					}
					_, err := client.TagUser(t.Context(), &sdkiam.TagUserInput{UserName: target.User.UserName, Tags: []types.Tag{}}, func(options *sdkiam.Options) {
						options.APIOptions = append(options.APIOptions, awstest.QueryValues(fields))
					})
					requireCode(t, err, row.Code)
					if err != nil {
						var response interface{ HTTPStatusCode() int }
						if !errors.As(err, &response) || response.HTTPStatusCode() != row.HTTPStatus {
							t.Fatalf("HTTP status differs from AWS %d: %v", row.HTTPStatus, err)
						}
					}
					out, err := root.ListUserTags(t.Context(), &sdkiam.ListUserTagsInput{UserName: target.User.UserName})
					if err != nil {
						t.Fatal(err)
					}
					if !slices.EqualFunc(out.Tags, row.Tags, func(a, b types.Tag) bool {
						return aws.ToString(a.Key) == aws.ToString(b.Key) && aws.ToString(a.Value) == aws.ToString(b.Value)
					}) {
						t.Fatalf("tag state differs from AWS: %+v, want %+v", out.Tags, row.Tags)
					}
					var keys []string
					for _, tag := range out.Tags {
						keys = append(keys, aws.ToString(tag.Key))
					}
					if len(keys) > 0 {
						if _, err := root.UntagUser(t.Context(), &sdkiam.UntagUserInput{UserName: target.User.UserName, TagKeys: keys}); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func TestIAMQueryCollectionsReplayAWS(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/iam/query_collections.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Code  string
			HTTPStatus  int `json:"http_status"`
			Query       map[string]string
			ContextKeys []string `json:"context_keys"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"standalone", "gateway"} {
		t.Run(endpoint, func(t *testing.T) {
			var client *sdkiam.Client
			if endpoint == "gateway" {
				client = newActivityFixture(t, nil, time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)).root
			} else {
				service := iam.New()
				t.Cleanup(func() { _ = service.Close() })
				client = clientFor(t, service, "123456789012", "us-east-1")
			}
			for _, row := range fixture.Observations {
				t.Run(row.Case, func(t *testing.T) {
					fields := url.Values{"PolicyInputList": nil}
					for name, value := range row.Query {
						fields.Set(name, value)
					}
					out, err := client.GetContextKeysForCustomPolicy(t.Context(), &sdkiam.GetContextKeysForCustomPolicyInput{PolicyInputList: []string{}}, func(options *sdkiam.Options) {
						options.APIOptions = append(options.APIOptions, awstest.QueryValues(fields))
					})
					requireCode(t, err, row.Code)
					if err != nil {
						var response interface{ HTTPStatusCode() int }
						if !errors.As(err, &response) || response.HTTPStatusCode() != row.HTTPStatus {
							t.Fatalf("HTTP status differs from AWS %d: %v", row.HTTPStatus, err)
						}
						return
					}
					if !slices.Equal(out.ContextKeyNames, row.ContextKeys) {
						t.Fatalf("policy context keys differ from AWS: %v", out.ContextKeyNames)
					}
				})
			}
		})
	}
}
