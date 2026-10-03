package iam_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/services/iam"
)

type capturedRoleState struct {
	Description string
	Duration    int32
}

func TestIAMResourceInputsReplayAWS(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/iam/resource_inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Creates []struct {
			Character string
			Count     int
			Code      string
			State     capturedRoleState
		}
		DurationCreates []struct {
			Duration int32
			Code     string
		} `json:"duration_creates"`
		Updates []struct {
			Operation string
			Input     struct {
				Description        *string
				MaxSessionDuration *int32
			}
			Code  string
			State capturedRoleState
		}
		KeyStatuses []struct {
			Status       types.StatusType
			Code         string
			StoredStatus types.StatusType `json:"stored_status"`
		} `json:"key_statuses"`
		Tags []struct {
			Kind   string
			Action string
			Input  struct {
				Tags    []types.Tag
				TagKeys []string
			}
			Code       string
			StoredTags []types.Tag `json:"stored_tags"`
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"standalone", "gateway"} {
		t.Run(endpoint, func(t *testing.T) {
			var client *sdkiam.Client
			if endpoint == "gateway" {
				client = newActivityFixture(t, nil, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)).root
			} else {
				service := iam.New()
				t.Cleanup(func() { _ = service.Close() })
				client = clientFor(t, service, "123456789012", "us-east-1")
			}
			ctx := t.Context()
			checkRole := func(t *testing.T, name string, want capturedRoleState) {
				t.Helper()
				out, err := client.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: &name})
				if err != nil {
					t.Fatal(err)
				}
				got := capturedRoleState{Description: aws.ToString(out.Role.Description), Duration: aws.ToInt32(out.Role.MaxSessionDuration)}
				if got != want {
					t.Fatalf("stored role = %+v; AWS = %+v", got, want)
				}
			}
			for i, row := range fixture.Creates {
				t.Run(fmt.Sprintf("create_description_%d", i), func(t *testing.T) {
					name := fmt.Sprintf("description-%d", i)
					_, err := client.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: &name, AssumeRolePolicyDocument: aws.String(trustEC2), Description: aws.String(strings.Repeat(row.Character, row.Count))})
					requireCode(t, err, row.Code)
					if row.Code == "Success" {
						checkRole(t, name, row.State)
					} else {
						_, err := client.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: &name})
						requireCode(t, err, "NoSuchEntity")
					}
				})
			}
			for _, row := range fixture.DurationCreates {
				t.Run(fmt.Sprintf("create_duration_%d", row.Duration), func(t *testing.T) {
					_, err := client.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("invalid-duration"), AssumeRolePolicyDocument: aws.String(trustEC2), MaxSessionDuration: &row.Duration})
					requireCode(t, err, row.Code)
				})
			}
			name := aws.String("updated")
			_, err := client.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: name, AssumeRolePolicyDocument: aws.String(trustEC2), Description: aws.String("initial"), MaxSessionDuration: aws.Int32(7200)})
			if err != nil {
				t.Fatal(err)
			}
			for i, row := range fixture.Updates {
				t.Run(fmt.Sprintf("update_%d", i), func(t *testing.T) {
					var err error
					if row.Operation == "update-role" {
						_, err = client.UpdateRole(ctx, &sdkiam.UpdateRoleInput{RoleName: name, Description: row.Input.Description, MaxSessionDuration: row.Input.MaxSessionDuration})
					} else {
						_, err = client.UpdateRoleDescription(ctx, &sdkiam.UpdateRoleDescriptionInput{RoleName: name, Description: row.Input.Description})
					}
					requireCode(t, err, row.Code)
					checkRole(t, *name, row.State)
				})
			}
			t.Run("access_key_status", func(t *testing.T) {
				name := aws.String("key-owner")
				if _, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: name}); err != nil {
					t.Fatal(err)
				}
				key, err := client.CreateAccessKey(ctx, &sdkiam.CreateAccessKeyInput{UserName: name})
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range fixture.KeyStatuses {
					_, err := client.UpdateAccessKey(ctx, &sdkiam.UpdateAccessKeyInput{UserName: name, AccessKeyId: key.AccessKey.AccessKeyId, Status: row.Status})
					requireCode(t, err, row.Code)
					out, err := client.ListAccessKeys(ctx, &sdkiam.ListAccessKeysInput{UserName: name})
					if err != nil || len(out.AccessKeyMetadata) != 1 || out.AccessKeyMetadata[0].Status != row.StoredStatus {
						t.Fatalf("status after %s = %+v, %v; AWS = %s", row.Status, out, err, row.StoredStatus)
					}
				}
			})
			oidc, err := client.CreateOpenIDConnectProvider(ctx, &sdkiam.CreateOpenIDConnectProviderInput{Url: aws.String("https://tags.example.com/path/"), ThumbprintList: []string{strings.Repeat("a", 40)}})
			if err != nil {
				t.Fatal(err)
			}
			saml, err := client.CreateSAMLProvider(ctx, &sdkiam.CreateSAMLProviderInput{Name: aws.String("tags"), SAMLMetadataDocument: aws.String(federationFixture(t, "metadata.xml"))})
			if err != nil {
				t.Fatal(err)
			}
			for i, row := range fixture.Tags {
				t.Run(fmt.Sprintf("%s_%s_%d", row.Kind, row.Action, i), func(t *testing.T) {
					var tags []types.Tag
					var err error
					if row.Kind == "open-id-connect" {
						if row.Action == "tag" {
							_, err = client.TagOpenIDConnectProvider(ctx, &sdkiam.TagOpenIDConnectProviderInput{OpenIDConnectProviderArn: oidc.OpenIDConnectProviderArn, Tags: row.Input.Tags})
						} else {
							_, err = client.UntagOpenIDConnectProvider(ctx, &sdkiam.UntagOpenIDConnectProviderInput{OpenIDConnectProviderArn: oidc.OpenIDConnectProviderArn, TagKeys: row.Input.TagKeys})
						}
						requireCode(t, err, row.Code)
						out, listErr := client.ListOpenIDConnectProviderTags(ctx, &sdkiam.ListOpenIDConnectProviderTagsInput{OpenIDConnectProviderArn: oidc.OpenIDConnectProviderArn})
						if listErr != nil {
							t.Fatal(listErr)
						}
						tags = out.Tags
					} else {
						if row.Action == "tag" {
							_, err = client.TagSAMLProvider(ctx, &sdkiam.TagSAMLProviderInput{SAMLProviderArn: saml.SAMLProviderArn, Tags: row.Input.Tags})
						} else {
							_, err = client.UntagSAMLProvider(ctx, &sdkiam.UntagSAMLProviderInput{SAMLProviderArn: saml.SAMLProviderArn, TagKeys: row.Input.TagKeys})
						}
						requireCode(t, err, row.Code)
						out, listErr := client.ListSAMLProviderTags(ctx, &sdkiam.ListSAMLProviderTagsInput{SAMLProviderArn: saml.SAMLProviderArn})
						if listErr != nil {
							t.Fatal(listErr)
						}
						tags = out.Tags
					}
					if !reflect.DeepEqual(tags, row.StoredTags) {
						t.Fatalf("stored tags = %+v; AWS = %+v", tags, row.StoredTags)
					}
				})
			}
		})
	}
}
