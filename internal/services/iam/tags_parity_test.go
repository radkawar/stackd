package iam_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/services/iam"
)

type tagAWSObservation struct {
	Case       string      `json:"case"`
	Code       string      `json:"code"`
	Tags       []types.Tag `json:"tags"`
	WireFields []string    `json:"wire_fields"`
}

func tagAWSFixture(t *testing.T) map[string]tagAWSObservation {
	t.Helper()
	data, err := os.ReadFile("testdata/tags_aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []tagAWSObservation `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	result := make(map[string]tagAWSObservation, len(fixture.Observations))
	for _, observation := range fixture.Observations {
		result[observation.Case] = observation
	}
	return result
}

func TestIAMTagValidationReplaysAWS(t *testing.T) {
	fixture := tagAWSFixture(t)
	check := func(name string, err error) {
		t.Helper()
		observation, ok := fixture[name]
		if !ok {
			t.Fatalf("missing AWS tag observation %s", name)
		}
		if observation.Code == "Success" {
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		} else {
			requireCode(t, err, observation.Code)
		}
	}
	ctx := context.Background()
	client := clientFor(t, iam.New(), "123456789012", "us-east-1")
	name := aws.String("tag-parity")
	_, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: name, Tags: []types.Tag{{Key: aws.String("Team"), Value: aws.String("One")}}})
	check("create_user", err)
	_, err = client.TagUser(ctx, &sdkiam.TagUserInput{UserName: name, Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("Two")}}})
	check("user_replace_key_case", err)
	tags, err := client.ListUserTags(ctx, &sdkiam.ListUserTagsInput{UserName: name})
	check("user_case_result", err)
	expected := fixture["user_case_result"].Tags
	if len(tags.Tags) != len(expected) || aws.ToString(tags.Tags[0].Key) != aws.ToString(expected[0].Key) || aws.ToString(tags.Tags[0].Value) != aws.ToString(expected[0].Value) {
		t.Fatalf("key casing differs from AWS: %+v", tags.Tags)
	}
	for _, test := range []struct {
		name string
		tags []types.Tag
	}{
		{"user_duplicate_case_keys", []types.Tag{{Key: aws.String("DUP"), Value: aws.String("one")}, {Key: aws.String("dup"), Value: aws.String("two")}}},
		{"user_reserved_key", []types.Tag{{Key: aws.String("aws:reserved"), Value: aws.String("one")}}},
		{"user_reserved_key_upper", []types.Tag{{Key: aws.String("AWS:reserved"), Value: aws.String("one")}}},
		{"user_reserved_value", []types.Tag{{Key: aws.String("reservedvalue"), Value: aws.String("aws:reserved")}}},
		{"user_reserved_value_upper", []types.Tag{{Key: aws.String("reservedvalueupper"), Value: aws.String("AWS:reserved")}}},
		{"user_whitespace_key", []types.Tag{{Key: aws.String("white\tkey"), Value: aws.String("line\nvalue")}}},
		{"user_empty_tag_list", []types.Tag{}},
	} {
		_, err := client.TagUser(ctx, &sdkiam.TagUserInput{UserName: name, Tags: test.tags})
		check(test.name, err)
	}
	for _, test := range []struct {
		name string
		keys []string
	}{
		{"user_empty_untag_list", []string{}},
		{"user_untag_reserved_key", []string{"aws:reserved"}},
		{"user_untag_duplicate_case", []string{"Team", "team"}},
	} {
		_, err := client.UntagUser(ctx, &sdkiam.UntagUserInput{UserName: name, TagKeys: test.keys})
		check(test.name, err)
	}
	tags, err = client.ListUserTags(ctx, &sdkiam.ListUserTagsInput{UserName: name})
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(tags.Tags))
	for _, tag := range tags.Tags {
		keys = append(keys, aws.ToString(tag.Key))
	}
	if _, err := client.UntagUser(ctx, &sdkiam.UntagUserInput{UserName: name, TagKeys: keys}); err != nil {
		t.Fatal(err)
	}
	fifty := make([]types.Tag, 50)
	for i := range fifty {
		fifty[i] = types.Tag{Key: aws.String(fmt.Sprintf("key%02d", i)), Value: aws.String("v")}
	}
	_, err = client.TagUser(ctx, &sdkiam.TagUserInput{UserName: name, Tags: fifty})
	check("user_fill_fifty_tags", err)
	_, err = client.TagUser(ctx, &sdkiam.TagUserInput{UserName: name, Tags: []types.Tag{{Key: aws.String("extra"), Value: aws.String("v")}, {Key: aws.String("key00"), Value: aws.String("changed")}}})
	check("user_exceed_total_tag_quota", err)
	tags, err = client.ListUserTags(ctx, &sdkiam.ListUserTagsInput{UserName: name})
	check("user_tags_after_quota_rejection", err)
	if len(tags.Tags) != 50 || aws.ToString(tags.Tags[0].Value) != "v" {
		t.Fatal("failed quota check partially overwrote existing tags")
	}
	_, err = client.TagUser(ctx, &sdkiam.TagUserInput{UserName: name, Tags: append(fifty, types.Tag{Key: aws.String("extra"), Value: aws.String("v")})})
	check("user_exceed_request_tag_limit", err)
}

func TestIAMPolicyAndMFATagCasesReplayAWS(t *testing.T) {
	fixture := tagAWSFixture(t)
	ctx := context.Background()
	client := clientFor(t, iam.New(), "123456789012", "us-east-1")
	caseTags := []types.Tag{{Key: aws.String("Team"), Value: aws.String("One")}, {Key: aws.String("team"), Value: aws.String("Two")}}
	policy, err := client.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("tagged-policy"), PolicyDocument: aws.String(allowRead), Tags: caseTags})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Policy.Tags) != len(fixture["create_policy_case_variants"].Tags) {
		t.Fatal("policy creation lost case-sensitive tag variants")
	}
	read, err := client.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: policy.Policy.Arn})
	if err != nil || len(read.Policy.Tags) != len(fixture["get_policy_tags"].Tags) {
		t.Fatalf("GetPolicy tag output differs from AWS: %+v %v", read, err)
	}
	_, err = client.TagPolicy(ctx, &sdkiam.TagPolicyInput{PolicyArn: policy.Policy.Arn, Tags: []types.Tag{{Key: aws.String("reservedvalue"), Value: aws.String("aws:reserved")}}})
	if err != nil || fixture["policy_reserved_value"].Code != "Success" {
		t.Fatalf("policy value prefix differs from AWS: %v", err)
	}
	mfa, err := client.CreateVirtualMFADevice(ctx, &sdkiam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("tagged-mfa"), Tags: caseTags})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListMFADeviceTags(ctx, &sdkiam.ListMFADeviceTagsInput{SerialNumber: mfa.VirtualMFADevice.SerialNumber})
	if err != nil || len(listed.Tags) != len(fixture["mfa_case_result"].Tags) {
		t.Fatalf("MFA case variants differ from AWS: %+v %v", listed, err)
	}
	_, err = client.TagMFADevice(ctx, &sdkiam.TagMFADeviceInput{SerialNumber: mfa.VirtualMFADevice.SerialNumber, Tags: []types.Tag{{Key: aws.String("reservedvalue"), Value: aws.String("aws:reserved")}}})
	if err != nil || fixture["mfa_reserved_value"].Code != "Success" {
		t.Fatalf("MFA value prefix differs from AWS: %v", err)
	}
	_, err = client.TagMFADevice(ctx, &sdkiam.TagMFADeviceInput{SerialNumber: mfa.VirtualMFADevice.SerialNumber, Tags: []types.Tag{{Key: aws.String("aws:reserved"), Value: aws.String("One")}}})
	requireCode(t, err, fixture["mfa_reserved_key"].Code)
}
