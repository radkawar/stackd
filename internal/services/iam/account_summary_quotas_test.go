package iam_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/internal/iam/managed"
	"stackd/internal/services/iam"
)

func TestIAMAccountSummaryAttachmentQuotas(t *testing.T) {
	service := iam.New()
	client := clientFor(t, service, "123456789012", "us-east-1")
	if _, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("quota-user")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateGroup(t.Context(), &sdkiam.CreateGroupInput{GroupName: aws.String("quota-group")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("quota-role"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}}`)}); err != nil {
		t.Fatal(err)
	}
	policies := make([]string, 21)
	for index := range policies {
		policies[index] = mustCreatePolicy(t, client, fmt.Sprintf("quota-%02d", index))
	}
	summary := accountSummary(t, client)
	for _, item := range []struct {
		kind   string
		quota  int
		attach func(string) error
	}{
		{"User", 10, func(arn string) error {
			_, err := client.AttachUserPolicy(t.Context(), &sdkiam.AttachUserPolicyInput{UserName: aws.String("quota-user"), PolicyArn: aws.String(arn)})
			return err
		}},
		{"Group", 10, func(arn string) error {
			_, err := client.AttachGroupPolicy(t.Context(), &sdkiam.AttachGroupPolicyInput{GroupName: aws.String("quota-group"), PolicyArn: aws.String(arn)})
			return err
		}},
		{"Role", 20, func(arn string) error {
			_, err := client.AttachRolePolicy(t.Context(), &sdkiam.AttachRolePolicyInput{RoleName: aws.String("quota-role"), PolicyArn: aws.String(arn)})
			return err
		}},
	} {
		t.Run(item.kind, func(t *testing.T) {
			if got := summary["AttachedPoliciesPer"+item.kind+"Quota"]; got != int32(item.quota) {
				t.Fatalf("reported quota %d, want %d", got, item.quota)
			}
			for _, arn := range policies[:item.quota] {
				if err := item.attach(arn); err != nil {
					t.Fatal(err)
				}
			}
			if err := item.attach(policies[0]); err != nil {
				t.Fatal("repeat attachment consumed quota", err)
			}
			requireCode(t, item.attach(policies[item.quota]), "LimitExceeded")
		})
	}
	role, err := client.ListAttachedRolePolicies(t.Context(), &sdkiam.ListAttachedRolePoliciesInput{RoleName: aws.String("quota-role")})
	if err != nil || len(role.AttachedPolicies) != 20 {
		t.Fatal("rejected role attachment changed state", err)
	}
	if _, err := client.DetachRolePolicy(t.Context(), &sdkiam.DetachRolePolicyInput{RoleName: aws.String("quota-role"), PolicyArn: aws.String(policies[0])}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachRolePolicy(t.Context(), &sdkiam.AttachRolePolicyInput{RoleName: aws.String("quota-role"), PolicyArn: aws.String(policies[20])}); err != nil {
		t.Fatal("detach did not release quota", err)
	}
}

func TestIAMAccountSummaryPolicyUseQuotaBound(t *testing.T) {
	client := clientFor(t, iam.New(), "123456789012", "us-east-1")
	summary := accountSummary(t, client)
	// Every attached/default policy is either customer-owned or belongs to
	// this finite immutable catalogue. A future capture/default-quota increase
	// that breaks the bound requires enforcement on first policy usage.
	maximum := int(summary["PoliciesQuota"]) + len(managed.List("aws"))
	if maximum > int(summary["PolicyVersionsInUseQuota"]) {
		t.Fatalf("%d possible distinct policy versions exceed the reported usage quota %d; implement first-usage quota checks", maximum, summary["PolicyVersionsInUseQuota"])
	}
}
