package iam_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/internal/services/iam"
)

func TestIAMAccountSummaryPolicyUsageTransitions(t *testing.T) {
	client := clientFor(t, iam.New(), "123456789012", "us-east-1")
	if _, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("usage-user")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateGroup(t.Context(), &sdkiam.CreateGroupInput{GroupName: aws.String("usage-group")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("usage-role"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}}`)}); err != nil {
		t.Fatal(err)
	}
	attached := mustCreatePolicy(t, client, "usage-attached")
	boundary := mustCreatePolicy(t, client, "usage-boundary")
	assertUsage := func(name string, used int32) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			requireSummaryValues(t, accountSummary(t, client), map[string]int32{"Policies": 2, "PolicyVersionsInUse": used})
		})
	}
	assertUsage("unreferenced policies", 0)
	for _, setDefault := range []bool{false, true} {
		if _, err := client.CreatePolicyVersion(t.Context(), &sdkiam.CreatePolicyVersionInput{PolicyArn: aws.String(attached), PolicyDocument: aws.String(allowRead), SetAsDefault: setDefault}); err != nil {
			t.Fatal(err)
		}
	}
	assertUsage("unreferenced retained and default versions", 0)
	if _, err := client.AttachUserPolicy(t.Context(), &sdkiam.AttachUserPolicyInput{UserName: aws.String("usage-user"), PolicyArn: aws.String(attached)}); err != nil {
		t.Fatal(err)
	}
	assertUsage("first attachment", 1)
	if _, err := client.AttachGroupPolicy(t.Context(), &sdkiam.AttachGroupPolicyInput{GroupName: aws.String("usage-group"), PolicyArn: aws.String(attached)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachRolePolicy(t.Context(), &sdkiam.AttachRolePolicyInput{RoleName: aws.String("usage-role"), PolicyArn: aws.String(attached)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutUserPermissionsBoundary(t.Context(), &sdkiam.PutUserPermissionsBoundaryInput{UserName: aws.String("usage-user"), PermissionsBoundary: aws.String(attached)}); err != nil {
		t.Fatal(err)
	}
	assertUsage("same policy across identities and boundary", 1)
	if _, err := client.SetDefaultPolicyVersion(t.Context(), &sdkiam.SetDefaultPolicyVersionInput{PolicyArn: aws.String(attached), VersionId: aws.String("v1")}); err != nil {
		t.Fatal(err)
	}
	assertUsage("default version replacement", 1)
	if _, err := client.PutUserPermissionsBoundary(t.Context(), &sdkiam.PutUserPermissionsBoundaryInput{UserName: aws.String("usage-user"), PermissionsBoundary: aws.String(boundary)}); err != nil {
		t.Fatal(err)
	}
	assertUsage("separate customer boundary only", 2)
	if _, err := client.PutRolePermissionsBoundary(t.Context(), &sdkiam.PutRolePermissionsBoundaryInput{RoleName: aws.String("usage-role"), PermissionsBoundary: aws.String(awsAdministrator)}); err != nil {
		t.Fatal(err)
	}
	assertUsage("AWS boundary only", 3)
	if _, err := client.AttachUserPolicy(t.Context(), &sdkiam.AttachUserPolicyInput{UserName: aws.String("usage-user"), PolicyArn: aws.String(awsAdministrator)}); err != nil {
		t.Fatal(err)
	}
	assertUsage("same AWS policy attached", 3)
	if _, err := client.DeleteRolePermissionsBoundary(t.Context(), &sdkiam.DeleteRolePermissionsBoundaryInput{RoleName: aws.String("usage-role")}); err != nil {
		t.Fatal(err)
	}
	assertUsage("AWS attachment only", 3)
	if _, err := client.DetachUserPolicy(t.Context(), &sdkiam.DetachUserPolicyInput{UserName: aws.String("usage-user"), PolicyArn: aws.String(awsAdministrator)}); err != nil {
		t.Fatal(err)
	}
	assertUsage("last AWS reference removed", 2)
	if _, err := client.DeleteUserPermissionsBoundary(t.Context(), &sdkiam.DeleteUserPermissionsBoundaryInput{UserName: aws.String("usage-user")}); err != nil {
		t.Fatal(err)
	}
	assertUsage("last boundary reference removed", 1)
	if _, err := client.DetachUserPolicy(t.Context(), &sdkiam.DetachUserPolicyInput{UserName: aws.String("usage-user"), PolicyArn: aws.String(attached)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DetachGroupPolicy(t.Context(), &sdkiam.DetachGroupPolicyInput{GroupName: aws.String("usage-group"), PolicyArn: aws.String(attached)}); err != nil {
		t.Fatal(err)
	}
	assertUsage("role reference remains", 1)
	if _, err := client.DetachRolePolicy(t.Context(), &sdkiam.DetachRolePolicyInput{RoleName: aws.String("usage-role"), PolicyArn: aws.String(attached)}); err != nil {
		t.Fatal(err)
	}
	assertUsage("last customer reference removed", 0)
}
