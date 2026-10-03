package iam_test

import (
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"stackd/internal/services/iam"
)

func TestAccountPropertiesAtomicStateAndRetainedBackend(t *testing.T) {
	repository := &failingIAMRepository{Repository: iam.NewMemoryRepository(nil)}
	service := iam.NewWithRepository(nil, repository)
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	input := &sdkiam.PutAccountPropertiesInput{Properties: map[string]string{"RoleManager/Enabled": "true"}}
	roleName := aws.String("AWSServiceRoleForIAMRoleManager")
	for _, cancel := range []bool{false, true} {
		repository.fail, repository.cancel = !cancel, cancel
		_, err := client.PutAccountProperties(t.Context(), input)
		requireCode(t, err, "ServiceFailure")
		repository.fail, repository.cancel = false, false
		state, err := client.GetAccountProperties(t.Context(), &sdkiam.GetAccountPropertiesInput{})
		if err != nil || state.Properties["RoleManager/Enabled"] != "false" {
			t.Fatalf("failed commit enabled feature: %+v, %v", state, err)
		}
		_, err = client.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: roleName})
		requireCode(t, err, "NoSuchEntity")
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Go(func() { _, err := client.PutAccountProperties(t.Context(), input); results <- err })
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	first, err := client.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: roleName})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	next := iam.NewWithRepository(nil, repository)
	t.Cleanup(func() { _ = next.Close() })
	reopened := clientFor(t, next, "123456789012", "eu-west-1")
	state, err := reopened.GetAccountProperties(t.Context(), &sdkiam.GetAccountPropertiesInput{})
	if err != nil || state.Properties["RoleManager/Enabled"] != "true" {
		t.Fatalf("retained state across regions: %+v, %v", state, err)
	}
	if _, err := reopened.PutAccountProperties(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	role, err := reopened.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: roleName})
	if err != nil || aws.ToString(role.Role.RoleId) != aws.ToString(first.Role.RoleId) {
		t.Fatalf("replaced retained role: %+v, %v", role, err)
	}
	policy, err := reopened.GetPolicy(t.Context(), &sdkiam.GetPolicyInput{PolicyArn: aws.String("arn:aws:iam::aws:policy/aws-service-role/AWSIAMRoleManagerServiceRolePolicy")})
	if err != nil || aws.ToInt32(policy.Policy.AttachmentCount) != 1 {
		t.Fatalf("attachment count after competing enables: %+v, %v", policy, err)
	}
	china := clientForPartition(t, next, "123456789012", "cn-north-1", "aws-cn")
	state, err = china.GetAccountProperties(t.Context(), &sdkiam.GetAccountPropertiesInput{})
	if err != nil || state.Properties["RoleManager/Enabled"] != "false" {
		t.Fatalf("partition overlap: %+v, %v", state, err)
	}
	_, err = china.PutAccountProperties(t.Context(), input)
	requireCode(t, err, "NotImplemented")
}

func TestAccountPropertiesPreserveExplicitAndOrdinaryRoles(t *testing.T) {
	for _, owned := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary collision", true: "explicit service role"}[owned], func(t *testing.T) {
			service := iam.New()
			t.Cleanup(func() { _ = service.Close() })
			client := clientFor(t, service, "123456789012", "us-east-1")
			name := aws.String("AWSServiceRoleForIAMRoleManager")
			if owned {
				_, err := client.CreateServiceLinkedRole(t.Context(), &sdkiam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("role-manager.iam.amazonaws.com"), Description: aws.String("Operator description")})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				_, err := client.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: name, AssumeRolePolicyDocument: aws.String(trustEC2)})
				if err != nil {
					t.Fatal(err)
				}
			}
			before, err := client.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: name})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.PutAccountProperties(t.Context(), &sdkiam.PutAccountPropertiesInput{Properties: map[string]string{"RoleManager/Enabled": "true"}})
			if owned {
				if err != nil {
					t.Fatal(err)
				}
				_, err = client.PutAccountProperties(t.Context(), &sdkiam.PutAccountPropertiesInput{Properties: map[string]string{"RoleManager/Enabled": "FALSE"}})
				requireCode(t, err, "InvalidInput")
			} else {
				requireCode(t, err, "InvalidInput")
			}
			state, err := client.GetAccountProperties(t.Context(), &sdkiam.GetAccountPropertiesInput{})
			if err != nil || (state.Properties["RoleManager/Enabled"] == "true") != owned {
				t.Fatalf("state = %+v, %v", state, err)
			}
			after, err := client.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: name})
			if err != nil || *before.Role.RoleId != *after.Role.RoleId || aws.ToString(before.Role.Description) != aws.ToString(after.Role.Description) || *before.Role.AssumeRolePolicyDocument != *after.Role.AssumeRolePolicyDocument {
				t.Fatalf("existing role changed: %+v, %v", after, err)
			}
		})
	}
}

// Exercise the modeled account-feature dependency through the real worker.
// AWS's Role Manager deletion checker currently fails even after disablement;
// this test is not a differential claim for its successful deletion behavior.
func TestAccountPropertiesServiceRoleDependency(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	name := aws.String("AWSServiceRoleForIAMRoleManager")
	if _, err := client.PutAccountProperties(t.Context(), &sdkiam.PutAccountPropertiesInput{Properties: map[string]string{"RoleManager/Enabled": "true"}}); err != nil {
		t.Fatal(err)
	}
	job, err := client.DeleteServiceLinkedRole(t.Context(), &sdkiam.DeleteServiceLinkedRoleInput{RoleName: name})
	if err != nil {
		t.Fatal(err)
	}
	waitLinkedStatus(t, client, *job.DeletionTaskId, types.DeletionTaskStatusTypeFailed)
	role, err := client.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: name})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutAccountProperties(t.Context(), &sdkiam.PutAccountPropertiesInput{Properties: map[string]string{"RoleManager/Enabled": "false"}}); err != nil {
		t.Fatal(err)
	}
	job, err = client.DeleteServiceLinkedRole(t.Context(), &sdkiam.DeleteServiceLinkedRoleInput{RoleName: name})
	if err != nil {
		t.Fatal(err)
	}
	waitLinkedStatus(t, client, *job.DeletionTaskId, types.DeletionTaskStatusTypeSucceeded)
	_, err = client.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: name})
	requireCode(t, err, "NoSuchEntity")
	if _, err := client.PutAccountProperties(t.Context(), &sdkiam.PutAccountPropertiesInput{Properties: map[string]string{"RoleManager/Enabled": "true"}}); err != nil {
		t.Fatal(err)
	}
	recreated, err := client.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: name})
	if err != nil || *recreated.Role.RoleId == *role.Role.RoleId {
		t.Fatalf("recreated role identity: %+v, %v", recreated, err)
	}
}
