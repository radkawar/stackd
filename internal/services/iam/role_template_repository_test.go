package iam_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/services/iam"
)

func TestRoleTemplateAtomicCreationAndRetainedSource(t *testing.T) {
	repository := &failingIAMRepository{Repository: iam.NewMemoryRepository(nil)}
	service := iam.NewWithRepository(nil, repository)
	client := clientFor(t, service, "123456789012", "us-east-1")
	input := &sdkiam.AcquireRoleInput{TemplateArn: aws.String("arn:aws:iam::aws:role-template/iam.amazonaws.com/PowerUserRoleTemplate:1"),
		ReplacementValues: map[string]types.ReplacementValueEntry{"RoleName": {Values: []string{"atomic"}}, "AWSServiceName": {Values: []string{"lambda.amazonaws.com"}}}}
	for _, cancel := range []bool{false, true} {
		repository.fail, repository.cancel = !cancel, cancel
		_, err := client.AcquireRole(t.Context(), input)
		requireCode(t, err, "ServiceFailure")
		repository.fail, repository.cancel = false, false
		_, err = client.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: aws.String("atomic")})
		requireCode(t, err, "NoSuchEntity")
		policy, err := client.GetPolicy(t.Context(), &sdkiam.GetPolicyInput{PolicyArn: aws.String("arn:aws:iam::aws:policy/PowerUserAccess")})
		if err != nil || aws.ToInt32(policy.Policy.AttachmentCount) != 0 {
			t.Fatalf("failed transaction published attachment: %+v, %v", policy, err)
		}
	}
	created, err := client.AcquireRole(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	if err := repository.View(t.Context(), func(tx iam.ReadTx) error {
		role, err := tx.Role(scope, "atomic")
		if err != nil {
			return err
		}
		role.SourceRoleTemplate.Parameters["AWSServiceName"][0] = "ec2.amazonaws.com"
		delete(role.SourceRoleTemplate.Parameters, "RoleName")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := clientFor(t, iam.NewWithRepository(nil, repository), scope.AccountID, "eu-west-1")
	result, err := reopened.AcquireRole(context.Background(), input)
	if err != nil || *created.Role.RoleId != *result.Role.RoleId {
		t.Fatalf("retained template source/reuse: %+v, %v", result, err)
	}
	// Commercial definitions must not make a role in another partition.
	china := clientForPartition(t, iam.NewWithRepository(nil, repository), scope.AccountID, "cn-north-1", "aws-cn")
	_, err = china.AcquireRole(t.Context(), input)
	requireCode(t, err, "AccessDenied")
	_, err = china.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: aws.String("atomic")})
	requireCode(t, err, "NoSuchEntity")
}
