package stackd_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"stackd"
)

func TestEKSNodegroupServiceRoleDeletion(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "111111111111"})
			identity := clients.iam("test", "test", "")
			created, err := identity.CreateServiceLinkedRole(t.Context(), &iam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("eks-nodegroup.amazonaws.com")})
			if err != nil {
				t.Fatal(err)
			}
			deletion, err := identity.DeleteServiceLinkedRole(t.Context(), &iam.DeleteServiceLinkedRoleInput{RoleName: created.Role.RoleName})
			if err != nil {
				t.Fatal(err)
			}
			status := waitOrganizationRoleDeletion(t, identity, deletion.DeletionTaskId)
			if status.Status != types.DeletionTaskStatusTypeSucceeded {
				t.Fatalf("unused nodegroup role deletion = %+v", status)
			}
			identity = reopen().iam("test", "test", "")
			_, err = identity.GetRole(t.Context(), &iam.GetRoleInput{RoleName: created.Role.RoleName})
			assertAPIError(t, err, "NoSuchEntity")
			status, err = identity.GetServiceLinkedRoleDeletionStatus(t.Context(), &iam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: deletion.DeletionTaskId})
			if err != nil || status.Status != types.DeletionTaskStatusTypeSucceeded {
				t.Fatalf("reopened deletion = %+v, %v", status, err)
			}
		})
	}
}
