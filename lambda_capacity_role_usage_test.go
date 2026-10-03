package stackd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
	"stackd/internal/services/lambda"
	"stackd/storage/sqlite"
	sqliam "stackd/storage/sqlite/iam"
	sqllambda "stackd/storage/sqlite/lambda"
)

func TestLambdaCapacityRoleDeletionUsesSharedWritableAuthority(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "capacity-role.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	repository := sqllambda.New(db)
	functions := lambda.New(lambda.Config{Repository: repository})
	roles := iam.NewWithRepository(nil, sqliam.New(db))
	t.Cleanup(func() {
		if err := roles.Close(); err != nil {
			t.Error(err)
		}
		if err := functions.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := registerLambdaCapacityRoleUsage(roles, functions); err != nil {
		t.Fatal(err)
	}
	scope := lambda.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}
	key := lambda.CapacityProviderKey{Scope: scope, Name: "retained-provider"}
	if err := repository.Update(t.Context(), func(tx lambda.Transaction) error {
		return tx.PutCapacityProvider(lambda.CapacityProviderRecord{Key: key, Generation: "retained-generation", State: "Active", Architecture: "x86_64", ScalingMode: "Manual", MaxVCPUs: 6, Modified: time.Now().UTC()})
	}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata := awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, AccessKeyID: "test", RequestID: "lambda-capacity-role-usage", PrincipalARN: "arn:aws:iam::" + scope.Account + ":root", PrincipalID: scope.Account}
		roles.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), metadata)))
	}))
	t.Cleanup(server.Close)
	client := sdkiam.New(sdkiam.Options{Region: scope.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), Retryer: aws.NopRetryer{}})
	created, err := client.CreateServiceLinkedRole(t.Context(), &sdkiam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("lambda.amazonaws.com")})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus := func(id string, want types.DeletionTaskStatusType) *sdkiam.GetServiceLinkedRoleDeletionStatusOutput {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			status, err := client.GetServiceLinkedRoleDeletionStatus(ctx, &sdkiam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: aws.String(id)})
			if err != nil {
				t.Fatal(err)
			}
			if status.Status == want {
				return status
			}
			if status.Status == types.DeletionTaskStatusTypeFailed || status.Status == types.DeletionTaskStatusTypeSucceeded {
				t.Fatalf("linked-role terminal state=%s, want %s: %+v", status.Status, want, status.Reason)
			}
			select {
			case <-ctx.Done():
				t.Fatalf("linked-role task retained %s instead of %s", status.Status, want)
			case <-tick.C:
			}
		}
	}
	first, err := client.DeleteServiceLinkedRole(t.Context(), &sdkiam.DeleteServiceLinkedRoleInput{RoleName: created.Role.RoleName})
	if err != nil {
		t.Fatal(err)
	}
	failed := waitStatus(aws.ToString(first.DeletionTaskId), types.DeletionTaskStatusTypeFailed)
	if failed.Reason == nil || len(failed.Reason.RoleUsageList) != 1 {
		t.Fatalf("provider dependency missing: %+v", failed.Reason)
	}
	usage := failed.Reason.RoleUsageList[0]
	if aws.ToString(usage.Region) != scope.Region || !slices.Equal(usage.Resources, []string{key.ARN()}) {
		t.Fatalf("wrong provider dependency: %+v", usage)
	}
	retained, err := client.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: created.Role.RoleName})
	if err != nil || aws.ToString(retained.Role.RoleId) != aws.ToString(created.Role.RoleId) {
		t.Fatalf("failed deletion changed linked role: %+v %v", retained, err)
	}
	if err := repository.Update(t.Context(), func(tx lambda.Transaction) error { return tx.DeleteCapacityProvider(key) }); err != nil {
		t.Fatal(err)
	}
	second, err := client.DeleteServiceLinkedRole(t.Context(), &sdkiam.DeleteServiceLinkedRoleInput{RoleName: created.Role.RoleName})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(aws.ToString(second.DeletionTaskId), types.DeletionTaskStatusTypeSucceeded)
	_, err = client.GetRole(t.Context(), &sdkiam.GetRoleInput{RoleName: created.Role.RoleName})
	var missing smithy.APIError
	if !errors.As(err, &missing) || missing.ErrorCode() != "NoSuchEntity" {
		t.Fatalf("completed deletion retained linked role: %v", err)
	}
}
