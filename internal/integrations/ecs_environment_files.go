package integrations

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
	"stackd/internal/services/ecs"
	"stackd/internal/services/s3"
)

type ECSEnvironmentObjects interface {
	GetObject(context.Context, *api.GetObjectInput) (*s3.ObjectResponse[api.GetObjectOutput], *awswire.Error)
}

// ECSEnvironmentFiles uses the S3 owner, including its current S3/KMS policy
// checks. Neither object bytes nor credentials are retained in ECS state.
type ECSEnvironmentFiles struct{ S3 ECSEnvironmentObjects }

var _ ecs.TaskEnvironmentFiles = ECSEnvironmentFiles{}

func (a ECSEnvironmentFiles) Read(ctx context.Context, key ecs.TaskKey, reference string, credentials ecs.TaskCredentialSource) ([]byte, error) {
	if credentials == nil || a.S3 == nil {
		return nil, fmt.Errorf("S3 environment files require an object adapter and execution-role credentials")
	}
	resource, err := arn.Parse(reference)
	bucket, object, found := strings.Cut(resource.Resource, "/")
	if err != nil || resource.Service != "s3" || resource.Region != "" || resource.AccountID != "" || bucket == "" || !found || !strings.HasSuffix(object, ".env") {
		return nil, fmt.Errorf("invalid S3 environment file object ARN")
	}
	credential, rejected := credentials(ctx)
	if rejected != nil {
		return nil, rejected
	}
	if credential.AccountID != key.AccountID {
		return nil, fmt.Errorf("execution-role credential account differs from task %s", key.ARN())
	}
	command, rejected := serviceRoleRequestContext(ctx, credential, key.Region, "ecs-tasks.amazonaws.com")
	if rejected != nil {
		return nil, rejected
	}
	out, rejected := a.S3.GetObject(command, &api.GetObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(object))})
	if rejected != nil {
		return nil, rejected
	}
	return out.Output.Body, nil
}
