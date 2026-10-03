package integrations

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/awswire"
	"stackd/internal/services/kms"
	"stackd/internal/services/pipes"
)

// PipesKeys uses the execution role required by the Pipes KMS key contract.
// SourceARN and regional via-service context remain present on every operation.
type PipesKeys struct {
	Roles ServiceRoles
	KMS   LambdaFilterKMSOperations
}

func (a *PipesKeys) Generate(ctx context.Context, p pipes.PipeRecord, identifier string) ([]byte, []byte, string, *awswire.Error) {
	if a.KMS == nil {
		return nil, nil, "", pipesDependency("KMS")
	}
	target := PipesTargets{Roles: a.Roles}
	ctx, rejected := target.context(ctx, p, p.Key.ARN())
	if rejected != nil {
		return nil, nil, "", rejected
	}
	ctx = kms.WithViaService(ctx, "pipes")
	metadata, rejected := a.KMS.DescribeKey(ctx, identifier)
	if rejected != nil {
		return nil, nil, "", rejected
	}
	keyARN := pipesValue(metadata.Arn)
	parsed, e := arn.Parse(keyARN)
	if e != nil || parsed.Region != p.Key.Region || parsed.Partition != p.Key.Partition {
		return nil, nil, "", pipesInvalid("KMS key must be in the pipe region and partition.")
	}
	plain, wrapped, resolved, rejected := a.KMS.GenerateDataKey(ctx, keyARN, pipesEncryptionContext(p))
	return plain, wrapped, resolved, rejected
}
func (a *PipesKeys) Decrypt(ctx context.Context, p pipes.PipeRecord, wrapped []byte) ([]byte, *awswire.Error) {
	if a.KMS == nil {
		return nil, pipesDependency("KMS")
	}
	target := PipesTargets{Roles: a.Roles}
	ctx, rejected := target.context(ctx, p, p.Key.ARN())
	if rejected != nil {
		return nil, rejected
	}
	plain, _, rejected := a.KMS.Decrypt(kms.WithViaService(ctx, "pipes"), wrapped, pipesEncryptionContext(p))
	return plain, rejected
}
func pipesEncryptionContext(p pipes.PipeRecord) map[string]string {
	return map[string]string{"aws:pipes:arn": p.Key.ARN()}
}
