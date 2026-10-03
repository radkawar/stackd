package secretsmanager

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

type secretAuditKey struct{}
type secretAudit struct {
	ARN string `json:"arn"`
}

// Failed key admission still identifies the allocated/resolved secret in native
// audit. The command owns that identity; recording never rereads changed state.
func noteSecretAudit(ctx context.Context, secret SecretRecord) {
	if audit, ok := ctx.Value(secretAuditKey{}).(*secretAudit); ok {
		audit.ARN = secret.ARN
	}
}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("secretsmanager")
	operation, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, Request: awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
		"SecretString": {Mode: awsapi.OmitField}, "SecretBinary": {Mode: awsapi.OmitField}, "RotationToken": {Mode: awsapi.OmitField},
	}}}
	switch action {
	case "GetSecretValue", "BatchGetSecretValue", "DescribeSecret", "GetResourcePolicy", "ListSecrets", "ListSecretVersionIds", "GetRandomPassword", "ValidateResourcePolicy":
		projection.ReadOnly = true
	case "CreateSecret", "PutSecretValue", "UpdateSecret":
		projection.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
			"Name": {Mode: awsapi.OmitField}, "VersionId": {Mode: awsapi.OmitField}, "VersionStages": {Mode: awsapi.OmitField}, "ReplicationStatus": {Mode: awsapi.OmitField},
		}}
	case "TagResource", "UntagResource":
	default:
		projection.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"DeletionDate": {TimeLayout: time.RFC3339}}}
	}
	if request, ok := in.(*api.CreateSecretInput); ok && request != nil && request.ForceOverwriteReplicaSecret == nil {
		copy := *request
		copy.ForceOverwriteReplicaSecret = new(api.BooleanType(false))
		in = &copy
	}
	call, err := projection.Call(model, operation, in, out, rejected)
	if err != nil {
		return err
	}
	if rejected != nil && (rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException") {
		call.ErrorCode = "AccessDenied"
	}
	if action == "CreateSecret" || action == "PutSecretValue" || action == "UpdateSecret" {
		if audit, ok := ctx.Value(secretAuditKey{}).(*secretAudit); ok && audit.ARN != "" {
			call.ResponseElements, err = json.Marshal(audit)
			if err != nil {
				return err
			}
		}
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	metadata := awsctx.FromContext(ctx)
	if action != "DeleteSecret" && metadata.InvokedBy != "secretsmanager.amazonaws.com" {
		var request struct {
			SecretID string `json:"secretId"`
		}
		if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
			return err
		}
		if resource, err := arn.Parse(request.SecretID); err == nil && resource.Service == "secretsmanager" {
			call.EventResources = []journal.APIEventResource{{AccountID: resource.AccountID, Type: "AWS::SecretsManager::Secret", ARN: request.SecretID}}
		}
	}
	if action == "GetSecretValue" && metadata.InvokedBy == "secretsmanager.amazonaws.com" {
		metadata.AccessKeyID = ""
		metadata.SourceIP, metadata.UserAgent = "secretsmanager.amazonaws.com", "secretsmanager.amazonaws.com"
		ctx = awsctx.WithMetadata(ctx, metadata)
	}
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}

func (s *Service) readBatchSecret(ctx context.Context, in *api.GetSecretValueInput) (*api.GetSecretValueOutput, *awswire.Error) {
	metadata := awsctx.FromContext(ctx)
	metadata.ParentEventID = apievents.EventID(ctx)
	metadata.RequestID += ":" + value(in.SecretId)
	metadata.InvokedBy = "secretsmanager.amazonaws.com"
	return runCommand(s, awsctx.WithMetadata(ctx, metadata), "GetSecretValue", in, s.getSecretValue)
}
