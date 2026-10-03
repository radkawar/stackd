package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/kms"
	"stackd/internal/services/stepfunctions"
)

// StepFunctionsKMSOperations preserves KMS key policies, current key state,
// authenticated encryption and auditing inside the caller's transaction.
type StepFunctionsKMSOperations interface {
	DescribeKey(context.Context, string) (*kmsapi.KeyMetadata, *awswire.Error)
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, string, *awswire.Error)
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
}

// StepFunctionsKeys distinguishes forwarded API callers from actual workflow
// execution-role sessions. Neither path substitutes a service principal at KMS.
type StepFunctionsKeys struct {
	KMS      StepFunctionsKMSOperations
	Activity IAMActivity
	Roles    ServiceRoles
}

var _ stepfunctions.EncryptionKeys = StepFunctionsKeys{}

func (k StepFunctionsKeys) ResolveKey(ctx context.Context, identifier string) (string, *awswire.Error) {
	ctx = kms.WithViaService(ctx, "states")
	if rejected := recordKMSActivity(ctx, k.Activity, "DescribeKey"); rejected != nil {
		return "", stepFunctionsKeyError(rejected, true)
	}
	metadata, rejected := k.KMS.DescribeKey(ctx, identifier)
	if rejected != nil {
		return "", stepFunctionsKeyError(rejected, true)
	}
	if metadata == nil || metadata.Arn == nil {
		return "", &awswire.Error{Code: "InternalServerError", Message: "KMS returned no key metadata.", StatusCode: 500}
	}
	if metadata.KeySpec == nil || string(*metadata.KeySpec) != "SYMMETRIC_DEFAULT" {
		return "", stepFunctionsKeyConfigurationError("kmsKeyId must use SYMMETRIC_DEFAULT key spec")
	}
	if metadata.KeyUsage == nil || string(*metadata.KeyUsage) != "ENCRYPT_DECRYPT" {
		return "", stepFunctionsKeyConfigurationError("kmsKeyId must use ENCRYPT_DECRYPT key usage")
	}
	if metadata.KeyState == nil || string(*metadata.KeyState) != "Enabled" {
		return "", stepFunctionsKeyConfigurationError("kmsKeyId is not enabled")
	}
	keyARN := string(*metadata.Arn)
	key, err := arn.Parse(keyARN)
	scope := awsctx.FromContext(ctx)
	if err != nil || key.Partition != scope.Partition || key.Region != scope.Region {
		return "", stepFunctionsKeyConfigurationError("kmsKeyId must reference a KMS key in the same Region")
	}
	// Native admission resolves IDs, aliases and alias ARNs to the key ARN.
	return keyARN, nil
}

func (k StepFunctionsKeys) GenerateDataKey(ctx context.Context, resourceARN, roleARN, keyID string) ([]byte, []byte, string, *awswire.Error) {
	ctx, encryption, rejected := k.requestContext(ctx, resourceARN, roleARN)
	if rejected != nil {
		return nil, nil, "", rejected
	}
	if rejected := recordKMSActivity(ctx, k.Activity, "GenerateDataKey"); rejected != nil {
		return nil, nil, "", stepFunctionsKeyError(rejected, false)
	}
	plain, wrapped, keyARN, rejected := k.KMS.GenerateDataKey(ctx, keyID, encryption)
	if rejected != nil {
		clear(plain)
		return nil, nil, "", stepFunctionsKeyError(rejected, false)
	}
	return plain, wrapped, keyARN, nil
}

func (k StepFunctionsKeys) Decrypt(ctx context.Context, resourceARN, roleARN string, wrapped []byte) ([]byte, string, *awswire.Error) {
	ctx, encryption, rejected := k.requestContext(ctx, resourceARN, roleARN)
	if rejected != nil {
		return nil, "", rejected
	}
	if rejected := recordKMSActivity(ctx, k.Activity, "Decrypt"); rejected != nil {
		return nil, "", stepFunctionsKeyError(rejected, false)
	}
	plain, keyARN, rejected := k.KMS.Decrypt(ctx, wrapped, encryption)
	if rejected != nil {
		clear(plain)
		return nil, "", stepFunctionsKeyError(rejected, false)
	}
	return plain, keyARN, nil
}

func (k StepFunctionsKeys) requestContext(ctx context.Context, resourceARN, roleARN string) (context.Context, map[string]string, *awswire.Error) {
	resource, err := arn.Parse(resourceARN)
	if err != nil || resource.Service != "states" {
		return nil, nil, &awswire.Error{Code: "InternalServerError", Message: "Invalid Step Functions encryption resource.", StatusCode: 500}
	}
	contextKey := "aws:states:stateMachineArn"
	if strings.HasPrefix(resource.Resource, "activity:") {
		contextKey = "aws:states:activityArn"
	}
	encryption := map[string]string{contextKey: resourceARN}
	origin := awsctx.FromContext(ctx)
	origin.Partition, origin.Region = resource.Partition, resource.Region
	ctx = awsctx.WithMetadata(ctx, origin)
	if roleARN == "" {
		return kms.WithViaService(ctx, "states"), encryption, nil
	}
	// The service supplies the workflow source separately: activity encryption
	// changes the KMS context, never the state-machine source used by role trust.
	source := origin.ServicePrincipal
	machine, err := arn.Parse(source.SourceARN)
	if source.Name != "states.amazonaws.com" || err != nil || machine.Service != "states" || !strings.HasPrefix(machine.Resource, "stateMachine:") {
		return nil, nil, &awswire.Error{Code: "InternalServerError", Message: "Workflow encryption requires a state-machine execution source.", StatusCode: 500}
	}
	credential, rejected := k.Roles.assume(ctx, source, roleARN, identity.RoleSessionSpec{SessionName: "StepFunctions_KMS"}, "")
	if rejected != nil {
		return nil, nil, stepFunctionsKeyError(rejected, false)
	}
	ctx, rejected = serviceRoleRequestContext(ctx, credential, resource.Region, source.Name)
	if rejected != nil {
		return nil, nil, stepFunctionsKeyError(rejected, false)
	}
	metadata := awsctx.FromContext(ctx)
	metadata.TraceHeader = origin.TraceHeader
	ctx = awsctx.WithMetadata(ctx, metadata)
	// Execution roles call KMS directly; kms:ViaService applies only to callers.
	return ctx, encryption, nil
}

func stepFunctionsKeyConfigurationError(message string) *awswire.Error {
	return &awswire.Error{Code: "InvalidEncryptionConfiguration", Message: message, StatusCode: 400}
}

func stepFunctionsKeyError(rejected *awswire.Error, admission bool) *awswire.Error {
	if rejected == nil {
		return nil
	}
	code, status := "InternalServerError", 500
	switch rejected.Code {
	case "AccessDenied", "AccessDeniedException":
		code, status = "KmsAccessDeniedException", 400
	case "ThrottlingException", "LimitExceededException":
		code, status = "KmsThrottlingException", 400
	case "DisabledException", "KMSInvalidStateException", "NotFoundException", "InvalidKeyUsageException", "IncorrectKeyException", "InvalidCiphertextException":
		code, status = "KmsInvalidStateException", 400
		if admission {
			code = "InvalidEncryptionConfiguration"
		}
	case "ValidationException":
		code, status = "ValidationException", 400
		if admission {
			code = "InvalidEncryptionConfiguration"
		}
	}
	result := &awswire.Error{Code: code, Message: rejected.Message, StatusCode: status, Cause: rejected}
	if code == "KmsInvalidStateException" {
		var state *kms.KeyStateError
		if errors.As(rejected, &state) {
			value := strings.ToUpper(state.State)
			switch state.State {
			case "PendingDeletion":
				value = "PENDING_DELETION"
			case "PendingImport":
				value = "PENDING_IMPORT"
			case "PendingReplicaDeletion":
				value = "PENDING_REPLICA_DELETION"
			}
			encoded, _ := json.Marshal(value)
			result.Details = map[string]json.RawMessage{"kmsKeyState": encoded}
		}
	}
	return result
}
