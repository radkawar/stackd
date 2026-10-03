package integrations

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/internal/awswire"
	"stackd/internal/services/kms"
	scheduler "stackd/internal/services/scheduler"
)

// SchedulerKeys encrypts only the customer payload with the CMK. Admission and
// reads preserve the caller; invocation decrypts as the current execution role.
type SchedulerKeys struct {
	KMS      StepFunctionsKMSOperations
	Activity IAMActivity
	Roles    ServiceRoles
}

func (k SchedulerKeys) Seal(ctx context.Context, key scheduler.ScheduleKey, keyID string, plain []byte) ([]byte, []byte, string, *awswire.Error) {
	if k.KMS == nil {
		return nil, nil, "", schedulerUnsupported("Scheduler KMS authority is not configured.")
	}
	ctx = kms.WithViaService(ctx, "scheduler")
	if rejected := recordKMSActivity(ctx, k.Activity, "DescribeKey"); rejected != nil {
		return nil, nil, "", schedulerKeyError(rejected)
	}
	meta, rejected := k.KMS.DescribeKey(ctx, keyID)
	if rejected != nil {
		return nil, nil, "", schedulerKeyError(rejected)
	}
	if meta == nil || meta.Arn == nil || meta.KeySpec == nil || string(*meta.KeySpec) != "SYMMETRIC_DEFAULT" || meta.KeyUsage == nil || string(*meta.KeyUsage) != "ENCRYPT_DECRYPT" {
		return nil, nil, "", schedulerInvalid("Scheduler requires a symmetric ENCRYPT_DECRYPT KMS key.")
	}
	resolved := string(*meta.Arn)
	a, err := arn.Parse(resolved)
	if err != nil || a.Region != key.Group.Region || a.Partition != key.Group.Partition {
		return nil, nil, "", schedulerInvalid("KMS key must be in the same Region and partition.")
	}
	if rejected = recordKMSActivity(ctx, k.Activity, "GenerateDataKey"); rejected != nil {
		return nil, nil, "", schedulerKeyError(rejected)
	}
	ec := map[string]string{"aws:scheduler:schedule:arn": key.ARN()}
	data, wrapped, resolved, rejected := k.KMS.GenerateDataKey(ctx, resolved, ec)
	if rejected != nil {
		return nil, nil, "", schedulerKeyError(rejected)
	}
	defer clear(data)
	block, err := aes.NewCipher(data)
	if err != nil {
		return nil, nil, "", schedulerKeyFailure()
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, "", schedulerKeyFailure()
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, "", schedulerKeyFailure()
	}
	encrypted := gcm.Seal(nonce, nonce, plain, []byte(key.ARN()))
	// Admission must also hold Decrypt, not only permission to mint data keys.
	if rejected = recordKMSActivity(ctx, k.Activity, "Decrypt"); rejected != nil {
		return nil, nil, "", schedulerKeyError(rejected)
	}
	check, _, rejected := k.KMS.Decrypt(ctx, wrapped, ec)
	clear(check)
	if rejected != nil {
		return nil, nil, "", schedulerKeyError(rejected)
	}
	return encrypted, wrapped, resolved, nil
}

func (k SchedulerKeys) Open(ctx context.Context, key scheduler.ScheduleKey, roleARN string, encrypted, wrapped []byte) ([]byte, *awswire.Error) {
	if k.KMS == nil {
		return nil, schedulerUnsupported("Scheduler KMS authority is not configured.")
	}
	if roleARN != "" {
		var rejected *awswire.Error
		ctx, rejected = (SchedulerTargets{Roles: k.Roles}).executionContext(ctx, key, roleARN)
		if rejected != nil {
			return nil, schedulerKeyError(rejected)
		}
	} else {
		ctx = kms.WithViaService(ctx, "scheduler")
	}
	if rejected := recordKMSActivity(ctx, k.Activity, "Decrypt"); rejected != nil {
		return nil, schedulerKeyError(rejected)
	}
	data, _, rejected := k.KMS.Decrypt(ctx, wrapped, map[string]string{"aws:scheduler:schedule:arn": key.ARN()})
	if rejected != nil {
		return nil, schedulerKeyError(rejected)
	}
	defer clear(data)
	block, err := aes.NewCipher(data)
	if err != nil {
		return nil, schedulerKeyFailure()
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(encrypted) < gcm.NonceSize() {
		return nil, schedulerKeyFailure()
	}
	plain, err := gcm.Open(nil, encrypted[:gcm.NonceSize()], encrypted[gcm.NonceSize():], []byte(key.ARN()))
	if err != nil {
		return nil, schedulerKeyFailure()
	}
	return plain, nil
}

func schedulerKeyFailure() *awswire.Error {
	return &awswire.Error{
		Code:       "InternalServerException",
		Message:    "Unable to decrypt Scheduler payload.",
		StatusCode: 500,
	}
}

func schedulerKeyError(e *awswire.Error) *awswire.Error {
	if e == nil {
		return nil
	}
	code, status := "ValidationException", 400
	if e.Code == "AccessDenied" || e.Code == "AccessDeniedException" {
		code, status = "AccessDeniedException", 403
	} else if e.StatusCode >= 500 {
		code, status = "InternalServerException", 500
	}
	return &awswire.Error{
		Code:       code,
		Message:    e.Message,
		StatusCode: status,
		Cause:      e,
	}
}
