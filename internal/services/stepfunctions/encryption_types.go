package stepfunctions

import (
	"context"

	"stackd/internal/awswire"
)

// EncryptionConfig is the admitted encryption configuration of a state machine
// revision or immutable activity. Existing executions retain their revision.
type EncryptionConfig struct {
	EncryptionType      string
	KMSKeyARN           string
	DataKeyReuseSeconds int64
}

// EncryptedPayload retains a KMS-wrapped data key and authenticated ciphertext.
// Plaintext keys never enter the resource repository. Resource metadata remains
// independently readable when a caller requests metadata only.
type EncryptedPayload struct {
	DataKey []byte
	Content []byte
}

// EncryptionKeys preserves the distinct native KMS authorities. An empty role
// forwards the API caller through states; a nonempty role uses an actual states
// execution-role session without kms:ViaService. The resource ARN determines
// the state-machine or activity encryption context.
type EncryptionKeys interface {
	ResolveKey(context.Context, string) (string, *awswire.Error)
	GenerateDataKey(ctx context.Context, resourceARN, roleARN, keyID string) (plain, wrapped []byte, keyARN string, rejected *awswire.Error)
	Decrypt(ctx context.Context, resourceARN, roleARN string, wrapped []byte) (plain []byte, keyARN string, rejected *awswire.Error)
}
