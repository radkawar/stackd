package glue

import (
	"context"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/awswire"
)

// ConnectionSecrets reads external SECRET_ID values through Secrets Manager's
// ordinary authorization/KMS boundary under the connection consumer's identity.
type ConnectionSecrets interface {
	Read(context.Context, string) (string, string, error)
}

// ConnectionCrypto keeps explicitly encrypted connection passwords within the
// existing KMS owner. Plain passwords never enter public retained properties.
type ConnectionCrypto interface {
	Encrypt(context.Context, string, []byte, map[string]string) ([]byte, string, *awswire.Error)
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
}

type ConnectionRecord struct {
	CFNOwner       string
	Key            ResourceKey
	Connection     api.Connection
	Tags           map[string]string
	Password       string
	PasswordCipher []byte
}
