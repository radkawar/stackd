package iam

import (
	"context"
	"errors"
	"time"

	"stackd/internal/identity"
)

// SSHPublicKeyRecord stores canonical SSH wire material without a private key.
type SSHPublicKeyRecord struct {
	ID, UserID, Body, Fingerprint, Status string
	Wire                                  []byte
	UploadDate                            time.Time
}

var ErrInvalidSSHPublicKey = errors.New("invalid SSH public key credential")

// SSHPublicKeyVerifier verifies an SSH wire-encoded signature and resolves the
// current IAM identity. Consumers retain responsibility for action authorization.
type SSHPublicKeyVerifier interface {
	VerifySSHPublicKey(context.Context, Scope, string, []byte, []byte) (identity.Principal, error)
}
