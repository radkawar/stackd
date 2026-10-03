package iam

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"stackd/internal/identity"
)

// SigningCertificateRecord binds public signing material to an immutable user.
type SigningCertificateRecord struct {
	ID, UserID, Body, Status string
	DER                      []byte
	UploadDate               time.Time
}

var ErrInvalidSigningCertificate = errors.New("invalid signing certificate credential")

// SigningCertificateVerifier verifies a signature and resolves the current IAM
// identity. Its consumer must then authorize the requested service operation.
type SigningCertificateVerifier interface {
	VerifySigningCertificate(context.Context, Scope, string, x509.SignatureAlgorithm, []byte, []byte) (identity.Principal, error)
}
