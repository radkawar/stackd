package iam

import (
	"context"
	"crypto/tls"
	"errors"
	"time"
)

// ServerCertificateRecord holds deployment material. PrivateKey is never part
// of an IAM API response; repository implementations must keep it confidential.
type ServerCertificateRecord struct {
	CloudFormationOwner              string
	ID, Name, Path, ARN, Body, Chain string
	PrivateKey                       []byte
	UploadDate, Expiration           time.Time
	Tags                             []Tag
	// TaggingInvalid records AWS's observed empty-update transition: tag
	// visibility is lost and subsequent tag mutations return InvalidInput.
	TaggingInvalid bool
}

var ErrInvalidServerCertificate = errors.New("invalid server certificate")

// ServerCertificateSource supplies detached TLS material to an authorized
// deployment consumer. The ARN must identify a certificate in the given scope.
type ServerCertificateSource interface {
	ServerCertificateForTLS(context.Context, Scope, string) (tls.Certificate, error)
}
