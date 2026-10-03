// Package acm owns locally trusted certificates and public DNS validation.
package acm

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("ACM certificate not found")

type Scope struct{ Partition, AccountID, Region string }

// CertificateRecord retains identity independently of renewable key material.
type CertificateRecord struct {
	Scope
	ARN, ID, Domain, Status, Type, KeyAlgorithm, Transparency, ExportOption                       string
	Created, Issued, Imported, NotBefore, NotAfter, ValidationDeadline, NextCheck, RenewalUpdated time.Time
	Version, MaterialVersion                                                                      uint64
	RenewalStatus                                                                                 string
	Exported                                                                                      bool
	CertificatePEM, ChainPEM, PrivateKeyPEM                                                       []byte
	Validations                                                                                   []Validation
	Tags                                                                                          map[string]string
}

// CertificateState allows TLS consumers to check current identity/time without copying keys on every handshake.
type CertificateState struct {
	Scope
	ID, Status          string
	NotBefore, NotAfter time.Time
	MaterialVersion     uint64
}
type Validation struct{ Domain, Name, Value, Status string }

// ValidationToken is account/domain scoped, deliberately not regional or certificate scoped.
type ValidationToken struct{ Partition, AccountID, Domain, Name, Value string }
type Authority struct{ CertificatePEM, PrivateKeyPEM []byte }
type Receipt struct {
	Scope
	Token, ARN string
	Expires    time.Time
}
type Reader interface {
	Context() context.Context
	Certificate(string) (CertificateRecord, error)
	CertificateState(string) (CertificateState, error)
	Certificates() ([]CertificateRecord, error)
	Token(string, string, string) (ValidationToken, error)
	Authority() (Authority, error)
	Receipt(Scope, string) (Receipt, error)
}
type Transaction interface {
	Reader
	PutCertificate(CertificateRecord) error
	DeleteCertificate(string) error
	PutToken(ValidationToken) error
	PutAuthority(Authority) error
	PutReceipt(Receipt) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
