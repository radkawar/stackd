// Package signer owns signing profiles, cryptographic authority and revocation.
package signer

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("signer resource not found")

const LambdaPlatform = "AWSLambda-SHA384-ECDSA"

type Scope struct{ Partition, AccountID, Region string }
type Authority struct {
	Scope
	Certificate, PrivateKey []byte
}
type Profile struct {
	Scope
	Name, ARN, Version, VersionARN, Status string
	Current                                bool
	ValidityValue                          int64
	ValidityType                           string
	Created, RevokedAt, EffectiveTime      time.Time
	RevocationReason, RevokedBy            string
	Certificate, PrivateKey                []byte
	Tags                                   map[string]string
	// Owner is private native authority for one CloudFormation incarnation.
	Owner string
}
type Job struct {
	Scope
	ID, ARN, ProfileName, ProfileVersion, ProfileVersionARN, Token                               string
	SourceBucket, SourceKey, SourceVersion, DestinationBucket, DestinationPrefix, DestinationKey string
	Status, StatusReason, RequestedBy                                                            string
	Created, Completed, Expires, RevokedAt                                                       time.Time
	RevocationReason, RevokedBy                                                                  string
	CertificateHashes                                                                            []string
}
type Reader interface {
	Context() context.Context
	Authority(Scope) (Authority, error)
	Authorities() ([]Authority, error)
	Profile(Scope, string, string) (Profile, error) // Empty version selects the current profile.
	Profiles(Scope) ([]Profile, error)
	Job(Scope, string) (Job, error)
	Jobs(Scope) ([]Job, error)
}
type Transaction interface {
	Reader
	PutAuthority(Authority) error
	PutProfile(Profile) error
	PutJob(Job) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

// Objects delegates to ordinary S3 commands with the current caller identity.
// S3 remains the sole authority for versioned input and signed output bytes.
type Objects interface {
	Read(context.Context, string, string, string) ([]byte, error)
	Write(context.Context, string, string, []byte) error
}
