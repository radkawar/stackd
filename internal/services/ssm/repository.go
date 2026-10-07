// Package ssm owns Parameter Store metadata, immutable versions and policy deadlines.
package ssm

import (
	"context"
	"errors"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"time"
)

var ErrNotFound = errors.New("parameter not found")

type Scope struct{ Partition, AccountID, Region string }
type ParameterKey struct {
	Scope
	Name string
}
type VersionKey struct {
	Parameter ParameterKey
	Version   int64
}

// ParameterRecord contains mutable metadata, never a copy of the current value.
type ParameterRecord struct {
	Key                                                    ParameterKey
	ARN, Type, Tier, DataType, Description, AllowedPattern string
	// Incarnation identifies creation, not a mutable parameter version.
	Incarnation string
	// CloudFormationOwner is the private claim of the AWS::SSM::Parameter
	// incarnation that created this parameter. It is fixed at creation, cannot
	// be set through tags or wire input, and never reaches an AWS response.
	CloudFormationOwner string
	CurrentVersion      int64
	Tags                map[string]string
	Policies            []ParameterPolicy
	ResourcePolicies    []ResourcePolicy
}
type ResourcePolicy struct {
	ID, Hash string
	Policy   authorization.BoundPolicy
	// CloudFormationOwner is the private stack-resource incarnation claim of a
	// policy created through AWS::SSM::ResourcePolicy. It never reaches an
	// AWS response and is empty for policies created by the public API.
	CloudFormationOwner string
}

// ParameterPolicy records native policy attributes and its retained delivery edge.
type ParameterPolicy struct {
	Type, Version string
	Attributes    map[string]string
	Due           time.Time
	Fired         bool
}

// VersionRecord owns one immutable value and its independently mutable labels.
// SecureString stores only ciphertext; WrappedKey is present for advanced envelopes.
type VersionRecord struct {
	Key                                                                            VersionKey
	Type, Tier, DataType, Description, AllowedPattern, KeyID, KeyARN, ModifiedUser string
	Value, WrappedKey                                                              []byte
	Modified                                                                       time.Time
	Labels                                                                         []string
	Policies                                                                       []ParameterPolicy
}
type SettingRecord struct {
	Scope                   Scope
	ID, Value, ModifiedUser string
	Modified                time.Time
}

// ValidationJob retains asynchronous aws:ec2:image validation intent and caller authority.
type ValidationJob struct {
	Key    VersionKey
	Due    time.Time
	Caller awsctx.Metadata
}
type Reader interface {
	Context() context.Context
	Parameter(ParameterKey) (ParameterRecord, error)
	Parameters(Scope) ([]ParameterRecord, error)
	Version(VersionKey) (VersionRecord, error)
	Versions(ParameterKey) ([]VersionRecord, error)
	Settings(Scope) ([]SettingRecord, error)
	NextPolicy() (ParameterRecord, error)
	ValidationJob(VersionKey) (ValidationJob, error)
	NextValidationJob() (ValidationJob, error)
}
type Transaction interface {
	Reader
	PutParameter(ParameterRecord) error
	DeleteParameter(ParameterKey) error
	PutVersion(VersionRecord) error
	DeleteVersion(VersionKey) error
	PutSetting(SettingRecord) error
	PutValidationJob(ValidationJob) error
	DeleteValidationJob(VersionKey) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
