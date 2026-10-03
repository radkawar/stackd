package lambda

import (
	"strconv"
	"time"
)

// LayerKey identifies a catalog whose allocation counter outlives its versions.
type LayerKey struct {
	Scope
	Name string
}

func (k LayerKey) ARN() string {
	return "arn:" + k.Partition + ":lambda:" + k.Region + ":" + k.Account + ":layer:" + k.Name
}

type LayerVersionKey struct {
	LayerKey
	Version uint64
}

func (k LayerVersionKey) ARN() string {
	return k.LayerKey.ARN() + ":" + strconv.FormatUint(k.Version, 10)
}

// LayerAttachment retains code identity independently of the deletable catalog.
// The owner scope, not the consuming function's scope, identifies its archive.
type LayerAttachment struct {
	Key                                     LayerVersionKey
	CodeSHA256                              string
	CodeSize                                int64
	SigningProfileVersionARN, SigningJobARN string
}

// LayerVersionOwner identifies a trusted service's immutable publication receipt.
// The zero value denotes an unowned legacy or natively published layer version.
type LayerVersionOwner struct{ StackID, LogicalID, Token string }

// LayerPermissionKey binds a private receipt to one statement in one version.
type LayerPermissionKey struct {
	LayerVersionKey
	StatementID string
}

// LayerPermissionOwner is a private deployment receipt, never a policy field.
type LayerPermissionOwner struct{ StackID, LogicalID, Token string }

type LayerVersionRecord struct {
	Key                                         LayerVersionKey
	Owner                                       LayerVersionOwner
	CodeSHA256                                  string
	CodeSize                                    int64
	Reference                                   *S3ObjectReference
	Description, LicenseInfo                    string
	Created                                     time.Time
	CompatibleRuntimes, CompatibleArchitectures []string
	SigningProfileVersionARN, SigningJobARN     string
}
type LayerPolicy struct {
	Key                LayerVersionKey
	Document, Revision string
	PrincipalIDs       map[string]string
}
type LayerReader interface {
	LayerVersion(LayerVersionKey) (LayerVersionRecord, error)
	// OwnedLayerVersion recovers an exact scoped owner; empty identities never match.
	OwnedLayerVersion(LayerKey, LayerVersionOwner) (LayerVersionRecord, error)
	LayerVersions(LayerKey) ([]LayerVersionRecord, error)
	// Layers returns the latest extant version of each name, sorted by name.
	Layers(Scope) ([]LayerVersionRecord, error)
	LayerPolicy(LayerVersionKey) (LayerPolicy, error)
	LayerPermissionOwner(LayerPermissionKey) (LayerPermissionOwner, error)
}
type LayerWriter interface {
	AllocateLayerVersion(LayerKey) (uint64, error)
	PutLayerVersion(LayerVersionRecord) error
	DeleteLayerVersion(LayerVersionKey) error
	PutLayerPolicy(LayerPolicy) error
	DeleteLayerPolicy(LayerVersionKey) error
	PutLayerPermissionOwner(LayerPermissionKey, LayerPermissionOwner) error
	DeleteLayerPermissionOwner(LayerPermissionKey) error
}
