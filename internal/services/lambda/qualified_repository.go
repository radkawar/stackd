package lambda

import "strconv"

// FunctionReference preserves the resource requested by a caller. An alias is
// an authorization identity, not the immutable deployment chosen to execute it.
type FunctionReference struct {
	FunctionKey
	Qualifier string
}

func (r FunctionReference) ARN() string {
	arn := r.FunctionKey.ARN()
	if r.Qualifier != "" {
		arn += ":" + r.Qualifier
	}
	return arn
}

// FunctionVersionKey identifies a resolved deployment. Version zero is $LATEST;
// reservations and account concurrency continue to use the base FunctionKey.
type FunctionVersionKey struct {
	FunctionKey
	Version uint64
}

func (k FunctionVersionKey) ARN() string {
	arn := k.FunctionKey.ARN()
	if k.Version != 0 {
		arn += ":" + versionName(k.Version)
	}
	return arn
}

func versionName(version uint64) string {
	if version == LatestPublishedVersion {
		return "$LATEST.PUBLISHED"
	}
	if version == 0 {
		return "$LATEST"
	}
	return strconv.FormatUint(version, 10)
}

// VersionOwner identifies a trusted publication request independently of the
// immutable version number. Each publication has at most one trusted owner.
type VersionOwner struct{ StackID, LogicalID, Token string }

// AliasOwner identifies a trusted service's alias independently of its name.
// The zero value denotes an unowned legacy or natively created alias.
type AliasOwner struct{ StackID, LogicalID, Token string }

// AliasRecord owns routing separately from published code and configuration.
// AdditionalVersion zero means no weighted secondary; an explicit zero weight
// with a nonzero secondary remains an observable routing configuration.
type AliasRecord struct {
	Key                                FunctionReference
	FunctionVersion, AdditionalVersion uint64
	AdditionalWeight                   float64
	Description, Revision              string
	Owner                              AliasOwner
}

type VersionReader interface {
	FunctionVersion(FunctionVersionKey) (FunctionRecord, error)
	// OwnedFunctionVersion recovers the exact publication for a scoped owner.
	OwnedFunctionVersion(FunctionKey, VersionOwner) (FunctionRecord, error)
	// FunctionVersionOwner returns ErrNotFound for native or legacy publications.
	FunctionVersionOwner(FunctionVersionKey) (VersionOwner, error)
	// FunctionVersions returns published versions, excluding $LATEST.
	FunctionVersions(FunctionKey) ([]FunctionRecord, error)
	// LastAllocatedVersion is zero before the first publication. Allocation
	// survives whole-function deletion and recreation with the same scoped name.
	LastAllocatedVersion(FunctionKey) (uint64, error)
}

type VersionWriter interface {
	AllocateFunctionVersion(FunctionKey) (uint64, error)
	PutFunctionVersion(FunctionRecord) error
	// PutFunctionVersionOwner cannot reassign an existing owner to another version.
	PutFunctionVersionOwner(FunctionVersionKey, VersionOwner) error
	DeleteFunctionVersion(FunctionVersionKey) error
	// SetPublishedDeploymentState updates readiness fields and its new public
	// Revision for snapshots sharing the supplied key and DeploymentRevision.
	// Configuration and publication modification times remain immutable.
	SetPublishedDeploymentState(FunctionRecord) error
}

type AliasReader interface {
	Alias(FunctionReference) (AliasRecord, error)
	// Aliases returns records in ascending qualifier order for pagination.
	Aliases(FunctionKey) ([]AliasRecord, error)
}

type AliasWriter interface {
	PutAlias(AliasRecord) error
	DeleteAlias(FunctionReference) error
}
