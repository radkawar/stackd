package rds

import (
	"context"
	"strings"
)

// CloudFormationOwner is private native provenance. Public tags cannot create,
// modify or transfer this claim; it commits with the actual resource row.
type CloudFormationOwner struct {
	StackID, LogicalID, Token string
}

type cloudFormationAuthority struct {
	Owner                                        CloudFormationOwner
	Kind, Name                                   string
	SnapshotKind, SnapshotName, SnapshotSourceID string
	SourceKind, SourceName                       string
}
type cloudFormationAuthorityKey struct{}

func WithCloudFormationOwner(ctx context.Context, kind, name string, owner CloudFormationOwner) context.Context {
	return context.WithValue(ctx, cloudFormationAuthorityKey{}, cloudFormationAuthority{Owner: owner, Kind: kind, Name: strings.ToLower(name)})
}

// WithCloudFormationSnapshot always claims the backup and binds its exact native
// source ID. Direct Cloud Control deletion need not claim the existing source.
func WithCloudFormationSnapshot(ctx context.Context, kind, name, sourceKind, sourceName, sourceID string, owner CloudFormationOwner, fenceSource bool) context.Context {
	a := cloudFormationAuthority{Owner: owner, SnapshotKind: kind, SnapshotName: strings.ToLower(name), SnapshotSourceID: sourceID, SourceKind: sourceKind, SourceName: strings.ToLower(sourceName)}
	if fenceSource {
		a.Kind, a.Name = a.SourceKind, a.SourceName
	}
	return context.WithValue(ctx, cloudFormationAuthorityKey{}, a)
}

func cloudFormationClaim(ctx context.Context, k Key) CloudFormationOwner {
	a, ok := ctx.Value(cloudFormationAuthorityKey{}).(cloudFormationAuthority)
	if ok && ((k.Kind == a.Kind && k.Name == a.Name) || (k.Kind == a.SnapshotKind && k.Name == a.SnapshotName)) {
		return a.Owner
	}
	return CloudFormationOwner{}
}

func checkCloudFormationOwner(ctx context.Context, k Key, owner CloudFormationOwner) error {
	wanted := cloudFormationClaim(ctx, k)
	if wanted != (CloudFormationOwner{}) && (wanted.Token == "" || owner != wanted) {
		return failure("InvalidParameterValue", "The resource belongs to a different native controller incarnation.")
	}
	return nil
}

func checkCloudFormationSnapshot(ctx context.Context, k Key, sourceID string) error {
	a, ok := ctx.Value(cloudFormationAuthorityKey{}).(cloudFormationAuthority)
	if ok && a.SnapshotSourceID != "" && ((k.Kind == a.SourceKind && k.Name == a.SourceName) || (k.Kind == a.SnapshotKind && k.Name == a.SnapshotName)) && sourceID != a.SnapshotSourceID {
		return failure("InvalidParameterValue", "The snapshot belongs to a different native source incarnation.")
	}
	return nil
}
