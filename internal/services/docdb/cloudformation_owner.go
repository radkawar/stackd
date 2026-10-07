package docdb

import (
	"context"
	"strings"
)

// CloudFormationOwner is native private provenance, never customer tag data.
type CloudFormationOwner struct {
	StackID, LogicalID, Token string
}

type cloudFormationAuthority struct {
	Owner                          CloudFormationOwner
	Kind, Name                     string
	SnapshotName, SnapshotSourceID string
	SourceName                     string
}
type cloudFormationAuthorityKey struct{}

func WithCloudFormationOwner(ctx context.Context, kind, name string, owner CloudFormationOwner) context.Context {
	return context.WithValue(ctx, cloudFormationAuthorityKey{}, cloudFormationAuthority{Owner: owner, Kind: kind, Name: strings.ToLower(name)})
}

// Backup admission always claims the snapshot, including direct Cloud Control
// deletion, and atomically fences the privately retained native source ID.
func WithCloudFormationSnapshot(ctx context.Context, name, sourceName, sourceID string, owner CloudFormationOwner, fenceSource bool) context.Context {
	a := cloudFormationAuthority{Owner: owner, SnapshotName: strings.ToLower(name), SnapshotSourceID: sourceID, SourceName: strings.ToLower(sourceName)}
	if fenceSource {
		a.Kind, a.Name = "cluster", a.SourceName
	}
	return context.WithValue(ctx, cloudFormationAuthorityKey{}, a)
}

func cloudFormationClaim(ctx context.Context, k Key) CloudFormationOwner {
	a, ok := ctx.Value(cloudFormationAuthorityKey{}).(cloudFormationAuthority)
	if ok && ((k.Kind == a.Kind && k.Name == a.Name) || (k.Kind == "cluster-snapshot" && k.Name == a.SnapshotName)) {
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
	if ok && a.SnapshotSourceID != "" && ((k.Kind == "cluster" && k.Name == a.SourceName) || (k.Kind == "cluster-snapshot" && k.Name == a.SnapshotName)) && sourceID != a.SnapshotSourceID {
		return failure("InvalidParameterValue", "The snapshot belongs to a different native source incarnation.")
	}
	return nil
}
