package resourcegroups

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

type cloudFormationOwnerKey struct{}

// WithCloudFormationOwner carries trusted controller provenance for tag-sync
// task creation; HTTP inputs cannot set it. The owner names one stack resource
// incarnation, so an interrupted create recovers the same task identity.
func WithCloudFormationOwner(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, owner)
}

func cloudFormationOwner(ctx context.Context) string {
	owner, _ := ctx.Value(cloudFormationOwnerKey{}).(string)
	return owner
}

// CloudFormationTagSyncTaskARN is the only task identity the owner can create
// in a group. Native task suffixes are random UUIDs and never collide with it.
func CloudFormationTagSyncTaskARN(groupARN, owner string) string {
	sum := sha256.Sum256([]byte(owner))
	return groupARN + "/tag-sync-task/" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:16]))
}

type cloudFormationGroupKey struct{}
type cloudFormationGroupOwner struct {
	Claim    string
	Enforce  bool
	Observed map[string]string
}

// WithCloudFormationGroupOwnership carries trusted group admission or mutation
// provenance. Authorized native reads publish private claims only to Observed.
func WithCloudFormationGroupOwnership(ctx context.Context, claim string, enforce bool, observed map[string]string) context.Context {
	return context.WithValue(ctx, cloudFormationGroupKey{}, cloudFormationGroupOwner{Claim: claim, Enforce: enforce, Observed: observed})
}

func cloudFormationGroupClaim(ctx context.Context) string {
	owner, _ := ctx.Value(cloudFormationGroupKey{}).(cloudFormationGroupOwner)
	return owner.Claim
}

func observeCloudFormationGroup(ctx context.Context, g Group) error {
	owner, ok := ctx.Value(cloudFormationGroupKey{}).(cloudFormationGroupOwner)
	if !ok {
		return nil
	}
	if owner.Observed != nil {
		owner.Observed[g.ARN] = g.CloudFormationClaim
		owner.Observed[g.Name] = g.CloudFormationClaim
	}
	if owner.Enforce && (owner.Claim == "" || g.CloudFormationClaim != owner.Claim) {
		return failure("ForbiddenException", "Group belongs to another CloudFormation incarnation.")
	}
	return nil
}
