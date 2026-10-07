package servicecatalogappregistry

import "context"

type cloudFormationOwnershipKey struct{}

// CloudFormationOwnership is trusted controller provenance for one stack
// resource incarnation. HTTP inputs cannot set it and no response exposes it;
// public tags never confer it.
type CloudFormationOwnership struct {
	// Claim names the incarnation, retained privately from trusted context.
	// Native ClientToken payloads never confer controller authority.
	Claim string
	// Target fences every operation loading this Application or AttributeGroup
	// ID/ARN to the parent created with Claim. Association edges leave it empty
	// and never borrow a parent's claim.
	Target string
	// Edge makes association creation claim a new edge (or replay an edge with
	// this claim) and makes disassociation require the edge's retained claim.
	Edge bool
	// Owned collects observed identities retained with Claim: application and
	// attribute group IDs, or associated attribute group and resource ARNs.
	// List operations observe every row, independent of the requested page.
	Owned map[string]bool
}

func WithCloudFormationOwnership(ctx context.Context, owner CloudFormationOwnership) context.Context {
	return context.WithValue(ctx, cloudFormationOwnershipKey{}, owner)
}

func cloudFormationOwner(ctx context.Context) (CloudFormationOwnership, bool) {
	owner, ok := ctx.Value(cloudFormationOwnershipKey{}).(CloudFormationOwnership)
	return owner, ok && owner.Claim != ""
}

// observeClaim records a row retained with the requesting incarnation's claim.
func observeClaim(ctx context.Context, id, claim string) {
	if owner, ok := cloudFormationOwner(ctx); ok && owner.Owned != nil && claim == owner.Claim {
		owner.Owned[id] = true
	}
}

// fenceParent hides a targeted parent created by another incarnation.
func fenceParent(ctx context.Context, id, arn, claim string) error {
	owner, ok := cloudFormationOwner(ctx)
	if !ok || owner.Target == "" || owner.Target != id && owner.Target != arn {
		return nil
	}
	if claim != owner.Claim {
		return failure("ResourceNotFoundException", "The resource was not created by this CloudFormation incarnation.")
	}
	return nil
}

// parentClaim admits controller provenance only from trusted parent creation
// context. Ordinary SDK ClientToken idempotency remains independent.
func parentClaim(ctx context.Context) string {
	if owner, ok := cloudFormationOwner(ctx); ok && !owner.Edge {
		return owner.Claim
	}
	return ""
}

// edgeClaim is the private claim retained by an association created now.
func edgeClaim(ctx context.Context) string {
	if owner, ok := cloudFormationOwner(ctx); ok && owner.Edge {
		return owner.Claim
	}
	return ""
}

// edgeOwned reports whether the caller may act on an existing edge. Direct
// callers remain governed by IAM alone.
func edgeOwned(ctx context.Context, claim string) bool {
	owner, ok := cloudFormationOwner(ctx)
	return !ok || !owner.Edge || claim == owner.Claim
}
