package ram

import (
	"context"

	"stackd/internal/services/identitystore"
)

// CloudFormation ownership is private immutable metadata recorded on the share
// and on each live association row. Public tags never grant authority. An empty
// owner is the default unowned scope of direct API calls. Removing an edge
// clears its claim, so recreating an identical edge cannot authorize an old
// stack incarnation.

type shareAuthorityKey struct{}
type ownedViewKey struct{}
type shareOwnerViewKey struct{}

// WithShareOwnerView selects exact-incarnation shares for private creation
// observation. Association controllers may still read their dependency share.
func WithShareOwnerView(ctx context.Context) context.Context {
	return context.WithValue(ctx, shareOwnerViewKey{}, true)
}

// WithShareAuthority carries trusted controller provenance, never caller wire
// input: edge mutations act for the share's recorded owner, including the
// unowned native scope, instead of bypassing edge ownership. A CloudFormation
// owner in the same context must also match the share's recorded owner.
func WithShareAuthority(ctx context.Context) context.Context {
	return context.WithValue(ctx, shareAuthorityKey{}, true)
}

// WithOwnedView limits association reads to edges owned by the call's exact
// authority, so a controller can distinguish its edges from separately owned ones.
func WithOwnedView(ctx context.Context) context.Context {
	return context.WithValue(ctx, ownedViewKey{}, true)
}

func notOwned(what string) error {
	return failure("OperationNotPermittedException", what+" is not owned by this CloudFormation incarnation.")
}

// edgeAuthority returns the exact owner a call acts for. exact is false only for
// direct API calls, which manage any edge under current IAM.
func edgeAuthority(ctx context.Context, v Share) (string, bool, error) {
	owner := identitystore.CloudFormationOwner(ctx)
	if share, _ := ctx.Value(shareAuthorityKey{}).(bool); share {
		if owner != "" && owner != v.CloudFormationOwner {
			return "", false, notOwned("Resource share")
		}
		return v.CloudFormationOwner, true, nil
	}
	return owner, owner != "", nil
}

// checkShareOwner fences share-level mutations to the recorded incarnation.
func checkShareOwner(ctx context.Context, v Share) error {
	if owner := identitystore.CloudFormationOwner(ctx); owner != "" && owner != v.CloudFormationOwner {
		return notOwned("Resource share")
	}
	return nil
}

func checkPermissionOwner(ctx context.Context, p Permission) error {
	if owner := identitystore.CloudFormationOwner(ctx); owner != "" && owner != p.CloudFormationOwner {
		return notOwned("Permission")
	}
	return nil
}

func (s *Service) edgeOwner(r Reader, v Share, kind, id string) (string, bool, error) {
	switch kind {
	case "RESOURCE":
		for _, a := range v.Resources {
			if a.ARN == id && a.Status != "DISASSOCIATED" {
				return a.CloudFormationOwner, true, nil
			}
		}
	case "PRINCIPAL":
		for _, a := range v.Principals {
			if a.Principal == id {
				status, e := s.principalAssociationStatus(r, a)
				return a.CloudFormationOwner, e == nil && status != "DISASSOCIATED", e
			}
		}
	case "PERMISSION":
		for _, a := range v.Permissions {
			if a.ARN == id {
				return a.CloudFormationOwner, true, nil
			}
		}
	}
	return "", false, nil
}

// claimEdge rejects an exact authority acting on another owner's live edge.
func (s *Service) claimEdge(r Reader, v Share, kind, id string) error {
	owner, exact, e := edgeAuthority(r.Context(), v)
	if e != nil || !exact {
		return e
	}
	current, exists, e := s.edgeOwner(r, v, kind, id)
	if e != nil {
		return e
	}
	if exists && current != owner {
		return notOwned("Association")
	}
	return nil
}

// ownedView returns the owner whose edges a WithOwnedView read may observe.
func ownedView(ctx context.Context, v Share) (string, bool, error) {
	if on, _ := ctx.Value(ownedViewKey{}).(bool); !on {
		return "", false, nil
	}
	owner, _, e := edgeAuthority(ctx, v)
	return owner, e == nil, e
}
