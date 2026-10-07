package stepfunctions

import "context"

type cloudFormationOwner struct {
	Kind, Owner string
	Creating    bool
}
type cloudFormationOwnerKey struct{}

func WithCloudFormationOwner(ctx context.Context, kind, owner string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{Kind: kind, Owner: owner})
}
func WithCloudFormationCreate(ctx context.Context, kind, owner string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{Kind: kind, Owner: owner, Creating: true})
}
func cloudFormationClaim(ctx context.Context, kind string) string {
	o, _ := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	if o.Kind == kind {
		return o.Owner
	}
	return ""
}
func cloudFormationCheck(ctx context.Context, kind, stored string) error {
	o, _ := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	if o.Kind != kind {
		return nil
	}
	if o.Creating && o.Owner == "" {
		return failure("ConflictException", "Resource already exists.", 400)
	}
	if o.Owner != "" && stored != o.Owner {
		return failure("ConflictException", "Resource is not owned by this CloudFormation incarnation.", 400)
	}
	return nil
}
