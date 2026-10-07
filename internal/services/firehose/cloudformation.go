package firehose

import "context"

type cloudFormationOwnerKey struct{}

func WithCloudFormationOwner(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, owner)
}
func cloudFormationOwner(ctx context.Context) string {
	owner, _ := ctx.Value(cloudFormationOwnerKey{}).(string)
	return owner
}
func cloudFormationCheck(ctx context.Context, stored string) error {
	expected := cloudFormationOwner(ctx)
	if expected != "" && stored != expected {
		return failure("ResourceInUseException", "Delivery stream belongs to another CloudFormation incarnation.")
	}
	return nil
}
