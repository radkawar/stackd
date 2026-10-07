package guardduty

import "context"

// CloudFormationOwnership is private native incarnation authority, never wire input.
type CloudFormationOwnership struct{ Owner, Token string }
type cloudFormationOwnershipKey struct{}

func WithCloudFormationOwnership(ctx context.Context, v CloudFormationOwnership) context.Context {
	return context.WithValue(ctx, cloudFormationOwnershipKey{}, v)
}
func creationOwnership(ctx context.Context) CloudFormationOwnership {
	v, _ := ctx.Value(cloudFormationOwnershipKey{}).(CloudFormationOwnership)
	return v
}
func checkCloudFormationOwnership(ctx context.Context, actual CloudFormationOwnership) error {
	v, ok := ctx.Value(cloudFormationOwnershipKey{}).(CloudFormationOwnership)
	if !ok {
		return nil
	}
	if v.Owner == "" || v.Token == "" || actual != v {
		return invalid("The control belongs to another resource incarnation.")
	}
	return nil
}
