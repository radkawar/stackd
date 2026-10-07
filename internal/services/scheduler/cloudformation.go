package scheduler

import "context"

type cloudFormationScheduleKey struct{}

// Private claims are supplied only by trusted adapters, never by ClientToken.
func WithCloudFormationSchedule(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, cloudFormationScheduleKey{}, owner)
}
func cloudFormationScheduleClaim(ctx context.Context) string {
	owner, _ := ctx.Value(cloudFormationScheduleKey{}).(string)
	return owner
}
func cloudFormationScheduleCheck(ctx context.Context, stored string) error {
	if expected := cloudFormationScheduleClaim(ctx); expected != "" && stored != expected {
		return failure("ConflictException", "Schedule belongs to another CloudFormation incarnation.", 409)
	}
	return nil
}

type cloudFormationGroupKey struct{}

func WithCloudFormationGroup(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, cloudFormationGroupKey{}, owner)
}
func cloudFormationGroupClaim(ctx context.Context) string {
	owner, _ := ctx.Value(cloudFormationGroupKey{}).(string)
	return owner
}
func cloudFormationGroupCheck(ctx context.Context, stored string) error {
	if expected := cloudFormationGroupClaim(ctx); expected != "" && stored != expected {
		return failure("ConflictException", "Schedule group belongs to another CloudFormation incarnation.", 409)
	}
	return nil
}
