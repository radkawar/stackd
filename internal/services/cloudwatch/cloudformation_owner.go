package cloudwatch

import (
	"context"
	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

type cloudFormationOwnerKey struct{}
type cloudFormationOwner struct {
	Marker string
	Create bool
}

// WithCloudFormationOwner constrains native row admission and mutations, never public tags.
func WithCloudFormationOwner(ctx context.Context, marker string, create bool) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{marker, create})
}
func cloudFormationClaim(ctx context.Context, old string, exists bool) (string, *awswire.Error) {
	owner, ok := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	if !ok {
		return old, nil
	}
	if owner.Marker == "" || exists && old != owner.Marker {
		return "", failure("AccessDeniedException", "The resource belongs to a different CloudFormation incarnation.")
	}
	if !exists && !owner.Create {
		return "", failure("ResourceNotFoundException", "The CloudWatch resource does not exist.")
	}
	return owner.Marker, nil
}
func cloudFormationOwned(ctx context.Context, marker string) *awswire.Error {
	_, wire := cloudFormationClaim(ctx, marker, true)
	return wire
}

type cloudFormationObservationKey struct{}
type cloudFormationObservation struct {
	Kind, Name string
	Rows       map[string]string
}

// WithCloudFormationObservation exposes private claims only after an authorized
// exact native read or a committed admission. Claims never enter public responses.
func WithCloudFormationObservation(ctx context.Context, kind, name string, rows map[string]string) context.Context {
	return context.WithValue(ctx, cloudFormationObservationKey{}, cloudFormationObservation{kind, name, rows})
}
func observeCloudFormation(ctx context.Context, kind, name, marker string) {
	if v, ok := ctx.Value(cloudFormationObservationKey{}).(cloudFormationObservation); ok && v.Kind == kind && v.Name == name && v.Rows != nil {
		v.Rows[name] = marker
	}
}

// Publish admission only after the native resource/event transaction commits.
// This receipt retains an authentic ID if the command response is lost.
func observeCloudFormationAdmission(ctx context.Context, operation string, input any) {
	owner, ok := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	if !ok || !owner.Create {
		return
	}
	switch operation {
	case "PutMetricAlarm":
		observeCloudFormation(ctx, "MetricAlarm", value(input.(*api.PutMetricAlarmInput).AlarmName), owner.Marker)
	case "PutCompositeAlarm":
		observeCloudFormation(ctx, "CompositeAlarm", value(input.(*api.PutCompositeAlarmInput).AlarmName), owner.Marker)
	case "PutDashboard":
		observeCloudFormation(ctx, "Dashboard", value(input.(*api.PutDashboardInput).DashboardName), owner.Marker)
	}
}
