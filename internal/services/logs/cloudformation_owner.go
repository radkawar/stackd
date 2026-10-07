package logs

import (
	"context"
	"stackd/internal/awswire"
)

type cloudFormationOwnerKey struct{}
type cloudFormationOwner struct {
	Marker string
	Create bool
}

// WithCloudFormationOwner constrains the existing command transaction. Native
// updates retain the marker; deletion/recreation loses it with the owner record.
func WithCloudFormationOwner(ctx context.Context, marker string, create bool) context.Context {
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{marker, create})
}
func cloudFormationClaim(ctx context.Context, old string, exists bool) (string, *awswire.Error) {
	owner, ok := ctx.Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	if !ok {
		return old, nil
	}
	if owner.Marker == "" || exists && old != owner.Marker || !exists && !owner.Create {
		return "", failure("AccessDeniedException", "The resource belongs to a different CloudFormation incarnation.")
	}
	return owner.Marker, nil
}
func cloudFormationDelete(ctx context.Context, old string) *awswire.Error {
	_, wire := cloudFormationClaim(ctx, old, true)
	return wire
}

type cloudFormationGroupOwnerKey struct{}

func WithCloudFormationLogGroupOwner(ctx context.Context, marker string, create bool) context.Context {
	return context.WithValue(ctx, cloudFormationGroupOwnerKey{}, cloudFormationOwner{marker, create})
}
func cloudFormationGroupClaim(ctx context.Context, old string, exists bool) (string, *awswire.Error) {
	owner, ok := ctx.Value(cloudFormationGroupOwnerKey{}).(cloudFormationOwner)
	if !ok {
		return old, nil
	}
	return cloudFormationClaim(WithCloudFormationOwner(ctx, owner.Marker, owner.Create), old, exists)
}

type cloudFormationObservationKey struct{}
type cloudFormationObservation struct {
	Kind, Name string
	Rows       map[string]string
}

// WithCloudFormationObservation exposes private claims after authorized exact
// native reads or committed admissions, without changing any public response.
func WithCloudFormationObservation(ctx context.Context, kind, name string, rows map[string]string) context.Context {
	return context.WithValue(ctx, cloudFormationObservationKey{}, cloudFormationObservation{kind, name, rows})
}
func observeCloudFormation(ctx context.Context, kind, name, marker string) {
	if v, ok := ctx.Value(cloudFormationObservationKey{}).(cloudFormationObservation); ok && v.Kind == kind && v.Name == name && v.Rows != nil {
		v.Rows[name] = marker
	}
}

type cloudFormationDestinationPolicyRemovalKey struct{}

// WithCloudFormationDestinationPolicyRemoval clears an omitted destination
// policy under PutDestinationPolicy authorization in the same transaction.
func WithCloudFormationDestinationPolicyRemoval(ctx context.Context) context.Context {
	return context.WithValue(ctx, cloudFormationDestinationPolicyRemovalKey{}, true)
}
