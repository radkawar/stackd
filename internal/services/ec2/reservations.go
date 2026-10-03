package ec2

import (
	"context"
	"errors"
	"reflect"
	"slices"

	api "stackd/internal/awsapi/ec2"
)

// ReservationRecord retains launch identity and token arguments, not mutable
// instance copies. TokenZone is empty for regional idempotency and the selected
// AZ for explicit Placement/Subnet zonal idempotency.
type ReservationRecord struct {
	Key                                   ResourceKey
	Input                                 api.RunInstancesRequest
	ClientToken, TokenZone, RequesterID   string
	LaunchPrincipalARN, LaunchPrincipalID string
	InstanceIDs                           []string
}

func cloneReservation(v ReservationRecord) ReservationRecord {
	v.Input = api.CloneRunInstancesRequest(v.Input)
	v.InstanceIDs = slices.Clone(v.InstanceIDs)
	return v
}

func reservationInput(in *api.RunInstancesRequest) api.RunInstancesRequest {
	out := api.CloneRunInstancesRequest(*in)
	out.DryRun, out.ClientToken = nil, nil
	// The accepted one-primary-address list and scalar form name the same
	// allocation. Persist their canonical effective input for token equality.
	for i := range out.NetworkInterfaces {
		network := &out.NetworkInterfaces[i]
		if len(network.PrivateIpAddresses) == 1 && boolValue(network.PrivateIpAddresses[0].Primary) {
			network.PrivateIpAddress = network.PrivateIpAddresses[0].PrivateIpAddress
			network.PrivateIpAddresses = nil
		}
	}
	return out
}

func reservationResult(ctx context.Context, tx Reader, record ReservationRecord) (*api.Reservation, error) {
	out := &api.Reservation{ReservationId: new(api.String(record.Key.ID)), OwnerId: new(api.String(record.Key.Scope.AccountID)), Groups: api.GroupIdentifierList{}, Instances: api.InstanceList{}}
	if record.RequesterID != "" {
		out.RequesterId = new(api.String(record.RequesterID))
	}
	for _, id := range record.InstanceIDs {
		instance, err := loadInstance(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		data, err := instanceProjection(ctx, tx, instance)
		if err != nil {
			return nil, err
		}
		out.Instances = append(out.Instances, data)
	}
	return out, nil
}

func retainedReservation(ctx context.Context, tx Reader, in *api.RunInstancesRequest, zone string) (*api.Reservation, error) {
	if str(in.ClientToken) == "" {
		return nil, nil
	}
	records, err := tx.InstanceReservationsByToken(scopeFor(ctx), str(in.ClientToken))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	input := reservationInput(in)
	for _, record := range records {
		if record.TokenZone != zone && record.TokenZone != "" && zone != "" {
			if _, managed := ctx.Value(lambdaManagedLaunchKey{}).(string); managed {
				return nil, networkInterfaceTokenMismatch()
			}
			continue
		}
		if record.TokenZone != zone || !reflect.DeepEqual(record.Input, input) {
			return nil, networkInterfaceTokenMismatch()
		}
		if err := validateLambdaReservation(ctx, tx, record); err != nil {
			return nil, err
		}
		return reservationResult(ctx, tx, record)
	}
	return nil, nil
}
