package ecs

import (
	"context"

	"stackd/compute/network"
	api "stackd/internal/awsapi/ecs"
)

// TaskPlacement is a validated EC2 subnet choice, not an address reservation.
type TaskPlacement struct {
	SubnetID, AvailabilityZone string
}

// TaskNetwork contains EC2-owned attachment facts and the current native policy.
type TaskNetwork struct {
	Attachment api.Attachment
	Network    network.Specification
}

// TaskNetworks joins allocation and release to the caller's state transaction.
// Native container effects must run outside that transaction.
type TaskNetworks interface {
	Select(context.Context, string, api.AwsVpcConfiguration) (TaskPlacement, error)
	Allocate(context.Context, string, api.Attachment, api.AwsVpcConfiguration) (TaskNetwork, error)
	Resolve(context.Context, string, api.Attachment) (network.Specification, error)
	Release(context.Context, string, api.Attachment) error
}
