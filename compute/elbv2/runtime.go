// Package elbv2 provides native ALB socket attachments, independent of ECS.
package elbv2

import (
	"context"
	"net"

	"stackd/compute/network"
)

// Specification binds a load balancer node to an EC2-owned attachment.
// Network.Policy includes EC2's authoritative public assignment and route
// admission; the runtime installs native public mappings, never allocates them.
type Specification struct {
	LoadBalancerARN, AttachmentID string
	Network                       network.Specification
}

// Runtime owns durable native attachments. Remove, not Node.Close, deletes them.
type Runtime interface {
	Prepare(context.Context, Specification) (Node, error)
	Remove(context.Context, Specification) error
}

// Node transports raw sockets only. HTTP, TLS and routing remain in the parent.
// Callers serialize current EC2 policy reads with SetNetworkPolicy so an older
// attachment snapshot cannot replace a later SG/NACL/route/public assignment.
type Node interface {
	Listen(context.Context, int) (net.Listener, error)
	DialContext(context.Context, string, string) (net.Conn, error)
	SetNetworkPolicy(context.Context, network.Policy) error
	Close() error
}
