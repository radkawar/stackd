package lambda

import (
	"context"
	"net"
)

// SourceNetworkConfiguration is the source's VPC placement, not the function's
// runtime VPC configuration. EC2 validates all candidates and owns the ENI.
type SourceNetworkConfiguration struct {
	SubnetIDs, SecurityGroupIDs []string
}

// SourceNetworks retains one mapping-owned EC2 attachment across consumer
// reconnects and controller restarts. Release is called when the mapping retires;
// closing a consumer lease does not release its authoritative ENI reservation.
type SourceNetworks interface {
	Open(context.Context, FunctionKey, string, string, SourceNetworkConfiguration) (SourceNetworkLease, error)
	Release(context.Context, FunctionKey, string, string) error
}

// SourceNetworkLease carries real sockets from an isolated native namespace.
// Check refreshes current execution-role and EC2 policy authority before a fetch
// or acknowledgement. Policy withdrawal closes existing sockets, so buffered
// source operations cannot evade a newly effective network boundary.
type SourceNetworkLease interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	Check(context.Context) error
	Close() error
}
