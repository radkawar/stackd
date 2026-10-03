package integrations

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	native "stackd/compute/lambda"
	"stackd/compute/network"
	"stackd/internal/services/ec2"
	"stackd/internal/services/lambda"
)

// LambdaSourceNetworkOwner is EC2's delegated execution-role ENI boundary.
// Mapping ownership is immutable EC2 state, never a mutable tag or description.
type LambdaSourceNetworkOwner interface {
	SelectLambdaSourceSubnet(context.Context, string, []string, []string) (ec2.SubnetRecord, error)
	AllocateLambdaSourceNetwork(context.Context, string, string, []string) (ec2.TaskNetwork, error)
	LookupLambdaSourceNetwork(context.Context, string) (ec2.TaskNetwork, error)
	ResolveLambdaSourceNetwork(context.Context, string, string) (network.Specification, error)
	ReleaseLambdaSourceNetwork(context.Context, string, string) error
}

type LambdaSourceNetworkRuntime interface {
	Attach(context.Context, string, network.Specification) (native.SourceNetworkAttachment, error)
	Release(context.Context, string) error
}

type LambdaSourceNetworks struct {
	Roles   ServiceRoles
	EC2     LambdaSourceNetworkOwner
	Runtime LambdaSourceNetworkRuntime
	// Keep authoritative reads ordered with native installs, including a
	// running consumer racing a second lease opened by admission preflight.
	policyMu sync.Mutex
}

func (a *LambdaSourceNetworks) Open(ctx context.Context, function lambda.FunctionKey, role, mapping string, configuration lambda.SourceNetworkConfiguration) (lambda.SourceNetworkLease, error) {
	if a.EC2 == nil || a.Runtime == nil {
		return nil, errors.New("lambda source VPC networking requires EC2 ownership and a native namespace runtime")
	}
	if len(configuration.SubnetIDs) == 0 || len(configuration.SecurityGroupIDs) == 0 {
		return nil, errors.New("lambda source VPC networking requires both subnets and security groups")
	}
	session, wire := openLambdaSourceSession(ctx, a.Roles, function, role)
	if wire != nil {
		return nil, wire
	}
	service, wire := session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	attachment, err := a.EC2.LookupLambdaSourceNetwork(service, mapping)
	if errors.Is(err, ec2.ErrNotFound) {
		subnet, selectErr := a.EC2.SelectLambdaSourceSubnet(service, mapping, configuration.SubnetIDs, configuration.SecurityGroupIDs)
		if selectErr != nil {
			return nil, selectErr
		}
		attachment, err = a.EC2.AllocateLambdaSourceNetwork(service, mapping, subnet.Key.ID, configuration.SecurityGroupIDs)
	}
	if err != nil {
		return nil, err
	}
	if attachment.Interface.NetworkInterfaceId == nil || attachment.Interface.SubnetId == nil {
		return nil, errors.New("EC2 source network has no authoritative interface identity")
	}
	if !slices.Contains(configuration.SubnetIDs, string(*attachment.Interface.SubnetId)) {
		return nil, errors.New("retained source ENI is outside the mapping subnet configuration")
	}
	groups := make([]string, 0, len(attachment.Interface.Groups))
	for _, group := range attachment.Interface.Groups {
		if group.GroupId != nil {
			groups = append(groups, string(*group.GroupId))
		}
	}
	wanted := slices.Clone(configuration.SecurityGroupIDs)
	slices.Sort(wanted)
	slices.Sort(groups)
	if !slices.Equal(slices.Compact(wanted), groups) {
		return nil, errors.New("retained source ENI security groups differ from immutable mapping configuration")
	}
	id := string(*attachment.Interface.NetworkInterfaceId)
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	spec, err := a.EC2.ResolveLambdaSourceNetwork(service, mapping, id)
	if err != nil {
		return nil, err
	}
	native, err := a.Runtime.Attach(ctx, mapping, spec)
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(context.WithoutCancel(ctx))
	lease := &lambdaSourceNetworkLease{adapter: a, session: session, mapping: mapping, interfaceID: id, native: native, cancel: cancel, done: make(chan struct{})}
	go lease.watch(life)
	return lease, nil
}

func (a *LambdaSourceNetworks) Release(ctx context.Context, function lambda.FunctionKey, role, mapping string) error {
	if a.EC2 == nil || a.Runtime == nil {
		return errors.New("lambda source network cleanup requires EC2 and its native namespace runtime")
	}
	session, wire := openLambdaSourceSession(ctx, a.Roles, function, role)
	if wire != nil {
		return wire
	}
	service, wire := session.context(ctx)
	if wire != nil {
		return wire
	}
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	attachment, err := a.EC2.LookupLambdaSourceNetwork(service, mapping)
	if err != nil && !errors.Is(err, ec2.ErrNotFound) {
		return err
	}
	if err := a.Runtime.Release(ctx, mapping); err != nil {
		return err
	}
	if errors.Is(err, ec2.ErrNotFound) {
		return nil
	}
	if attachment.Interface.NetworkInterfaceId == nil {
		return errors.New("EC2 source network has no authoritative interface identity")
	}
	return a.EC2.ReleaseLambdaSourceNetwork(service, mapping, string(*attachment.Interface.NetworkInterfaceId))
}

type lambdaSourceNetworkLease struct {
	adapter              *LambdaSourceNetworks
	session              *lambdaSourceSession
	mapping, interfaceID string
	native               native.SourceNetworkAttachment
	mu                   sync.Mutex
	closed               bool
	cancel               context.CancelFunc
	done                 chan struct{}
}

func (l *lambdaSourceNetworkLease) Check(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return net.ErrClosed
	}
	service, wire := l.session.context(ctx)
	if wire != nil {
		l.native.Revoke()
		return wire
	}
	l.adapter.policyMu.Lock()
	defer l.adapter.policyMu.Unlock()
	spec, err := l.adapter.EC2.ResolveLambdaSourceNetwork(service, l.mapping, l.interfaceID)
	if err == nil {
		err = l.native.SetPolicy(ctx, spec)
	}
	if err != nil {
		l.native.Revoke()
	}
	return err
}
func (l *lambdaSourceNetworkLease) DialContext(ctx context.Context, kind, address string) (net.Conn, error) {
	if err := l.Check(ctx); err != nil {
		return nil, err
	}
	return l.native.DialContext(ctx, kind, address)
}
func (l *lambdaSourceNetworkLease) watch(ctx context.Context) {
	defer close(l.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check, cancel := context.WithTimeout(ctx, 20*time.Second)
			_ = l.Check(check)
			cancel()
		}
	}
}
func (l *lambdaSourceNetworkLease) Close() error {
	l.cancel()
	<-l.done
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.native.Close()
}

var _ lambda.SourceNetworks = (*LambdaSourceNetworks)(nil)
