package integrations

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"stackd/compute/docker"
	native "stackd/compute/lambda"
	"stackd/compute/network"
	"stackd/internal/services/ec2"
	"stackd/internal/services/lambda"
)

// LambdaFunctionNetworkOwner is EC2's scoped execution-role authority boundary.
// Function ARN plus incarnation are immutable service-only ENI owner fields.
type LambdaFunctionNetworkOwner interface {
	SelectLambdaFunctionSubnet(context.Context, string, string, []string, []string) (ec2.SubnetRecord, error)
	AllocateLambdaFunctionNetwork(context.Context, string, string, string, []string) (ec2.TaskNetwork, error)
	ResolveLambdaFunctionNetwork(context.Context, string, string, string) (network.Specification, error)
	ReleaseLambdaFunctionNetwork(context.Context, string, string, string) error
	ListLambdaFunctionNetworks(context.Context, string, string) ([]ec2.LambdaFunctionNetworkRecord, error)
	ResolveLambdaFunctionEndpoint(context.Context, string, string, string, string, string, string) (ec2.LambdaFunctionEndpointAccess, error)
	ObserveLambdaFunctionServiceEndpoint(context.Context, string, string, string, string, string) (network.Specification, error)
}

type LambdaFunctionNetworks struct {
	Roles   ServiceRoles
	EC2     LambdaFunctionNetworkOwner
	Runtime *native.FunctionNetworkRuntime
	// Authoritative policy reads remain ordered with native installations.
	policyMu    sync.Mutex
	lifecycleMu sync.Mutex
	live        map[string]struct{}
	credentials map[string]*lambdaFunctionNetworkLease
	handlerMu   sync.RWMutex
	handler     http.Handler
}

func (a *LambdaFunctionNetworks) Validate(ctx context.Context, function lambda.FunctionKey, role, incarnation string, configuration lambda.FunctionNetworkConfiguration) (string, error) {
	if a.EC2 == nil || a.Runtime == nil {
		return "", errors.New("lambda function VPC networking requires EC2 ownership and a native Docker packet-policy runtime")
	}
	session, wire := openLambdaSourceSession(ctx, a.Roles, function, role)
	if wire != nil {
		return "", wire
	}
	service, wire := session.context(ctx)
	if wire != nil {
		return "", wire
	}
	subnet, err := a.EC2.SelectLambdaFunctionSubnet(service, function.ARN(), incarnation, configuration.SubnetIDs, configuration.SecurityGroupIDs)
	if err != nil {
		return "", err
	}
	if subnet.Data.VpcId == nil {
		return "", errors.New("EC2 function placement has no authoritative VPC identity")
	}
	return string(*subnet.Data.VpcId), nil
}

func (a *LambdaFunctionNetworks) Open(ctx context.Context, function lambda.FunctionKey, role, incarnation string, configuration lambda.FunctionNetworkConfiguration) (native.FunctionNetworkLease, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if a.EC2 == nil || a.Runtime == nil {
		return nil, errors.New("lambda function VPC networking requires EC2 ownership and a native Docker packet-policy runtime")
	}
	if incarnation == "" || len(configuration.SubnetIDs) == 0 || len(configuration.SecurityGroupIDs) == 0 {
		return nil, errors.New("lambda function VPC networking requires an incarnation, subnets and security groups")
	}
	session, wire := openLambdaSourceSession(ctx, a.Roles, function, role)
	if wire != nil {
		return nil, wire
	}
	service, wire := session.context(ctx)
	if wire != nil {
		return nil, wire
	}
	subnet, err := a.EC2.SelectLambdaFunctionSubnet(service, function.ARN(), incarnation, configuration.SubnetIDs, configuration.SecurityGroupIDs)
	if err != nil {
		return nil, err
	}
	allocation, err := a.EC2.AllocateLambdaFunctionNetwork(service, function.ARN(), incarnation, subnet.Key.ID, configuration.SecurityGroupIDs)
	if err != nil {
		return nil, err
	}
	if allocation.Interface.NetworkInterfaceId == nil {
		return nil, errors.New("EC2 function network has no authoritative interface identity")
	}
	owner := function.ARN() + "\x00" + incarnation
	lease := &lambdaFunctionNetworkLease{adapter: a, session: session, function: function.ARN(), incarnation: incarnation, interfaceID: string(*allocation.Interface.NetworkInterfaceId), native: a.Runtime.Prepare(owner, allocation.Network), spec: allocation.Network}
	// Fence recovery between EC2 allocation and native endpoint creation.
	if a.live == nil {
		a.live = make(map[string]struct{})
	}
	a.live[lease.interfaceID] = struct{}{}
	// Read current policy rather than admitting a stale allocation snapshot.
	if err := lease.Check(ctx); err != nil {
		return lease, err
	}
	return lease, nil
}

type lambdaFunctionNetworkLease struct {
	adapter                            *LambdaFunctionNetworks
	session                            *lambdaSourceSession
	function, incarnation, interfaceID string
	native                             *native.FunctionNetworkAttachment
	spec                               network.Specification
	services                           *native.FunctionServiceEndpoints
	servicesRecovered                  bool
	accessKey                          string
	mu                                 sync.Mutex
	closed, nativeClosed               bool
	cancel                             context.CancelFunc
	done                               chan struct{}
}

func (l *lambdaFunctionNetworkLease) checkLocked(ctx context.Context) error {
	if l.closed {
		return net.ErrClosed
	}
	service, wire := l.session.context(ctx)
	var err error
	if wire != nil {
		err = wire
	} else {
		l.adapter.policyMu.Lock()
		var spec network.Specification
		spec, err = l.adapter.EC2.ResolveLambdaFunctionNetwork(service, l.function, l.incarnation, l.interfaceID)
		if err == nil {
			err = l.native.SetPolicy(ctx, spec)
		}
		if err == nil && !l.servicesRecovered {
			err = l.adapter.Runtime.RetireOrphanServices(ctx, spec, func(ctx context.Context, endpointID, address string) (bool, error) {
				_, err := l.adapter.EC2.ObserveLambdaFunctionServiceEndpoint(service, l.function, l.incarnation, l.interfaceID, endpointID, address)
				if errors.Is(err, ec2.ErrNotFound) {
					return false, nil
				}
				return err == nil, err
			})
			l.servicesRecovered = err == nil
		}
		if err == nil && l.services != nil {
			err = l.services.SetPolicy(ctx, spec.ServiceEndpoints, func(ctx context.Context, endpoint network.ServiceEndpoint) (network.Specification, bool, error) {
				current, err := l.adapter.EC2.ObserveLambdaFunctionServiceEndpoint(service, l.function, l.incarnation, l.interfaceID, endpoint.ID, endpoint.Network.Address.String())
				if errors.Is(err, ec2.ErrNotFound) {
					return current, false, nil
				}
				return current, err == nil, err
			})
		}
		if err == nil {
			l.spec = spec
		}
		l.adapter.policyMu.Unlock()
	}
	if err != nil {
		return errors.Join(err, l.native.RevokeTimeout(ctx))
	}
	return nil
}

func (l *lambdaFunctionNetworkLease) Check(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.checkLocked(ctx)
}

func (l *lambdaFunctionNetworkLease) Configure(ctx context.Context, config *docker.ContainerConfig, port string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkLocked(ctx); err != nil {
		return err
	}
	if err := l.native.Configure(ctx, config, port); err != nil {
		return err
	}
	if len(l.spec.ServiceEndpoints) > 0 {
		if !l.adapter.hasHandler() {
			return errors.New("lambda VPC service endpoints require the authenticated AWS handler")
		}
		var err error
		l.services, err = l.adapter.Runtime.OpenServices(ctx, l.spec, l.adapter.endpointHandler)
		return err
	}
	return nil
}

func (l *lambdaFunctionNetworkLease) Attach(ctx context.Context, container string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkLocked(ctx); err != nil {
		return err
	}
	if err := l.native.Attach(ctx, container); err != nil {
		return err
	}
	life, cancel := context.WithCancel(context.WithoutCancel(ctx))
	l.cancel, l.done = cancel, make(chan struct{})
	go l.watch(life)
	return nil
}

func (l *lambdaFunctionNetworkLease) watch(ctx context.Context) {
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

func (l *lambdaFunctionNetworkLease) Close(ctx context.Context) error {
	l.mu.Lock()
	cancel, done := l.cancel, l.done
	l.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.adapter.lifecycleMu.Lock()
	defer l.adapter.lifecycleMu.Unlock()
	l.adapter.policyMu.Lock()
	defer l.adapter.policyMu.Unlock()
	if !l.nativeClosed {
		if err := l.native.Close(ctx); err != nil {
			return err
		}
		l.nativeClosed = true
	}
	if l.services != nil {
		if err := l.services.Close(ctx); err != nil {
			return err
		}
	}
	service, wire := l.session.context(ctx)
	if wire != nil {
		return wire
	}
	if err := l.adapter.EC2.ReleaseLambdaFunctionNetwork(service, l.function, l.incarnation, l.interfaceID); err != nil {
		return err
	}
	l.closed = true
	delete(l.adapter.live, l.interfaceID)
	if l.accessKey != "" && l.adapter.credentials[l.accessKey] == l {
		delete(l.adapter.credentials, l.accessKey)
	}
	return nil
}

var _ lambda.FunctionNetworks = (*LambdaFunctionNetworks)(nil)
var _ native.FunctionNetworkLease = (*lambdaFunctionNetworkLease)(nil)

func (a *LambdaFunctionNetworks) Recover(ctx context.Context, function lambda.FunctionKey, role, incarnation string) error {
	if a.EC2 == nil || a.Runtime == nil {
		return errors.New("lambda function VPC recovery requires EC2 and the native network runtime")
	}
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	session, wire := openLambdaSourceSession(ctx, a.Roles, function, role)
	if wire != nil {
		return wire
	}
	service, wire := session.context(ctx)
	if wire != nil {
		return wire
	}
	records, err := a.EC2.ListLambdaFunctionNetworks(service, function.ARN(), incarnation)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Interface.NetworkInterfaceId == nil {
			return errors.New("EC2 function recovery interface has no immutable ID")
		}
		id := string(*record.Interface.NetworkInterfaceId)
		if _, live := a.live[id]; live {
			continue
		}
		owner := function.ARN() + "\x00" + record.Incarnation
		live, err := a.Runtime.HasEndpoint(ctx, owner, record.Network)
		if err != nil {
			return err
		}
		if live {
			continue
		}
		if err := a.Runtime.Retire(ctx, owner, record.Network); err != nil {
			return err
		}
		if err := a.EC2.ReleaseLambdaFunctionNetwork(service, function.ARN(), record.Incarnation, id); err != nil {
			return err
		}
	}
	return nil
}
