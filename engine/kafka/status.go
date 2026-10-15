package kafka

import (
	"context"
	"errors"
	"slices"
	"time"

	"stackd/compute/network"
	msk "stackd/internal/services/kafka"
)

// A flight exists only while its physical observation is running. Completed
// proof is never cached: the next read rechecks native policy and admission.
type statusFlight struct {
	done     chan struct{}
	request  msk.Specification
	observed []msk.BrokerNetwork
	endpoint msk.Endpoint
	err      error
}

func sameStatusIntent(a, b msk.Specification) bool {
	if a.ARN != b.ARN || a.Incarnation != b.Incarnation || a.Partition != b.Partition || a.AccountID != b.AccountID || a.Region != b.Region ||
		a.Brokers != b.Brokers || a.KafkaVersion != b.KafkaVersion || a.ServerProperties != b.ServerProperties || a.SecurityMode != b.SecurityMode ||
		a.DefaultMetrics != b.DefaultMetrics || !slices.Equal(a.Users, b.Users) || len(a.Networks) != len(b.Networks) {
		return false
	}
	for index, current := range a.Networks {
		previous := b.Networks[index]
		if current.InterfaceID != previous.InterfaceID || current.SubnetID != previous.SubnetID || current.AvailabilityZone != previous.AvailabilityZone ||
			current.Network.NetworkID != previous.Network.NetworkID || current.Network.Pool != previous.Network.Pool || current.Network.Gateway != previous.Network.Gateway ||
			current.Network.Address != previous.Network.Address || current.Network.MAC != previous.Network.MAC {
			return false
		}
	}
	return true
}

func (d *Docker) Status(ctx context.Context, spec msk.Specification) (msk.Endpoint, error) {
	return d.status(ctx, spec, d.statusOnce)
}

// observe is supplied explicitly so concurrency regressions exercise the real
// flight/gate/authority algorithm without substituting a fake public endpoint.
func (d *Docker) status(ctx context.Context, spec msk.Specification, observe func(context.Context, msk.Specification) (msk.Endpoint, error)) (msk.Endpoint, error) {
	key := resourceName(spec, "status")
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return msk.Endpoint{}, err
		}
		d.statusMu.Lock()
		flight := d.statusFlights[key]
		joined := flight != nil && sameStatusIntent(spec, flight.request)
		if !joined {
			flight = &statusFlight{done: make(chan struct{}), request: spec, observed: make([]msk.BrokerNetwork, len(spec.Networks))}
			flight.request.Users = slices.Clone(spec.Users)
			flight.request.Networks = slices.Clone(spec.Networks)
			if d.statusFlights == nil {
				d.statusFlights = make(map[string]*statusFlight)
			}
			d.statusFlights[key] = flight
		}
		d.statusMu.Unlock()
		if !joined {
			observedSpec := spec
			if spec.RefreshNetwork != nil {
				observedSpec.RefreshNetwork = func(call context.Context, index int) (msk.BrokerNetwork, error) {
					current, err := spec.RefreshNetwork(call, index)
					if err == nil {
						flight.observed[index] = current
						flight.observed[index].Network = cloneObservedNetwork(current.Network)
					}
					return current, err
				}
			}
			flight.endpoint, flight.err = observe(ctx, observedSpec)
			d.statusMu.Lock()
			if d.statusFlights[key] == flight {
				delete(d.statusFlights, key)
			}
			close(flight.done)
			d.statusMu.Unlock()
			return flight.endpoint, flight.err
		}
		select {
		case <-ctx.Done():
			return msk.Endpoint{}, ctx.Err()
		case <-flight.done:
		}
		if flight.err != nil {
			// Cancellation of a different caller is not this caller's authority or
			// readiness result. At most one fresh physical observation may retry it.
			if ctx.Err() == nil && (errors.Is(flight.err, context.Canceled) || errors.Is(flight.err, context.DeadlineExceeded)) {
				continue
			}
			return msk.Endpoint{}, flight.err
		}
		same, err := d.verifyStatusCaller(ctx, spec, flight.observed)
		if err != nil {
			return msk.Endpoint{}, err
		}
		if same {
			return flight.endpoint, nil
		}
	}
	return msk.Endpoint{}, errors.Join(errors.New("native Kafka current observation changed during concurrent status verification"), d.Quarantine(ctx, spec))
}

func (d *Docker) verifyStatusCaller(ctx context.Context, spec msk.Specification, observed []msk.BrokerNetwork) (bool, error) {
	if err := d.lock(ctx); err != nil {
		return false, err
	}
	defer d.unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if len(spec.Networks) == 0 {
		return true, nil
	}
	if spec.RefreshNetwork == nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		return false, errors.Join(errors.New("native Kafka status requires current EC2 observation"), d.quarantineLocked(cleanup, spec))
	}
	for index := range spec.Networks {
		current, err := spec.RefreshNetwork(ctx, index)
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			err = errors.Join(err, d.quarantineLocked(cleanup, spec))
			cancel()
			return false, err
		}
		previous := observed[index]
		if current.InterfaceID != previous.InterfaceID || current.SubnetID != previous.SubnetID || current.AvailabilityZone != previous.AvailabilityZone || !equalObservedNetwork(current.Network, previous.Network) {
			return false, nil
		}
	}
	return true, nil
}

func equalObservedNetwork(a, b network.Specification) bool {
	if a.NetworkID != b.NetworkID || a.Pool != b.Pool || a.Gateway != b.Gateway || a.Address != b.Address || a.MAC != b.MAC ||
		a.NetBIOSNodeType != b.NetBIOSNodeType || a.DomainName != b.DomainName || a.Hostname != b.Hostname || a.PublicHostname != b.PublicHostname || a.DNSSupport != b.DNSSupport ||
		!slices.Equal(a.DNS, b.DNS) || !slices.Equal(a.NTPServers, b.NTPServers) || !slices.Equal(a.NetBIOSServers, b.NetBIOSServers) || !a.Policy.Equal(b.Policy) || len(a.ServiceEndpoints) != len(b.ServiceEndpoints) {
		return false
	}
	for index, endpoint := range a.ServiceEndpoints {
		other := b.ServiceEndpoints[index]
		if endpoint.ID != other.ID || endpoint.Service != other.Service || endpoint.Kind != other.Kind || endpoint.PrivateDNS != other.PrivateDNS || !equalObservedNetwork(endpoint.Network, other.Network) {
			return false
		}
	}
	return true
}

// Only a new flight copies its observed inputs. A later caller may receive
// reused backing slices from an owner; that must not rewrite an earlier proof.
func cloneObservedNetwork(value network.Specification) network.Specification {
	value.DNS = slices.Clone(value.DNS)
	value.NTPServers = slices.Clone(value.NTPServers)
	value.NetBIOSServers = slices.Clone(value.NetBIOSServers)
	value.Policy.SecurityIngress = slices.Clone(value.Policy.SecurityIngress)
	value.Policy.SecurityEgress = slices.Clone(value.Policy.SecurityEgress)
	value.Policy.ACLIngress = slices.Clone(value.Policy.ACLIngress)
	value.Policy.ACLEgress = slices.Clone(value.Policy.ACLEgress)
	value.Policy.PrivateRoutes = slices.Clone(value.Policy.PrivateRoutes)
	value.Policy.NATRoutes = slices.Clone(value.Policy.NATRoutes)
	for index := range value.Policy.NATRoutes {
		value.Policy.NATRoutes[index].Ingress = slices.Clone(value.Policy.NATRoutes[index].Ingress)
		value.Policy.NATRoutes[index].Egress = slices.Clone(value.Policy.NATRoutes[index].Egress)
	}
	value.ServiceEndpoints = slices.Clone(value.ServiceEndpoints)
	for index := range value.ServiceEndpoints {
		value.ServiceEndpoints[index].Network = cloneObservedNetwork(value.ServiceEndpoints[index].Network)
	}
	return value
}
