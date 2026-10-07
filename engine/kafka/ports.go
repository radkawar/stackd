package kafka

import (
	"context"
	"errors"
	"net"

	"stackd/compute/ports"
)

// Public clients use the configured pool; controller-only TLS administration
// stays private ephemeral. Both are persisted in native material before start.
func (d *Docker) reserveBrokerPorts(ctx context.Context, brokers int32, m *material) ([]net.Listener, error) {
	m.Nodes = make([]nodePorts, brokers)
	held := make([]net.Listener, int(brokers)*2)
	fail := func(err error) ([]net.Listener, error) {
		for _, listener := range held {
			if listener != nil {
				listener.Close()
			}
		}
		return nil, err
	}
	// Reserve all public sockets before private ephemeral allocation, so private
	// ports cannot consume a not-yet-reserved customer slot in a narrow pool.
	for node := range m.Nodes {
		listener, err := d.portRange.Listen(ctx, d.endpointHost, 0)
		if err != nil {
			return fail(err)
		}
		held[node*2] = listener
		m.Nodes[node].Client = listener.Addr().(*net.TCPAddr).Port
	}
	for node := range m.Nodes {
		listener, err := (ports.Range{}).Listen(ctx, d.endpointHost, 0)
		if err != nil {
			return fail(err)
		}
		held[node*2+1] = listener
		m.Nodes[node].Admin = listener.Addr().(*net.TCPAddr).Port
	}
	return held, nil
}

func (m *material) validatePorts() error {
	seen := make(map[int]bool, len(m.Nodes)*2)
	for _, node := range m.Nodes {
		for _, port := range [...]int{node.Client, node.Admin} {
			if port < 1 || port > 65535 || seen[port] {
				return errors.New("MSK retained native ports are invalid or duplicated")
			}
			seen[port] = true
		}
	}
	return nil
}
