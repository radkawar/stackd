package kafka

import (
	"errors"
	"net"
	"testing"

	"stackd/compute/ports"
)

func TestBrokerPublicPoolAndPrivateAdminReservations(t *testing.T) {
	placeholder, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(placeholder.Addr().(*net.TCPAddr).Port)
	placeholder.Close()
	d := &Docker{endpointHost: "127.0.0.1", portRange: ports.Range{First: port, Last: port}}
	m := &material{}
	held, err := d.reserveBrokerPorts(t.Context(), 1, m)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, listener := range held {
			listener.Close()
		}
	}()
	if m.Nodes[0].Client != int(port) || m.Nodes[0].Admin == int(port) {
		t.Fatalf("public/private reservations: %+v", m.Nodes)
	}
	if err := m.validatePorts(); err != nil {
		t.Fatal(err)
	}
	if listener, err := d.portRange.Listen(t.Context(), d.endpointHost, 0); !errors.Is(err, ports.ErrExhausted) {
		if listener != nil {
			listener.Close()
		}
		t.Fatalf("public listener was not held: %v", err)
	}
	// A changed pool must not reinterpret or invalidate exact native material.
	d.portRange = ports.Range{First: 1, Last: 1}
	if err := m.validatePorts(); err != nil {
		t.Fatalf("retained outside-pool ports: %v", err)
	}
}

func TestBrokerPartialPoolExhaustionReleasesClaims(t *testing.T) {
	placeholder, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(placeholder.Addr().(*net.TCPAddr).Port)
	placeholder.Close()
	d := &Docker{endpointHost: "127.0.0.1", portRange: ports.Range{First: port, Last: port}}
	if held, err := d.reserveBrokerPorts(t.Context(), 2, &material{}); !errors.Is(err, ports.ErrExhausted) || len(held) != 0 {
		for _, listener := range held {
			listener.Close()
		}
		t.Fatalf("two public brokers in one slot: held=%d err=%v", len(held), err)
	}
	listener, err := d.portRange.Listen(t.Context(), d.endpointHost, 0)
	if err != nil {
		t.Fatalf("partial allocation leaked its socket: %v", err)
	}
	listener.Close()
}

func TestRetainedBrokerPortValidation(t *testing.T) {
	for _, nodes := range [][]nodePorts{{{Client: 0, Admin: 1}}, {{Client: 1, Admin: 65536}}, {{Client: 1, Admin: 1}}, {{Client: 1, Admin: 2}, {Client: 3, Admin: 2}}} {
		if err := (&material{Nodes: nodes}).validatePorts(); err == nil {
			t.Errorf("invalid retained ports accepted: %+v", nodes)
		}
	}
	if err := (&material{Nodes: []nodePorts{{Client: 65535, Admin: 1}}}).validatePorts(); err != nil {
		t.Fatalf("inclusive retained boundary: %v", err)
	}
}
