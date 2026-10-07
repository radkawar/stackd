package valkey

import (
	"errors"
	"net"
	"testing"

	"stackd/compute/ports"
)

func TestManifestUsesPublicPoolAndPrivateClusterBus(t *testing.T) {
	for _, cluster := range []bool{false, true} {
		t.Run(map[bool]string{false: "standalone", true: "cluster"}[cluster], func(t *testing.T) {
			placeholder, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := uint16(placeholder.Addr().(*net.TCPAddr).Port)
			placeholder.Close()
			d := &Docker{portRange: ports.Range{First: port, Last: port}}
			m, held, err := d.newManifest(t.Context(), Specification{ID: "incarnation", Shards: 1, ClusterMode: cluster})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, listener := range held {
					listener.Close()
				}
			}()
			if m.Nodes[0].Port != int32(port) {
				t.Fatalf("public port outside pool: %+v", m.Nodes)
			}
			if cluster && (m.Nodes[0].BusPort == 0 || m.Nodes[0].BusPort == m.Nodes[0].Port) {
				t.Fatalf("missing/distinct private cluster bus: %+v", m.Nodes)
			}
			if !cluster && (m.Nodes[0].BusPort != 0 || len(held) != 1) {
				t.Fatal("unused standalone bus reservation")
			}
			if err := m.validatePorts(); err != nil {
				t.Fatal(err)
			}
			if listener, err := d.portRange.Listen(t.Context(), "127.0.0.1", 0); !errors.Is(err, ports.ErrExhausted) {
				if listener != nil {
					listener.Close()
				}
				t.Fatalf("public reservation not held: %v", err)
			}
			d.portRange = ports.Range{First: 1, Last: 1}
			if err := m.validatePorts(); err != nil {
				t.Fatalf("retained outside-pool ports: %v", err)
			}
		})
	}
}

func TestManifestPoolExhaustionReleasesPartialClaims(t *testing.T) {
	placeholder, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(placeholder.Addr().(*net.TCPAddr).Port)
	placeholder.Close()
	d := &Docker{portRange: ports.Range{First: port, Last: port}}
	if _, held, err := d.newManifest(t.Context(), Specification{ID: "incarnation", Shards: 1, Replicas: 1}); !errors.Is(err, ports.ErrExhausted) || len(held) != 0 {
		for _, listener := range held {
			listener.Close()
		}
		t.Fatalf("two nodes in one slot: held=%d err=%v", len(held), err)
	}
	listener, err := d.portRange.Listen(t.Context(), "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("exhaustion leaked public reservation: %v", err)
	}
	listener.Close()
}

func TestRetainedManifestPorts(t *testing.T) {
	for _, m := range []manifest{
		{Nodes: []nativeNode{{Port: 0}}},
		{Nodes: []nativeNode{{Port: 65536}}},
		{ClusterMode: true, Nodes: []nativeNode{{Port: 1}}},
		{ClusterMode: true, Nodes: []nativeNode{{Port: 1, BusPort: 1}}},
		{Nodes: []nativeNode{{Port: 1}, {Port: 1}}},
	} {
		if err := m.validatePorts(); err == nil {
			t.Errorf("invalid native manifest accepted: %+v", m)
		}
	}
	for _, m := range []manifest{
		{Nodes: []nativeNode{{Port: 65535}}},
		{Nodes: []nativeNode{{Port: 1, BusPort: 65535}}}, // old standalone metadata
		{ClusterMode: true, Nodes: []nativeNode{{Port: 65535, BusPort: 1}}},
	} {
		if err := m.validatePorts(); err != nil {
			t.Errorf("retained port boundary rejected: %v", err)
		}
	}
}
