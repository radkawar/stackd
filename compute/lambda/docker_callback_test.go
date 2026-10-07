package lambda

import (
	"context"
	"reflect"
	"testing"
)

func TestDesktopCallbackKeepsContainerDNS(t *testing.T) {
	// A cancelled context proves Desktop's special name is not resolved through
	// controller DNS. The daemon, not the Mac controller, owns this DNS record.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	host, extraHosts, err := callbackNetwork(ctx, "owned", "host.docker.internal")
	if err != nil || host != "host.docker.internal" {
		t.Fatalf("Desktop callback was resolved on the controller: host=%q err=%v", host, err)
	}
	if !reflect.DeepEqual(extraHosts, []string{"sandbox.localdomain:127.0.0.1"}) {
		t.Fatalf("Desktop host DNS was shadowed: %v", extraHosts)
	}
}

func TestLinuxAndExplicitCallbackMappings(t *testing.T) {
	for _, test := range []struct {
		callback, gateway string
	}{
		{"", "host-gateway"},
		{"192.0.2.20", "192.0.2.20"},
	} {
		host, extraHosts, err := callbackNetwork(t.Context(), "owned", test.callback)
		want := []string{"sandbox.localdomain:127.0.0.1", "owned.runtime.internal:" + test.gateway, "host.docker.internal:" + test.gateway}
		if err != nil || host != "owned.runtime.internal" || !reflect.DeepEqual(extraHosts, want) {
			t.Fatalf("callback %q changed native mapping: host=%q hosts=%v err=%v", test.callback, host, extraHosts, err)
		}
	}
}
