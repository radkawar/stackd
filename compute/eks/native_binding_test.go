package eks

import (
	"encoding/json"
	"testing"
)

func TestNativeAPIBindingDockerRepresentations(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "192.0.2.10"} {
		state := diskState{NativePort: 18443}
		if host != "127.0.0.1" {
			state.WorkerAdvertiseHost = host
		}
		for _, key := range []string{"6443", "6443/tcp"} {
			t.Run(host+"/"+key, func(t *testing.T) {
				// The bare key is k3d v5.8.3's actual --no-lb create request;
				// Docker can return either spelling without changing exposure.
				raw := `{"HostConfig":{"PortBindings":{"` + key + `":[{"HostIp":"` + host + `","HostPort":"18443"}]}}}`
				var container dockerContainer
				if err := json.Unmarshal([]byte(raw), &container); err != nil {
					t.Fatal(err)
				}
				if !nativeAPIBindingMatches(state, container.HostConfig.PortBindings) {
					t.Fatal("exact retained endpoint rejected")
				}
			})
		}
	}
}

func TestNativeAPIBindingRejectsEndpointDrift(t *testing.T) {
	state := diskState{NativePort: 18443}
	exact := dockerPortBinding{HostIP: "127.0.0.1", HostPort: "18443"}
	for _, key := range []string{"6443", "6443/tcp"} {
		for _, tc := range []struct {
			name     string
			bindings []dockerPortBinding
		}{
			{"missing", nil},
			{"duplicate", []dockerPortBinding{exact, exact}},
			{"wildcard", []dockerPortBinding{{HostIP: "0.0.0.0", HostPort: "18443"}}},
			{"implicit wildcard", []dockerPortBinding{{HostPort: "18443"}}},
			{"foreign host", []dockerPortBinding{{HostIP: "192.0.2.10", HostPort: "18443"}}},
			{"other loopback", []dockerPortBinding{{HostIP: "127.0.0.2", HostPort: "18443"}}},
			{"IPv6 loopback", []dockerPortBinding{{HostIP: "::1", HostPort: "18443"}}},
			{"wrong port", []dockerPortBinding{{HostIP: "127.0.0.1", HostPort: "18444"}}},
			{"ephemeral port", []dockerPortBinding{{HostIP: "127.0.0.1"}}},
			{"port range", []dockerPortBinding{{HostIP: "127.0.0.1", HostPort: "18443-18444"}}},
		} {
			t.Run(key+"/"+tc.name, func(t *testing.T) {
				if nativeAPIBindingMatches(state, map[string][]dockerPortBinding{key: tc.bindings}) {
					t.Fatal("non-exact API binding accepted")
				}
			})
		}
	}
	for _, extra := range []dockerPortBinding{exact, {HostIP: "0.0.0.0", HostPort: "18443"}, {HostIP: "127.0.0.1", HostPort: "18444"}} {
		ports := map[string][]dockerPortBinding{"6443": {exact}, "6443/tcp": {extra}}
		if nativeAPIBindingMatches(state, ports) {
			t.Fatal("second API alias binding accepted")
		}
	}
	if nativeAPIBindingMatches(state, map[string][]dockerPortBinding{"6443/udp": {exact}}) {
		t.Fatal("UDP publication accepted as the TCP API endpoint")
	}
}
