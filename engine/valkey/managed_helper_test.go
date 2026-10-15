package valkey

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"stackd/compute/docker"
)

func TestManagedInterruptedHelperCreateCleansOnlyExactOwnedConfiguration(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(*containerState)
		removed bool
	}{
		{name: "accepted-create-error", removed: true},
		{name: "foreign-account", mutate: func(s *containerState) { s.Config.Labels[labelPrefix+"account"] = "222222222222" }},
		{name: "replacement-incarnation", mutate: func(s *containerState) { s.Config.Labels[labelPrefix+"id"] = "replacement" }},
		{name: "foreign-purpose", mutate: func(s *containerState) { s.Config.Labels[labelPrefix+"role"] = "network-helper-2" }},
		{name: "foreign-image", mutate: func(s *containerState) { s.Image = "foreign-toolkit" }},
		{name: "foreign-host-mount", mutate: func(s *containerState) { s.HostConfig.Binds = []string{"/:/host"} }},
		{name: "foreign-command", mutate: func(s *containerState) { s.Config.Entrypoint = []string{"/bin/sh", "-ec", "unowned"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := &Docker{namespace: "test", image: "installed-valkey", toolkitImage: "installed-toolkit"}
			spec := managedTestSpec()
			var state containerState
			var mu sync.Mutex
			var removed atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				path := strings.TrimPrefix(r.URL.Path, "/v1.44")
				switch {
				case path == "/version":
					_, _ = w.Write([]byte(`{"ApiVersion":"1.44","MinAPIVersion":"1.41","Os":"linux"}`))
				case path == "/info":
					_, _ = w.Write([]byte(`{"MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`))
				case path == "/containers/create":
					var config docker.ContainerConfig
					if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
						t.Error(err)
						return
					}
					encoded, err := json.Marshal(map[string]any{"Id": "accepted-helper-id", "Image": d.toolkitImage, "Config": config, "HostConfig": config.HostConfig})
					if err != nil {
						t.Error(err)
						return
					}
					if err = json.Unmarshal(encoded, &state); err != nil {
						t.Error(err)
						return
					}
					if test.mutate != nil {
						test.mutate(&state)
					}
					// Docker accepted the native object, but the caller never gets a
					// successful create acknowledgement. Cleanup must still fence it.
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"message":"create acknowledgement lost"}`))
				case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
					_ = json.NewEncoder(w).Encode(state)
				case path == "/containers/accepted-helper-id" && r.Method == http.MethodDelete:
					removed.Store(true)
					w.WriteHeader(http.StatusNoContent)
				default:
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"message":"absent"}`))
				}
			}))
			t.Cleanup(server.Close)
			client, err := docker.New(t.Context(), docker.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			d.client = client
			if _, err := d.networkHelper(t.Context(), spec, 0, "container:exact-node-id", []string{"/bin/sh", "-ec", "read-exact-veth"}, []string{"MAC=" + spec.Networks[0].Network.MAC}); err == nil {
				t.Fatal("lost create acknowledgement manufactured native success")
			}
			if removed.Load() != test.removed {
				t.Fatalf("cleanup removed=%t, want=%t", removed.Load(), test.removed)
			}
		})
	}
}
