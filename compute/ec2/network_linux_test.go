package ec2

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"stackd/compute/docker"
	"stackd/compute/network"
)

func TestGuestLinksBoundedObservationAndOwnership(t *testing.T) {
	const arn = "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0"
	owned := guestLink{Name: guestTAP(arn), Alias: guestAlias(arn), Master: "br-owned"}
	owned.LinkInfo.Kind = "tun"
	owned.LinkInfo.Data.Type = "tap"
	owned.LinkInfo.Data.Persist = true
	owned.LinkInfo.Data.User = os.Getuid()
	marshal := func(links ...guestLink) []byte {
		t.Helper()
		data, err := json.Marshal(links)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	foreign := owned
	foreign.Alias = "stackd.ec2:foreign"
	large := owned
	large.Alias = strings.Repeat("unrelated-host-link", 5<<10)
	for _, test := range []struct {
		name    string
		stdout  []byte
		stderr  string
		exit    int
		prepare bool
		want    int
		err     string
	}{
		{name: "owned", stdout: marshal(owned), want: 1},
		{name: "absent", stdout: []byte("[]")},
		{name: "large-owned-output-still-rejected", stdout: marshal(large), err: "output exceeds 64 KiB"},
		{name: "native-failure-retains-diagnostic", stderr: "Cannot open netlink socket: Permission denied\n", exit: 2, err: "Permission denied"},
		{name: "foreign-owned-name-is-not-adopted", stdout: marshal(foreign), prepare: true, err: "existing native TAP identity/bridge/owner differs"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := r.URL.Path
				if strings.HasPrefix(path, "/v1.") {
					_, path, _ = strings.Cut(path[1:], "/")
					path = "/" + path
				}
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == "GET" && path == "/version":
					_ = json.NewEncoder(w).Encode(map[string]any{"ApiVersion": "1.48", "MinAPIVersion": "1.41", "Os": "linux"})
				case r.Method == "GET" && path == "/info":
					_ = json.NewEncoder(w).Encode(map[string]bool{"MemoryLimit": true, "SwapLimit": true, "CPUCfsQuota": true, "CPUCfsPeriod": true})
				case r.Method == "POST" && path == "/containers/create":
					var config docker.ContainerConfig
					if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
						t.Error(err)
						http.Error(w, "invalid helper input", http.StatusBadRequest)
						return
					}
					if config.Labels[guestNetworkLabel] != arn {
						t.Error("native helper lost its exact instance owner")
					}
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(map[string]string{"Id": "owned-helper"})
				case r.Method == "POST" && strings.HasSuffix(path, "/start"):
					w.WriteHeader(http.StatusNoContent)
				case r.Method == "POST" && strings.HasSuffix(path, "/wait"):
					_ = json.NewEncoder(w).Encode(map[string]int{"StatusCode": test.exit})
				case r.Method == "GET" && strings.HasSuffix(path, "/logs"):
					w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
					frame := func(stream byte, data []byte) {
						if len(data) == 0 {
							return
						}
						var header [8]byte
						header[0] = stream
						binary.BigEndian.PutUint32(header[4:], uint32(len(data)))
						_, _ = w.Write(header[:])
						_, _ = w.Write(data)
					}
					frame(1, test.stdout)
					frame(2, []byte(test.stderr))
				case r.Method == "DELETE" && strings.HasPrefix(path, "/containers/"):
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected Docker helper request %s %s", r.Method, r.URL)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			engine, err := docker.New(context.Background(), docker.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			manager := &GuestNetworkManager{config: GuestNetworkConfig{Docker: engine}}
			if test.prepare {
				err = manager.prepareTAP(context.Background(), &guestAttachment{arn: arn, tap: guestTAP(arn), bridge: network.Bridge{Device: "br-owned"}})
			} else {
				var links []guestLink
				links, err = manager.links(context.Background(), arn)
				if test.err == "" && (len(links) != test.want || len(links) != 0 && links[0].Name != guestTAP(arn)) {
					t.Fatalf("owned link observation differs: %#v", links)
				}
			}
			if test.err == "" && err != nil || test.err != "" && (err == nil || !strings.Contains(err.Error(), test.err)) {
				t.Fatalf("helper result %v, want error containing %q", err, test.err)
			}
		})
	}
}
