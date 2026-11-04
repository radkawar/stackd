package rds

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDockerPublishAddressConfiguration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/version":
			_, _ = w.Write([]byte(`{"ApiVersion":"1.44","MinAPIVersion":"1.41","Os":"linux"}`))
		case r.URL.Path == "/v1.44/info":
			_, _ = w.Write([]byte(`{"MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`))
		case strings.HasPrefix(r.URL.Path, "/v1.44/images/") && strings.HasSuffix(r.URL.Path, "/json"):
			_, _ = w.Write([]byte(`{"Id":"installed-image","Os":"linux"}`))
		default:
			t.Errorf("unexpected Docker request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	for _, test := range []struct {
		address, want string
	}{
		{"", "127.0.0.1"},
		{"127.0.0.1", "127.0.0.1"},
		{"172.17.0.1", "172.17.0.1"},
		{"0.0.0.0", "0.0.0.0"},
		{"::", "::"},
		{"0:0:0:0:0:0:0:1", "::1"},
	} {
		t.Run(test.address, func(t *testing.T) {
			d, err := NewDocker(DockerConfig{Host: server.URL, Namespace: "publication-test", PublishAddress: test.address})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if d.publishAddress != test.want || d.endpointHost != "127.0.0.1" {
				t.Fatalf("bind=%q endpoint=%q; want bind=%q and unchanged default endpoint", d.publishAddress, d.endpointHost, test.want)
			}
		})
	}
	for _, address := range []string{"localhost", "172.17.0.1:5432", "[::1]", " 127.0.0.1", "127.0.0.1/8", "not-an-ip"} {
		if d, err := NewDocker(DockerConfig{Host: server.URL, Namespace: "publication-test", PublishAddress: address}); err == nil {
			d.Close()
			t.Fatalf("accepted invalid publish address %q", address)
		}
	}
}

func TestPublishedSQLBindings(t *testing.T) {
	for _, engine := range []string{"postgres", "aurora-postgresql", "mysql", "aurora-mysql"} {
		for _, address := range []string{"127.0.0.1", "172.17.0.1", "0.0.0.0", "::1"} {
			t.Run(engine+"/"+address, func(t *testing.T) {
				d := &Docker{namespace: "publication-test", publishAddress: address, endpointHost: "database.stackd.test", postgresImage: "postgres-image", mysqlImage: "mysql-image"}
				spec := Specification{ID: "database", Engine: engine, Username: "owner", Port: 40123}
				config := d.databaseConfig(spec)
				wire, mount, _ := nativeLayout(engine)
				bindings := config.HostConfig.PortBindings[wire]
				if len(config.HostConfig.PortBindings) != 1 || len(bindings) != 1 || bindings[0].HostIP != address || bindings[0].HostPort != "40123" {
					t.Fatalf("wrong published mapping: %+v", config.HostConfig.PortBindings)
				}
				var state containerState
				state.Image = config.Image
				state.Config.Labels = config.Labels
				state.Config.Entrypoint = config.Entrypoint
				state.Config.Cmd = config.Cmd
				state.HostConfig.NetworkMode = config.HostConfig.NetworkMode
				state.HostConfig.PortBindings = config.HostConfig.PortBindings
				state.NetworkSettings.Ports = map[string][]portBinding{wire: {{HostIP: address, HostPort: "40123"}}}
				state.Mounts = append(state.Mounts, struct {
					Type, Name, Destination string
					RW                      bool
				}{Type: "volume", Name: d.name(spec.ID, "data"), Destination: mount, RW: true})
				if err := d.checkDatabase(state, spec); err != nil {
					t.Fatal(err)
				}
				endpoint, err := state.endpoint(d.endpointHost, d.publishAddress, engine)
				if err != nil || endpoint.Address != d.endpointHost || endpoint.Port != spec.Port {
					t.Fatalf("advertised address confused with bind address: %+v, %v", endpoint, err)
				}
				state.NetworkSettings.Ports = nil
				if port, err := state.retainedPort(d.publishAddress, engine); err != nil || port != spec.Port {
					t.Fatalf("stopped configured binding lost its port: %d, %v", port, err)
				}
				state.HostConfig.PortBindings[wire][0].HostPort = "0"
				state.NetworkSettings.Ports = map[string][]portBinding{wire: {{HostIP: address, HostPort: "40123"}}}
				if port, err := state.retainedPort(d.publishAddress, engine); err != nil || port != spec.Port {
					t.Fatalf("legacy dynamic configured binding lost its port: %d, %v", port, err)
				}
				state.HostConfig.PortBindings[wire][0].HostIP = "192.0.2.10"
				state.NetworkSettings.Ports[wire][0].HostIP = "192.0.2.10"
				if err := d.checkDatabase(state, spec); err == nil {
					t.Fatal("reattached database on an unconfigured bind address")
				}
				if _, err := state.endpoint(d.endpointHost, d.publishAddress, engine); err == nil {
					t.Fatal("advertised endpoint on an unconfigured bind address")
				}
				if _, err := state.retainedPort(d.publishAddress, engine); err == nil {
					t.Fatal("retained port from an unconfigured bind address")
				}
				state.HostConfig.PortBindings[wire] = []portBinding{{HostIP: address, HostPort: "40123"}, {HostIP: address, HostPort: "40124"}}
				state.NetworkSettings.Ports[wire] = state.HostConfig.PortBindings[wire]
				if err := d.checkDatabase(state, spec); err == nil {
					t.Fatal("accepted multiple SQL publications")
				}
				if _, err := state.endpoint(d.endpointHost, d.publishAddress, engine); err == nil {
					t.Fatal("advertised ambiguous SQL publications")
				}
			})
		}
	}
}

func TestNativePostgresPublishedAddress(t *testing.T) {
	d := nativeRuntime(t)
	d.publishAddress = "0.0.0.0"
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	spec := Specification{ID: rand.Text(), Engine: "postgres", Database: "appdb", Username: "owner", Password: rand.Text()}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := d.Delete(cleanup, spec.ID); err != nil {
			t.Error(err)
		}
	})
	endpoint, err := d.Ensure(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	state, err := d.inspect(ctx, d.name(spec.ID, "database"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.checkDatabase(state, spec); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, spec.Engine, endpoint, spec.Database, spec.Username, spec.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var encrypted bool
	if err := db.QueryRowContext(ctx, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&encrypted); err != nil || !encrypted {
		t.Fatalf("published PostgreSQL did not use verified TLS: ssl=%t err=%v", encrypted, err)
	}
	if err := plaintextPostgres(ctx, endpoint, spec); err == nil {
		t.Fatal("published PostgreSQL accepted plaintext despite force_ssl default")
	}
	wrong := endpoint
	wrong.Address = "localhost"
	if invalid, err := Open(ctx, spec.Engine, wrong, spec.Database, spec.Username, spec.Password); err == nil {
		invalid.Close()
		t.Fatal("published PostgreSQL accepted a host absent from its SANs")
	}
}
