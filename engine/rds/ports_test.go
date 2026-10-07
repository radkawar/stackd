package rds

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"stackd/compute/ports"
)

func TestRetainedSQLPortFromStoppedBindings(t *testing.T) {
	var stopped containerState
	stopped.HostConfig.PortBindings = map[string][]portBinding{"5432/tcp": {{HostIP: "127.0.0.1", HostPort: "15432"}}}
	if port, err := stopped.retainedPort("postgres"); err != nil || port != 15432 {
		t.Fatalf("logical SQL port confused with retained published port: %d, %v", port, err)
	}
	stopped.HostConfig.PortBindings["5432/tcp"][0].HostPort = ""
	if _, err := stopped.retainedPort("postgres"); err == nil {
		t.Fatal("missing legacy dynamic port was invented")
	}
	stopped.NetworkSettings.Ports = map[string][]portBinding{"5432/tcp": {{HostIP: "127.0.0.1", HostPort: "15432"}}}
	if port, err := stopped.retainedPort("postgres"); err != nil || port != 15432 {
		t.Fatalf("legacy published SQL port not retained: %d, %v", port, err)
	}
}

func TestNativePortPoolBoundariesAndRetainedReplacement(t *testing.T) {
	d := nativeRuntime(t)
	placeholder, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(placeholder.Addr().(*net.TCPAddr).Port)
	placeholder.Close()
	d.portRange = ports.Range{First: port, Last: port}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	spec := Specification{ID: rand.Text(), Engine: "postgres", Database: "appdb", Username: "master", Password: rand.Text()}
	other := spec
	other.ID = rand.Text()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, id := range []string{spec.ID, other.ID} {
			if err := d.Delete(cleanup, id); err != nil {
				t.Error(err)
			}
		}
		d.Close()
	})
	endpoint, err := d.Ensure(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Port != int32(port) {
		t.Fatalf("native port %d escaped singleton pool %d", endpoint.Port, port)
	}
	db, err := Open(ctx, spec.Engine, endpoint, spec.Database, spec.Username, spec.Password)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{"CREATE TABLE pool_retained (value INTEGER)", "INSERT INTO pool_retained VALUES (42)"} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	db.Close()
	if _, err := d.Ensure(ctx, other); !errors.Is(err, ports.ErrExhausted) {
		t.Fatalf("full native pool: %v", err)
	}
	if err := d.Stop(ctx, spec.ID); err != nil {
		t.Fatal(err)
	}
	spec.Parameters = map[string]string{"max_connections": "101"}
	retained, err := d.Ensure(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if retained.Port != endpoint.Port {
		t.Fatal("static replacement moved stopped SQL listener")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDocker(DockerConfig{Host: os.Getenv("DOCKER_HOST"), Namespace: d.namespace, PortRange: ports.Range{First: 1, Last: 1}})
	if err != nil {
		t.Fatal(err)
	}
	d = reopened
	state, err := d.inspect(ctx, d.name(spec.ID, "database"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.client.RemoveContainer(ctx, state.ID); err != nil {
		t.Fatal(err)
	}
	retained, err = d.Ensure(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if retained.Port != endpoint.Port {
		t.Fatal("reopen/missing-container recovery moved retained port outside new pool")
	}
	db, err = Open(ctx, spec.Engine, retained, spec.Database, spec.Username, spec.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var value int
	if err := db.QueryRowContext(ctx, "SELECT value FROM pool_retained").Scan(&value); err != nil || value != 42 {
		t.Fatalf("native replacement discarded SQL bytes: value=%d err=%v", value, err)
	}
	if volume, err := d.volume(ctx, other.ID, "data", nil, false); !dockerStatus(err, http.StatusNotFound) {
		t.Fatalf("exhaustion published a durable allocation: volume=%s err=%v", volume.Name, err)
	}
}
