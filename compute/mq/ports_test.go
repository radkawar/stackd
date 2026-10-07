package mq

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"stackd/compute/ports"
	service "stackd/internal/services/mq"
)

func TestNativeMQPoolExhaustionAndExactRetainedEndpoint(t *testing.T) {
	placeholder, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(placeholder.Addr().(*net.TCPAddr).Port)
	placeholder.Close()
	r := &Runtime{config: Config{PortRange: ports.Range{First: port, Last: port}}}
	got, release, err := r.reserveNativePort(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if got != strconv.Itoa(int(port)) {
		t.Fatalf("allocated %s; want %d", got, port)
	}
	if _, release, err := r.reserveNativePort(t.Context(), ""); !errors.Is(err, ports.ErrExhausted) {
		if release != nil {
			release()
		}
		t.Fatalf("second protocol/management socket escaped full pool: %v", err)
	}
	release()
	r.config.PortRange = ports.Range{First: 1, Last: 1}
	retained := "amqps://127.0.0.1:" + got
	exact, releaseExact, err := r.reserveNativePort(t.Context(), retained)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseExact()
	if exact != got {
		t.Fatal("retained endpoint moved outside its original port")
	}
	if _, release, err := r.reserveNativePort(t.Context(), retained); err == nil || errors.Is(err, ports.ErrExhausted) {
		if release != nil {
			release()
		}
		t.Fatalf("competing explicit endpoint was substituted: %v", err)
	}
	for _, endpoint := range []string{"amqps://127.0.0.1:0", "amqps://127.0.0.1:65536", "amqps://example.com:5671", "amqps://127.0.0.1"} {
		if _, err := endpointPort(endpoint); err == nil {
			t.Errorf("invalid retained endpoint accepted: %s", endpoint)
		}
	}
}

func TestNativeMQPortsSurviveMissingContainerAndOwnerCommit(t *testing.T) {
	r := &Runtime{config: Config{Namespace: "installation", DataDir: t.TempDir()}}
	v := service.BrokerRecord{ARN: "arn:aws:mq:us-east-1:123456789012:broker:owned:id", ID: "id", Engine: "RABBITMQ", Endpoint: service.Endpoint{Address: "amqps://127.0.0.1:25000", ConsoleURL: "https://127.0.0.1:25001"}}
	dir := filepath.Join(r.config.DataDir, r.name(v))
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := atomicNativeFile(dir, "owner", []byte(v.ARN), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.persistNativePorts(v); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "ports.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private durable port record: %v", err)
	}
	retained := v
	retained.Endpoint = service.Endpoint{}
	if err := loadNativePorts(dir, &retained); err != nil {
		t.Fatal(err)
	}
	if retained.Endpoint.Address != v.Endpoint.Address || retained.Endpoint.ConsoleURL != v.Endpoint.ConsoleURL {
		t.Fatalf("missing typed endpoint did not recover exact native ports: %+v", retained.Endpoint)
	}
	conflicting := v
	conflicting.Endpoint.Address = "amqps://127.0.0.1:25002"
	if err := loadNativePorts(dir, &conflicting); err == nil {
		t.Fatal("conflicting retained endpoint replaced native record")
	}
	foreign := v
	foreign.ID = "replacement-incarnation"
	if err := loadNativePorts(dir, &foreign); err == nil {
		t.Fatal("foreign owner adopted native ports")
	}
	if err := removeNativeConfiguration(dir); err != nil {
		t.Fatalf("owned cleanup left port record: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("native directory remains: %v", err)
	}
}

func TestStoppedMQBindingsPreserveProtocolAndConsolePorts(t *testing.T) {
	v := service.BrokerRecord{Engine: "ACTIVEMQ", Endpoint: service.Endpoint{Address: "ssl://127.0.0.1:25000"}}
	var stopped inspection
	stopped.HostConfig.PortBindings = map[string][]struct{ HostIP, HostPort string }{
		"61617/tcp":         {{HostIP: "127.0.0.1", HostPort: "25000"}},
		activeMQConsolePort: {{HostIP: "127.0.0.1", HostPort: "25001"}},
	}
	if err := retainNativePorts(&v, stopped); err != nil {
		t.Fatal(err)
	}
	if v.Endpoint.Address != "ssl://127.0.0.1:25000" || v.Endpoint.ConsoleURL != "https://127.0.0.1:25001" {
		t.Fatalf("stopped bindings lost retained endpoints: %+v", v.Endpoint)
	}
}
