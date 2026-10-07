package mq

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	service "stackd/internal/services/mq"
	"strconv"
)

// Keep fresh ports reserved until Docker has accepted the immutable container
// configuration. Docker binds them at start, after the reservations are released;
// a competing host process causes a real startup error, never endpoint drift.
func (r *Runtime) reserveNativePort(ctx context.Context, endpoint string) (string, func(), error) {
	requested, err := endpointPort(endpoint)
	if err != nil {
		return "", nil, err
	}
	listener, err := r.config.PortRange.Listen(ctx, "127.0.0.1", requested)
	if err != nil {
		return "", nil, err
	}
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	return port, func() { _ = listener.Close() }, nil
}

func endpointPort(endpoint string) (uint16, error) {
	if endpoint == "" {
		return 0, nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" {
		return 0, errors.New("invalid retained native MQ endpoint")
	}
	value, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || value == 0 {
		return 0, errors.New("invalid retained native MQ endpoint port")
	}
	return uint16(value), nil
}

func nativeDynamicPorts(native inspection) bool {
	for _, bindings := range native.HostConfig.PortBindings {
		for _, binding := range bindings {
			if binding.HostPort == "" || binding.HostPort == "0" {
				return true
			}
		}
	}
	return false
}

func retainNativePorts(v *service.BrokerRecord, native inspection) error {
	if !native.State.Running && nativeDynamicPorts(native) && v.Endpoint.Address != "" {
		// Docker clears NetworkSettings ports while stopped. The durable
		// endpoint is then the source of truth for the one-time cutover.
		return nil
	}
	port, scheme := "5671/tcp", "amqps"
	if v.Engine == "ACTIVEMQ" {
		port, scheme = "61617/tcp", "ssl"
	}
	ports := native.NetworkSettings.Ports
	if !native.State.Running {
		ports = native.HostConfig.PortBindings
	}
	binding := ports[port]
	if len(binding) != 1 || binding[0].HostIP != "127.0.0.1" || binding[0].HostPort == "" || binding[0].HostPort == "0" {
		return errors.New("cannot preserve missing native MQ TLS endpoint")
	}
	v.Endpoint.Address = scheme + "://" + net.JoinHostPort("127.0.0.1", binding[0].HostPort)
	consolePort := "15671/tcp"
	if v.Engine == "ACTIVEMQ" {
		consolePort = activeMQConsolePort
	}
	if bindings := ports[consolePort]; len(bindings) != 0 {
		if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" || bindings[0].HostPort == "" || bindings[0].HostPort == "0" {
			return errors.New("cannot preserve native MQ management endpoint")
		}
		v.Endpoint.ConsoleURL = "https://" + net.JoinHostPort("127.0.0.1", bindings[0].HostPort)
	}
	return nil
}

// The private record precedes container creation and owner transaction commit.
// Losing a container or an interrupted API transition cannot reallocate ports.
type nativePortRecord struct {
	ARN, ID, Engine, Address, ConsoleURL string
}

func loadNativePorts(dir string, v *service.BrokerRecord) error {
	path := filepath.Join(dir, "ports.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("refusing non-regular MQ native port record")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var record nativePortRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return err
	}
	if record.ARN != v.ARN || record.ID != v.ID || record.Engine != v.Engine || record.Address == "" {
		return errors.New("conflicting MQ native port record owner")
	}
	if _, err := endpointPort(record.Address); err != nil {
		return err
	}
	if _, err := endpointPort(record.ConsoleURL); err != nil {
		return err
	}
	if (v.Endpoint.Address != "" && v.Endpoint.Address != record.Address) || (v.Endpoint.ConsoleURL != "" && v.Endpoint.ConsoleURL != record.ConsoleURL) {
		return errors.New("conflicting retained MQ native endpoints")
	}
	v.Endpoint.Address, v.Endpoint.ConsoleURL = record.Address, record.ConsoleURL
	return nil
}

func (r *Runtime) persistNativePorts(v service.BrokerRecord) error {
	dir, err := r.ownedDirectory(v)
	if err != nil {
		return err
	}
	data, err := json.Marshal(nativePortRecord{ARN: v.ARN, ID: v.ID, Engine: v.Engine, Address: v.Endpoint.Address, ConsoleURL: v.Endpoint.ConsoleURL})
	if err != nil {
		return err
	}
	return atomicNativeFile(dir, "ports.json", data, 0600)
}
