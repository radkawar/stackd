package mq

import (
	"errors"
	"net"
	"net/url"
	service "stackd/internal/services/mq"
)

// Keep fresh ports reserved until Docker has accepted the immutable container
// configuration. Docker binds them at start, after the reservations are released;
// a competing host process causes a real startup error, never endpoint drift.
func reserveNativePort(endpoint string) (string, func(), error) {
	address := "127.0.0.1:0"
	if endpoint != "" {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.Port() == "0" {
			return "", nil, errors.New("invalid retained native MQ endpoint")
		}
		address = parsed.Host
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return "", nil, err
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		return "", nil, err
	}
	return port, func() { _ = listener.Close() }, nil
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
	if !native.State.Running && v.Endpoint.Address != "" {
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
