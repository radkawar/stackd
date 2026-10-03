package mq

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	service "stackd/internal/services/mq"
	"strings"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

func (r *Runtime) checkNativeStorage(ctx context.Context, v service.BrokerRecord, native inspection) error {
	dir, err := r.ownedDirectory(v)
	if err != nil {
		return err
	}
	volumeName := r.name(v) + "-data"
	var volume struct{ Labels map[string]string }
	if err = r.client.JSON(ctx, "GET", "/volumes/"+volumeName, nil, &volume); err != nil {
		return err
	}
	if err = r.check(volume.Labels, v); err != nil {
		return err
	}
	target := "/var/lib/rabbitmq"
	if v.Engine == "ACTIVEMQ" {
		target = "/opt/apache-activemq/data"
	}
	configuration, storage := false, false
	for _, mount := range native.Mounts {
		if mount.Destination == "/stackd" {
			configuration = mount.Type == "bind" && mount.Source == dir && !mount.RW
		}
		if mount.Destination == target {
			storage = mount.Type == "volume" && mount.Name == volumeName && mount.RW
		}
	}
	if !configuration || !storage {
		return errors.New("refusing MQ container with foreign native mounts")
	}
	return nil
}

func (r *Runtime) nativeReady(ctx context.Context, v service.BrokerRecord, endpoint service.Endpoint) error {
	dir, err := r.ownedDirectory(v)
	if err != nil {
		return err
	}
	if v.Engine == "ACTIVEMQ" {
		// Broker health is independent of customer destination permissions.
		// Even connection.start can emit server-side advisories that a valid
		// restrictive ACL denies. Negotiate OpenWire without creating a JMS
		// session or authenticating as a customer instead.
		if err = r.probeOpenWire(ctx, endpoint); err != nil {
			return err
		}
		return r.activeMQConsoleReady(ctx, endpoint)
	}
	if err = r.rabbitRunning(ctx, endpoint.NativeID); err != nil {
		return err
	}
	if endpoint.ConsoleURL != "" {
		transport := &http.Transport{TLSClientConfig: r.tls}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		request, err := http.NewRequestWithContext(ctx, "GET", endpoint.ConsoleURL+"/api/overview", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("RabbitMQ HTTPS management readiness: %w", err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			return errors.New("RabbitMQ management API is not enforcing authentication")
		}
	}
	info, err := os.Lstat(filepath.Join(dir, "rabbitmq.conf"))
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("refusing non-regular RabbitMQ configuration")
	}
	config, err := os.ReadFile(filepath.Join(dir, "rabbitmq.conf"))
	if err != nil {
		return err
	}
	if strings.Contains(string(config), "definitions.import_backend") {
		// The initial account must actually authenticate over AMQPS, not merely
		// complete TLS. Native users may subsequently be changed independently.
		if v.Password != "" {
			if err = r.probeAMQP(ctx, endpoint.Address, v.Username, v.Password); err != nil {
				return err
			}
		}
		var retained strings.Builder
		for _, line := range strings.Split(string(config), "\n") {
			if strings.HasPrefix(line, "definitions.import_backend") || strings.HasPrefix(line, "definitions.local.path") {
				continue
			}
			retained.WriteString(line + "\n")
		}
		return atomicNativeFile(dir, "rabbitmq.conf", []byte(retained.String()), 0644)
	}
	return nil
}

func (r *Runtime) activeMQConsoleReady(ctx context.Context, endpoint service.Endpoint) error {
	if endpoint.ConsoleURL == "" {
		return errors.New("ActiveMQ console omitted exact loopback TLS binding")
	}
	transport := &http.Transport{TLSClientConfig: r.tls}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request, err := http.NewRequestWithContext(ctx, "GET", endpoint.ConsoleURL+"/admin/queues.jsp", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("ActiveMQ HTTPS console readiness: %w", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || !strings.Contains(response.Header.Get("WWW-Authenticate"), `realm="ActiveMQRealm"`) {
		return errors.New("ActiveMQ web console is not enforcing authentication")
	}
	return nil
}

func (r *Runtime) probeAMQP(ctx context.Context, address, username, password string) error {
	connection, err := amqp.DialConfig(address, amqp.Config{SASL: []amqp.Authentication{&amqp.PlainAuth{Username: username, Password: password}}, Vhost: "/", TLSClientConfig: r.tls, Dial: func(network, address string) (net.Conn, error) {
		socket, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
		if err == nil {
			deadline := time.Now().Add(3 * time.Second)
			if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
				deadline = limit
			}
			_ = socket.SetDeadline(deadline)
		}
		return socket, err
	}})
	if err != nil {
		return errors.New("RabbitMQ initial AMQPS authentication failed")
	}
	return connection.Close()
}

func (r *Runtime) probeOpenWire(ctx context.Context, endpoint service.Endpoint) error {
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dir := r.jmsDirectory()
	command := exec.CommandContext(probe, r.config.Java, "-Xms16m", "-Xmx64m", "-cp", dir+string(filepath.ListSeparator)+filepath.Join(dir, "*"), "StackdMQ", "--probe")
	fields := []string{endpoint.Address, "", "", "", string(endpoint.CAPEM)}
	for i, value := range fields {
		fields[i] = base64.StdEncoding.EncodeToString([]byte(value))
	}
	command.Stdin = strings.NewReader(strings.Join(fields, "\t") + "\n")
	output, err := command.Output()
	if err != nil || string(output) != "READY\n" {
		return errors.New("ActiveMQ OpenWire negotiation readiness failed")
	}
	return nil
}

func (r *Runtime) rabbitRunning(ctx context.Context, id string) error {
	var created struct {
		ID string `json:"Id"`
	}
	input := map[string]any{"Cmd": []string{"rabbitmq-diagnostics", "-q", "check_running"}, "User": "rabbitmq", "AttachStdout": true, "AttachStderr": true, "Tty": true}
	if err := r.client.JSON(ctx, "POST", "/containers/"+id+"/exec", input, &created); err != nil {
		return err
	}
	response, err := r.client.Request(ctx, "POST", "/exec/"+created.ID+"/start", strings.NewReader(`{"Detach":false,"Tty":true}`), "application/json")
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if err != nil {
		return err
	}
	var result struct {
		Running  bool
		ExitCode int
	}
	if err = r.client.JSON(ctx, "GET", "/exec/"+created.ID+"/json", nil, &result); err != nil {
		return err
	}
	if result.Running || result.ExitCode != 0 {
		return errors.New("RabbitMQ application is not running")
	}
	return nil
}

// Remove only recognized regular native files, never recursive broker data.
func removeNativeConfiguration(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"owner": true, "configured": true, "cert.pem": true, "key.pem": true, "definitions.json": true, "enabled_plugins": true, "rabbitmq.conf": true, "advanced.config": true, "broker.p12": true, "activemq.xml": true, "jetty-realm.properties": true, "log4j2.properties": true}
	allowed["StackdMQMetrics.class"] = true
	for _, entry := range entries {
		if !allowed[entry.Name()] && !strings.HasPrefix(entry.Name(), ".mq-config-") && !strings.HasPrefix(entry.Name(), ".mq-keystore-") {
			return errors.New("refusing unrecognized file in MQ native directory")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("refusing non-regular file in MQ native directory")
		}
	}
	for _, entry := range entries {
		if entry.Name() == "owner" {
			continue
		}
		if err = os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	if err = os.Remove(filepath.Join(dir, "owner")); err != nil {
		return err
	}
	return os.Remove(dir)
}
