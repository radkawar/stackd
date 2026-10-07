// Package mq runs installed real RabbitMQ and ActiveMQ brokers with exact native ownership.
package mq

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"stackd/compute/docker"
	"stackd/compute/ports"
	service "stackd/internal/services/mq"
	"strings"
	"sync"
	"time"
)

const RabbitMQImage = "rabbitmq@sha256:87178a0ee3e2f52980ba356d38646ed1056705ff2d5ff281f8965456eaa0c1e3"
const ActiveMQImage = "apache/activemq-classic@sha256:65814d0a18a16bef9096ce7829fcb27e501e281e0ef1064857b9eded4927508c"

// Config requires explicit native TLS trust and a stable private state directory.
// Images must be installed beforehand. Runtime/API calls never download images.
// PortRange bounds new protocol and management endpoints, not retained ports.
type Config struct {
	Host, Namespace, DataDir, TLSCertificate, TLSKey, Java string
	StartupTimeout                                         time.Duration
	PortRange                                              ports.Range
}
type Runtime struct {
	client    *docker.Client
	config    Config
	cert, key []byte
	tls       *tls.Config
	gate      chan struct{}
	mu        sync.Mutex
	closed    bool
}

var _ service.Runtime = (*Runtime)(nil)

func New(c Config) (*Runtime, error) {
	if err := c.PortRange.Validate(); err != nil {
		return nil, err
	}
	if c.Namespace == "" || c.DataDir == "" || c.TLSCertificate == "" || c.TLSKey == "" {
		return nil, errors.New("MQ requires namespace, private DataDir and TLS certificate/key")
	}
	if c.Host != "" && !strings.HasPrefix(c.Host, "unix://") {
		return nil, errors.New("MQ native bind mounts require a local Unix Docker daemon")
	}
	var err error
	c.DataDir, err = filepath.Abs(c.DataDir)
	if err != nil {
		return nil, err
	}
	if c.StartupTimeout == 0 {
		c.StartupTimeout = 90 * time.Second
	}
	if c.StartupTimeout < 0 {
		return nil, errors.New("MQ StartupTimeout must be positive")
	}
	if c.Java == "" {
		c.Java = "java"
	}
	if c.Java, err = exec.LookPath(c.Java); err != nil {
		return nil, fmt.Errorf("MQ requires an installed Java 11+ JDK: %w", err)
	}
	if _, err = exec.LookPath(filepath.Join(filepath.Dir(c.Java), "javac")); err != nil {
		return nil, fmt.Errorf("MQ requires the matching Java compiler: %w", err)
	}
	if _, err = exec.LookPath("openssl"); err != nil {
		return nil, fmt.Errorf("MQ ActiveMQ TLS requires openssl: %w", err)
	}
	cert, err := os.ReadFile(c.TLSCertificate)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(c.TLSKey)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if err = leaf.VerifyHostname("127.0.0.1"); err != nil {
		return nil, fmt.Errorf("MQ certificate must cover 127.0.0.1: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	if err = os.MkdirAll(c.DataDir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(c.DataDir)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("MQ state directory must not be accessible by group or other users")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := docker.New(ctx, docker.Config{Host: c.Host})
	if err != nil {
		return nil, err
	}
	for _, image := range []string{RabbitMQImage, ActiveMQImage} {
		if err = client.JSON(ctx, "GET", "/images/"+url.PathEscape(image)+"/json", nil, nil); err != nil {
			client.Close()
			return nil, fmt.Errorf("MQ requires explicitly installed image %s: %w", image, err)
		}
	}
	r := &Runtime{client: client, config: c, cert: cert, key: key, tls: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1"}, gate: make(chan struct{}, 1)}
	return r, nil
}
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.client.Close()
	return nil
}
func (r *Runtime) lock(ctx context.Context) error {
	select {
	case r.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		<-r.gate
		return errors.New("MQ runtime is closed")
	}
	return nil
}
func (r *Runtime) unlock() { <-r.gate }
func (r *Runtime) name(v service.BrokerRecord) string {
	return fmt.Sprintf("stackd-mq-%x", sha256.Sum256([]byte(r.config.Namespace+"\x00"+v.ARN)))
}
func (r *Runtime) labels(v service.BrokerRecord) map[string]string {
	return map[string]string{"stackd.mq.namespace": r.config.Namespace, "stackd.mq.arn": v.ARN, "stackd.mq.id": v.ID, "stackd.mq.layout": "native-v1"}
}
func (r *Runtime) check(labels map[string]string, v service.BrokerRecord) error {
	for k, x := range r.labels(v) {
		if labels[k] != x {
			return errors.New("refusing foreign MQ native resource")
		}
	}
	return nil
}
func missing(err error) bool { var e *docker.Error; return errors.As(err, &e) && e.StatusCode == 404 }

type inspection struct {
	ID     string `json:"Id"`
	Config struct {
		Labels map[string]string
		Env    []string
	}
	State  struct{ Running bool }
	Mounts []struct {
		Type, Name, Source, Destination string
		RW                              bool
	}
	HostConfig struct {
		PortBindings map[string][]struct{ HostIP, HostPort string }
	}
	NetworkSettings struct {
		Ports map[string][]struct{ HostIP, HostPort string }
	}
}

func needsNativeReplacement(v service.BrokerRecord, i inspection) bool {
	if v.Engine == "ACTIVEMQ" {
		bindings := i.HostConfig.PortBindings[activeMQConsolePort]
		if !slices.Contains(i.Config.Env, activeMQConsoleEnvironment) || len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" || bindings[0].HostPort == "" || bindings[0].HostPort == "0" {
			return true
		}
	}
	return nativeDynamicPorts(i) || (v.Engine == "RABBITMQ" && !slices.Contains(i.Config.Env, rabbitAdvancedConfigEnvironment))
}

func (r *Runtime) inspect(ctx context.Context, v service.BrokerRecord) (inspection, error) {
	var i inspection
	err := r.client.JSON(ctx, "GET", "/containers/"+r.name(v)+"/json", nil, &i)
	if err == nil {
		err = r.check(i.Config.Labels, v)
	}
	return i, err
}
func (r *Runtime) Ensure(ctx context.Context, v service.BrokerRecord) (service.Endpoint, error) {
	if err := r.lock(ctx); err != nil {
		return service.Endpoint{}, err
	}
	defer r.unlock()
	return r.ensure(ctx, v)
}
func (r *Runtime) ensure(ctx context.Context, v service.BrokerRecord) (service.Endpoint, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.StartupTimeout)
	defer cancel()
	i, err := r.inspect(ctx, v)
	if missing(err) {
		if err = r.create(ctx, v); err != nil {
			return service.Endpoint{}, err
		}
		i, err = r.inspect(ctx, v)
	}
	if err != nil {
		return service.Endpoint{}, err
	}
	if err = r.checkNativeStorage(ctx, v, i); err != nil {
		return service.Endpoint{}, err
	}
	if needsNativeReplacement(v, i) && (!i.State.Running || v.Engine == "ACTIVEMQ") {
		if err = retainNativePorts(&v, i); err != nil {
			return service.Endpoint{}, err
		}
		if err = r.persistNativePorts(v); err != nil {
			return service.Endpoint{}, err
		}
		// Upgrade only the checked owned container. Configuration uses current
		// users, never their pending passwords, groups or console grants.
		if v.Engine == "ACTIVEMQ" {
			if err = r.applyConfiguration(v); err != nil {
				return service.Endpoint{}, err
			}
		}
		if i.State.Running {
			if err = r.client.JSON(ctx, "POST", "/containers/"+i.ID+"/stop?t=30", nil, nil); err != nil {
				return service.Endpoint{}, err
			}
		}
		if err = r.client.RemoveContainer(ctx, i.ID); err != nil {
			return service.Endpoint{}, err
		}
		return r.ensure(ctx, v)
	}
	if !i.State.Running {
		if err = r.client.JSON(ctx, "POST", "/containers/"+i.ID+"/start", nil, nil); err != nil {
			return service.Endpoint{}, err
		}
		i, err = r.inspect(ctx, v)
		if err != nil {
			return service.Endpoint{}, err
		}
	}
	port, scheme := "5671/tcp", "amqps"
	if v.Engine == "ACTIVEMQ" {
		port, scheme = "61617/tcp", "ssl"
		if err = r.installJMS(ctx, i.ID); err != nil {
			return service.Endpoint{}, err
		}
	}
	bindings := i.NetworkSettings.Ports[port]
	if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" {
		return service.Endpoint{}, errors.New("native MQ endpoint omitted exact loopback TLS binding")
	}
	address := net.JoinHostPort("127.0.0.1", bindings[0].HostPort)
	for {
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: r.tls}
		conn, e := dialer.DialContext(ctx, "tcp", address)
		if e == nil {
			_ = conn.Close()
			endpoint := service.Endpoint{Address: scheme + "://" + address, NativeID: i.ID, CAPEM: bytes.Clone(r.cert)}
			consolePort := "15671/tcp"
			if v.Engine == "ACTIVEMQ" {
				consolePort = activeMQConsolePort
			}
			if bindings := i.NetworkSettings.Ports[consolePort]; len(bindings) == 1 && bindings[0].HostIP == "127.0.0.1" {
				endpoint.ConsoleURL = "https://" + net.JoinHostPort("127.0.0.1", bindings[0].HostPort)
			}
			e = r.nativeReady(ctx, v, endpoint)
			if e == nil {
				v.Endpoint = endpoint
				return endpoint, r.persistNativePorts(v)
			}
		}
		select {
		case <-ctx.Done():
			return service.Endpoint{}, fmt.Errorf("MQ broker native readiness: %w", e)
		case <-time.After(200 * time.Millisecond):
		}
	}
}
func (r *Runtime) create(ctx context.Context, v service.BrokerRecord) error {
	name := r.name(v)
	dir := filepath.Join(r.config.DataDir, name)
	if err := os.Mkdir(dir, 0755); err == nil {
		if v.Password == "" && len(v.Users) == 0 {
			_ = os.Remove(dir)
			return errors.New("broker native configuration is missing; refusing to replace retained broker data")
		}
		if err = atomicNativeFile(dir, "owner", []byte(v.ARN), 0600); err != nil {
			return err
		}
	} else if !os.IsExist(err) {
		return err
	}
	if _, err := r.ownedDirectory(v); err != nil {
		return err
	}
	if err := loadNativePorts(dir, &v); err != nil {
		return err
	}
	var err error
	// Retain ownership before writing secrets so interrupted configuration is
	// both retryable and removable. The marker describes native files, not data.
	configured := filepath.Join(dir, "configured")
	if _, err = os.Stat(configured); os.IsNotExist(err) {
		if v.Password == "" && len(v.Users) == 0 {
			return errors.New("broker native configuration is incomplete")
		}
		if err = r.configure(ctx, dir, v); err != nil {
			return err
		}
		if err = atomicNativeFile(dir, "configured", []byte(v.ID), 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if v.Engine == "RABBITMQ" {
		// Pre-advanced-config containers only admitted finite timeouts. Keep
		// their existing conf, including bootstrap definitions if the first
		// launch was interrupted before RabbitMQ imported its initial user.
		if _, err = os.Stat(filepath.Join(dir, "advanced.config")); os.IsNotExist(err) {
			if err = atomicNativeFile(dir, "advanced.config", []byte("[].\n"), 0644); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	} else if v.Engine == "ACTIVEMQ" {
		// Recreate the process around the retained keystore and journal.
		if err = r.applyConfiguration(v); err != nil {
			return err
		}
	}
	volume := name + "-data"
	var vol struct{ Labels map[string]string }
	err = r.client.JSON(ctx, "GET", "/volumes/"+volume, nil, &vol)
	if missing(err) {
		err = r.client.JSON(ctx, "POST", "/volumes/create", docker.VolumeConfig{Name: volume, Labels: r.labels(v)}, nil)
	} else if err == nil {
		err = r.check(vol.Labels, v)
	}
	if err != nil {
		return err
	}
	image, port, target := RabbitMQImage, "5671/tcp", "/var/lib/rabbitmq"
	env := []string{"RABBITMQ_CONFIG_FILE=/stackd/rabbitmq", rabbitAdvancedConfigEnvironment, "RABBITMQ_ENABLED_PLUGINS_FILE=/stackd/enabled_plugins", "RABBITMQ_NODENAME=rabbit@localhost", "RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS=+S 2:2"}
	cmd := []string(nil)
	if v.Engine == "ACTIVEMQ" {
		image, port, target = ActiveMQImage, "61617/tcp", "/opt/apache-activemq/data"
		env = []string{activeMQConsoleEnvironment}
		cmd = []string{"activemq", "console", "xbean:file:/stackd/activemq.xml"}
	}
	exposed := map[string]any{port: struct{}{}}
	hostPort, releasePort, err := r.reserveNativePort(ctx, v.Endpoint.Address)
	if err != nil {
		return err
	}
	defer releasePort()
	scheme := "amqps"
	if v.Engine == "ACTIVEMQ" {
		scheme = "ssl"
	}
	v.Endpoint.Address = scheme + "://" + net.JoinHostPort("127.0.0.1", hostPort)
	ports := map[string]any{port: []map[string]string{{"HostIp": "127.0.0.1", "HostPort": hostPort}}}
	if v.Engine == "RABBITMQ" {
		if _, err := os.Stat(filepath.Join(dir, "enabled_plugins")); err == nil {
			exposed["15671/tcp"] = struct{}{}
			managementPort, releaseManagement, err := r.reserveNativePort(ctx, v.Endpoint.ConsoleURL)
			if err != nil {
				return err
			}
			defer releaseManagement()
			ports["15671/tcp"] = []map[string]string{{"HostIp": "127.0.0.1", "HostPort": managementPort}}
			v.Endpoint.ConsoleURL = "https://" + net.JoinHostPort("127.0.0.1", managementPort)
		} else if !os.IsNotExist(err) {
			return err
		}
	} else {
		exposed[activeMQConsolePort] = struct{}{}
		consolePort, releaseConsole, err := r.reserveNativePort(ctx, v.Endpoint.ConsoleURL)
		if err != nil {
			return err
		}
		defer releaseConsole()
		ports[activeMQConsolePort] = []map[string]string{{"HostIp": "127.0.0.1", "HostPort": consolePort}}
		v.Endpoint.ConsoleURL = "https://" + net.JoinHostPort("127.0.0.1", consolePort)
	}
	if err := r.persistNativePorts(v); err != nil {
		return err
	}
	input := map[string]any{"Image": image, "Cmd": cmd, "Env": env, "Labels": r.labels(v), "ExposedPorts": exposed, "HostConfig": map[string]any{"Memory": int64(768 << 20), "MemorySwap": int64(768 << 20), "CPUPeriod": 100000, "CPUQuota": 100000, "PidsLimit": 512, "PortBindings": ports, "Mounts": []docker.ContainerMount{{Type: "bind", Source: dir, Target: "/stackd", ReadOnly: true}, {Type: "volume", Source: volume, Target: target}}, "LogConfig": docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "2"}}}}
	return r.client.JSON(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), input, nil)
}
func (r *Runtime) Reboot(ctx context.Context, v service.BrokerRecord) (service.Endpoint, error) {
	if err := r.lock(ctx); err != nil {
		return service.Endpoint{}, err
	}
	defer r.unlock()
	ctx, cancel := context.WithTimeout(ctx, r.config.StartupTimeout)
	defer cancel()
	i, err := r.inspect(ctx, v)
	if missing(err) {
		if err = r.applyConfiguration(v); err != nil {
			return service.Endpoint{}, err
		}
		return r.ensure(ctx, v)
	}
	if err != nil {
		return service.Endpoint{}, err
	}
	if err = r.checkNativeStorage(ctx, v, i); err != nil {
		return service.Endpoint{}, err
	}
	if err = r.applyConfiguration(v); err != nil {
		return service.Endpoint{}, err
	}
	// Older containers lack stable ports or native configuration paths. Cut
	// over only the exact-owned container; preserve its journal volume,
	// credentials and published ports.
	if needsNativeReplacement(v, i) {
		if err = retainNativePorts(&v, i); err != nil {
			return service.Endpoint{}, err
		}
		if err = r.persistNativePorts(v); err != nil {
			return service.Endpoint{}, err
		}
		if i.State.Running {
			if err = r.client.JSON(ctx, "POST", "/containers/"+i.ID+"/stop?t=30", nil, nil); err != nil {
				return service.Endpoint{}, err
			}
		}
		if err = r.client.RemoveContainer(ctx, i.ID); err != nil {
			return service.Endpoint{}, err
		}
		return r.ensure(ctx, v)
	}
	if err = r.client.JSON(ctx, "POST", "/containers/"+i.ID+"/restart?t=10", nil, nil); err != nil {
		return service.Endpoint{}, err
	}
	return r.ensure(ctx, v)
}
func (r *Runtime) Delete(ctx context.Context, v service.BrokerRecord) error {
	if err := r.lock(ctx); err != nil {
		return err
	}
	defer r.unlock()
	i, err := r.inspect(ctx, v)
	if err != nil && !missing(err) {
		return err
	}
	if err == nil {
		if err = r.client.RemoveContainer(ctx, i.ID); err != nil {
			return err
		}
	}
	name := r.name(v)
	var volume struct{ Labels map[string]string }
	err = r.client.JSON(ctx, "GET", "/volumes/"+name+"-data", nil, &volume)
	if err != nil && !missing(err) {
		return err
	}
	if err == nil {
		if err = r.check(volume.Labels, v); err != nil {
			return err
		}
		if err = r.client.JSON(ctx, "DELETE", "/volumes/"+name+"-data", nil, nil); err != nil {
			return err
		}
	}
	dir, err := r.ownedDirectory(v)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return removeNativeConfiguration(dir)
}
func (r *Runtime) installJMS(ctx context.Context, id string) error {
	dir := r.jmsDirectory()
	if _, err := os.Stat(filepath.Join(dir, "StackdMQ.class")); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	response, err := r.client.Request(ctx, http.MethodGet, "/containers/"+id+"/archive?path=/opt/apache-activemq/lib", nil, "")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	tr := tar.NewReader(response.Body)
	for {
		header, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if header.Typeflag != tar.TypeReg || !strings.HasSuffix(header.Name, ".jar") || strings.Count(header.Name, "/") != 1 {
			continue
		}
		file, e := os.OpenFile(filepath.Join(dir, filepath.Base(header.Name)), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if e != nil {
			return e
		}
		_, e = io.Copy(file, io.LimitReader(tr, 64<<20))
		closeErr := file.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	source := filepath.Join(dir, "StackdMQ.java")
	if err = os.WriteFile(source, []byte(jmsSource), 0600); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, filepath.Join(filepath.Dir(r.config.Java), "javac"), "-cp", filepath.Join(dir, "*"), "-d", dir, source)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("compiling installed OpenWire driver: %w: %s", err, output)
	}
	return nil
}
func (r *Runtime) jmsDirectory() string {
	return filepath.Join(r.config.DataDir, fmt.Sprintf("jms-5.18.7-%x", sha256.Sum256([]byte(jmsSource))))
}
