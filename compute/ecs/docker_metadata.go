package ecs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"stackd/compute/docker"
)

const (
	metadataTaskLabel   = dockerTaskLabel
	metadataHostLabel   = "stackd.ecs.metadata.callback.host"
	metadataPortLabel   = "stackd.ecs.metadata.callback.port"
	metadataSourceLabel = "stackd.ecs.metadata.callback.source"
)

type dockerMetadataSpec struct {
	TaskARN, NetworkName, Image, MACAddress string
	Address, Gateway                        netip.Addr
	// DNS and DNSSearch apply only to a fresh anchor. A reattached anchor keeps
	// the resolvers its live namespace was created with.
	DNS, DNSSearch []string
	Handler        http.Handler
	Configure      func(context.Context, string, string) error
}

// dockerMetadata owns an Engine anchor independently of this process's listener.
// It requires a local rootful Linux bridge and a namespace permitting port 80
// without NET_BIND_SERVICE. Remote/Desktop/rootless and userns-remapped engines
// are not supported by this mechanism. The executor checks these capabilities.
// Customers sharing this namespace are not isolated from one another.
type dockerMetadata struct {
	client      *docker.Client
	id, taskARN string
	server      *http.Server
}

type dockerMetadataInspection struct {
	ID     string `json:"Id"`
	Config struct{ Labels map[string]string }
	State  struct {
		Running, Paused, Restarting, Dead bool
		Status, Error                     string
	}
	RestartCount    int
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress, Gateway, MacAddress string
		}
	}
}

func metadataContainerName(taskARN string) string {
	return fmt.Sprintf("stackd-ecs-metadata-%x", sha256.Sum256([]byte(taskARN)))
}

func metadataCommand(callback string) []string {
	return []string{"-c", "ip addr replace 169.254.170.2/32 dev lo && exec socat TCP4-LISTEN:80,bind=169.254.170.2,reuseaddr,fork TCP4:" + callback}
}

// prepareMetadata never repairs an existing anchor by restarting it: customers
// would remain in the old network namespace. Main owns task-wide replacement.
func prepareMetadata(ctx context.Context, client *docker.Client, spec dockerMetadataSpec) (_ *dockerMetadata, resultErr error) {
	if client == nil || spec.TaskARN == "" || spec.NetworkName == "" || spec.Image == "" || spec.Handler == nil {
		return nil, errors.New("ECS metadata requires an Engine client, task ARN, network, pinned toolkit image and handler")
	}
	if !spec.Address.Is4() || !spec.Gateway.Is4() || spec.Address == spec.Gateway || !spec.Address.IsGlobalUnicast() || !spec.Gateway.IsGlobalUnicast() {
		return nil, errors.New("ECS metadata requires distinct unicast IPv4 task and bridge gateway addresses")
	}
	mac, err := net.ParseMAC(spec.MACAddress)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return nil, fmt.Errorf("ECS metadata requires a unicast Ethernet MAC address: %q", spec.MACAddress)
	}
	spec.MACAddress = mac.String()
	name := metadataContainerName(spec.TaskARN)
	var existing dockerMetadataInspection
	err = client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &existing)
	var engineErr *docker.Error
	fresh := errors.As(err, &engineErr) && engineErr.StatusCode == http.StatusNotFound
	if err != nil && !fresh {
		return nil, fmt.Errorf("inspect ECS metadata anchor: %w", err)
	}
	callback := net.JoinHostPort(spec.Gateway.String(), "0")
	if !fresh {
		callback, err = existing.validate(spec)
		if err != nil {
			return nil, err
		}
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", callback)
	if err != nil {
		if !fresh {
			return nil, fmt.Errorf("recover ECS metadata callback %s without replacing surviving anchor: %w", callback, err)
		}
		return nil, fmt.Errorf("bind ECS metadata callback on bridge gateway %s: %w", spec.Gateway, err)
	}
	callback = listener.Addr().String()
	probe := "/.stackd-ecs-ready/" + rand.Text()
	var probing atomic.Bool
	probing.Store(true)
	observed := make(chan struct{}, 1)
	m := &dockerMetadata{client: client, id: existing.ID, taskARN: spec.TaskARN}
	m.server = &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, splitErr := net.SplitHostPort(r.RemoteAddr)
			source, parseErr := netip.ParseAddr(host)
			if splitErr != nil || parseErr != nil || source.Unmap() != spec.Address {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if probing.Load() && r.Method == http.MethodGet && r.RequestURI == probe {
				w.WriteHeader(http.StatusNoContent)
				select {
				case observed <- struct{}{}:
				default:
				}
				return
			}
			// The raw TCP proxy leaves method, path, body and headers untouched.
			// Same-task direct requests have the same source and are valid; opaque
			// credential/metadata authorization belongs exclusively to Handler.
			spec.Handler.ServeHTTP(w, r)
		}),
	}
	served := make(chan error, 1)
	go func() { served <- m.server.Serve(listener) }()
	createAttempted := false
	defer func() {
		probing.Store(false)
		if resultErr == nil {
			return
		}
		resultErr = errors.Join(resultErr, m.close())
		// A failed reattachment owns no native resources. A failed fresh create
		// must not leave an anchor, even if the request context was canceled.
		if fresh && createAttempted {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if m.id == "" {
				resultErr = errors.Join(resultErr, m.findCreated(cleanupCtx, name, callback))
			}
			resultErr = errors.Join(resultErr, m.remove(cleanupCtx))
		}
	}()
	if fresh {
		_, port, _ := net.SplitHostPort(callback)
		config := docker.ContainerConfig{
			Image: spec.Image, Entrypoint: []string{"/bin/sh"}, Cmd: metadataCommand(callback),
			Labels: map[string]string{
				metadataTaskLabel: spec.TaskARN, metadataHostLabel: spec.Gateway.String(),
				metadataPortLabel: port, metadataSourceLabel: spec.Address.String(),
			},
			NetworkingConfig: &docker.ContainerNetworkingConfig{EndpointsConfig: map[string]docker.ContainerEndpointConfig{
				spec.NetworkName: {MacAddress: spec.MACAddress, IPAMConfig: docker.ContainerEndpointIPAMConfig{IPv4Address: spec.Address.String()}},
			}},
			HostConfig: docker.ContainerHostConfig{
				NetworkMode: spec.NetworkName, ReadonlyRootfs: true,
				CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"},
				SecurityOpt: []string{"no-new-privileges:true"},
				ExtraHosts:  []string{"host.docker.internal:host-gateway"},
				DNS:         spec.DNS, DNSSearch: spec.DNSSearch,
				LogConfig: docker.ContainerLogConfig{Type: "none"},
			},
		}
		var created struct {
			ID string `json:"Id"`
		}
		createAttempted = true
		if err := client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), config, &created); err != nil {
			return nil, fmt.Errorf("create ECS metadata anchor: %w", err)
		}
		m.id = created.ID
		if m.id == "" {
			return nil, errors.New("creating the ECS metadata anchor returned no container ID")
		}
		if err := client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(m.id)+"/start", nil, nil); err != nil {
			return nil, fmt.Errorf("start ECS metadata anchor: %w", err)
		}
	}
	// Attach the outside-customer boundary before probing or exposing a fresh
	// namespace to any customer, and reapply it on controller recovery.
	if spec.Configure != nil {
		if err := spec.Configure(ctx, m.id, callback); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNetworkPolicy, err)
		}
	}
	if err := m.awaitReady(ctx, probe, observed, served); err != nil {
		return nil, err
	}
	return m, nil
}

func (state *dockerMetadataInspection) validate(spec dockerMetadataSpec) (string, error) {
	labels := state.Config.Labels
	if state.ID == "" || labels[metadataTaskLabel] != spec.TaskARN {
		return "", errors.New("ECS metadata anchor name is occupied by a container without matching task ownership")
	}
	port, err := strconv.Atoi(labels[metadataPortLabel])
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != labels[metadataPortLabel] || labels[metadataHostLabel] != spec.Gateway.String() || labels[metadataSourceLabel] != spec.Address.String() {
		return "", errors.New("ECS metadata anchor retained callback configuration does not match task attachment")
	}
	callback := net.JoinHostPort(labels[metadataHostLabel], labels[metadataPortLabel])
	if !state.State.Running || state.State.Paused || state.State.Restarting || state.State.Dead || state.RestartCount != 0 {
		return "", fmt.Errorf("ECS metadata anchor is not continuously running (status %q, restart count %d, error %q); task-wide handling is required", state.State.Status, state.RestartCount, state.State.Error)
	}
	endpoint, ok := state.NetworkSettings.Networks[spec.NetworkName]
	if !ok || endpoint.IPAddress != spec.Address.String() || endpoint.Gateway != spec.Gateway.String() || !strings.EqualFold(endpoint.MacAddress, spec.MACAddress) {
		return "", errors.New("ECS metadata anchor native address/MAC/network differs from task attachment; task-wide handling is required")
	}
	return callback, nil
}

// awaitReady checks the entire namespace-local proxy and HTTP listener path. It
// invokes only the caller-supplied toolkit, through bounded native Engine execs.
func (m *dockerMetadata) awaitReady(ctx context.Context, probe string, observed <-chan struct{}, served <-chan error) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		lastErr = m.probe(ctx, probe)
		if lastErr == nil {
			select {
			case <-observed:
				return nil
			default:
				lastErr = errors.New("native metadata probe did not reach the task-scoped callback")
			}
		}
		select {
		case err := <-served:
			return fmt.Errorf("ECS metadata callback listener stopped before readiness: %w", err)
		case <-ctx.Done():
			return fmt.Errorf("ECS metadata proxy did not become ready; task-wide handling is required: %w", errors.Join(ctx.Err(), lastErr))
		case <-ticker.C:
		}
	}
}

func (m *dockerMetadata) probe(ctx context.Context, path string) error {
	// path contains only a fixed prefix and a cryptographically random base32
	// token; neither task identifiers nor caller input are interpolated in sh.
	command := "printf 'GET " + path + " HTTP/1.1\\r\\nHost: 169.254.170.2\\r\\nConnection: close\\r\\n\\r\\n' | socat -T 1 - TCP4:169.254.170.2:80,connect-timeout=1"
	var created struct {
		ID string `json:"Id"`
	}
	input := struct {
		AttachStdout, AttachStderr bool
		Cmd                        []string
	}{true, true, []string{"/bin/sh", "-c", command}}
	if err := m.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(m.id)+"/exec", input, &created); err != nil {
		return err
	}
	if created.ID == "" {
		return errors.New("creating the metadata readiness command returned no exec ID")
	}
	response, err := m.client.Request(ctx, http.MethodPost, "/exec/"+url.PathEscape(created.ID)+"/start", strings.NewReader(`{"Detach":false,"Tty":false}`), "application/json")
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(io.Discard, io.LimitReader(response.Body, 8192))
	closeErr := response.Body.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	var state struct {
		Running  bool
		ExitCode int
	}
	if err := m.client.JSON(ctx, http.MethodGet, "/exec/"+url.PathEscape(created.ID)+"/json", nil, &state); err != nil {
		return err
	}
	if state.Running || state.ExitCode != 0 {
		return fmt.Errorf("metadata readiness exec running=%t exit=%d", state.Running, state.ExitCode)
	}
	return nil
}

func (m *dockerMetadata) containerID() string { return m.id }

// close detaches only this process. Native configuration and the running anchor
// survive so another controller can bind the exact retained callback endpoint.
func (m *dockerMetadata) close() error {
	if m == nil || m.server == nil {
		return nil
	}
	return m.server.Close()
}

// A transport failure can hide a successful native create. The callback port
// was exclusively bound by this process, so matching its retained endpoint
// distinguishes our attempted create from a concurrent name claimant.
func (m *dockerMetadata) findCreated(ctx context.Context, name, callback string) error {
	var state dockerMetadataInspection
	err := m.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &state)
	var engineErr *docker.Error
	if errors.As(err, &engineErr) && engineErr.StatusCode == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("discover ECS metadata anchor after uncertain create: %w", err)
	}
	labels := state.Config.Labels
	if labels[metadataTaskLabel] == m.taskARN && net.JoinHostPort(labels[metadataHostLabel], labels[metadataPortLabel]) == callback {
		m.id = state.ID
	}
	return nil
}

// remove follows removal of customers sharing the namespace. The immutable ID
// was obtained from creation or an ownership-checked native lookup.
func (m *dockerMetadata) remove(ctx context.Context) error {
	if m == nil {
		return nil
	}
	return errors.Join(m.close(), m.client.RemoveContainer(ctx, m.id))
}
