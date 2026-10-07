package codebuild

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"stackd/compute/docker"
)

const metadataLabel = "stackd.codebuild.metadata"
const metadataTargetLabel = "stackd.codebuild.metadata.target"
const metadataIDLabel = "stackd.codebuild.metadata.id"
const metadataTLSLabel = "stackd.codebuild.metadata.tls"
const metadataPort = "51679"

// The proxy anchors the build network namespace and exposes localhost HTTP to
// SDK credential providers, which do not all consume AWS_CA_BUNDLE. HTTPS
// upstreams are independently verified using scoped public CA trust. It forwards
// request bytes; the service still owns capability validation and role issuance.
// No host credentials, Docker socket or build authorization token are installed.
func (d *DockerExecutor) prepareMetadata(ctx context.Context, arn string, environment []string) (string, []string, error) {
	index := -1
	var endpoint *url.URL
	for i, entry := range environment {
		if !strings.HasPrefix(entry, "AWS_CONTAINER_CREDENTIALS_FULL_URI=") {
			continue
		}
		parsed, err := url.Parse(strings.TrimPrefix(entry, "AWS_CONTAINER_CREDENTIALS_FULL_URI="))
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return "", nil, fmt.Errorf("invalid build role credential endpoint")
		}
		endpoint, index = parsed, i
		break
	}
	if index < 0 {
		return "", environment, nil
	}
	host, port := endpoint.Hostname(), endpoint.Port()
	if port == "" {
		port = "80"
		if endpoint.Scheme == "https" {
			port = "443"
		}
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", nil, fmt.Errorf("invalid build credential endpoint port")
	}
	if net.ParseIP(host) == nil {
		for _, c := range host {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
				return "", nil, fmt.Errorf("invalid build credential endpoint hostname")
			}
		}
	}
	target := net.JoinHostPort(host, port)
	name := d.name(arn) + "-metadata"
	state, err := d.nativeInspect(ctx, name)
	fresh := errors.Is(err, ErrNotFound)
	if err != nil && !fresh {
		return "", nil, err
	}
	if !fresh {
		if state.Config.Labels[namespaceLabel] != d.config.Namespace || state.Config.Labels[arnLabel] != arn || state.Config.Labels[metadataLabel] != "true" || state.Config.Labels[metadataTargetLabel] != target {
			return "", nil, fmt.Errorf("retained build credential proxy ownership or target mismatch")
		}
		if (state.Config.Labels[metadataTLSLabel] == "true") != (endpoint.Scheme == "https") {
			return "", nil, fmt.Errorf("retained build credential proxy TLS mode mismatch")
		}
		if !state.State.Running {
			return "", nil, fmt.Errorf("retained build credential proxy is not running; cannot replace its live network namespace")
		}
	} else {
		var image struct {
			ID     string
			Config struct{ Env []string }
		}
		if err := d.client.JSON(ctx, "GET", "/images/"+url.PathEscape(docker.ToolkitImage)+"/json", nil, &image); err != nil {
			return "", nil, fmt.Errorf("CodeBuild role credential proxy requires installed %s: %w", docker.ToolkitImage, err)
		}
		transport := "TCP4:"
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			transport = "TCP6:"
		}
		upstream := transport + target + ",connect-timeout=5"
		if endpoint.Scheme == "https" {
			ca := "/etc/ssl/certs/ca-certificates.crt"
			if d.config.Networking.CAFile != "" {
				ca = path.Join(docker.RuntimeTrustDirectory, "ca-bundle.pem")
			}
			upstream = "OPENSSL:" + target + ",connect-timeout=5,verify=1,cafile=" + ca + ",cn=" + host
			if net.ParseIP(host) == nil {
				upstream += ",snihost=" + host
			}
		}
		config := docker.ContainerConfig{
			Image: docker.ToolkitImage, Entrypoint: []string{"socat"}, Cmd: []string{"TCP4-LISTEN:" + metadataPort + ",bind=127.0.0.1,reuseaddr,fork", upstream},
			Labels: map[string]string{namespaceLabel: d.config.Namespace, arnLabel: arn, metadataLabel: "true", metadataTargetLabel: target, metadataTLSLabel: strconv.FormatBool(endpoint.Scheme == "https")},
			HostConfig: docker.ContainerHostConfig{NetworkMode: d.config.Network, ReadonlyRootfs: true, Memory: 64 << 20, MemorySwap: 64 << 20, CPUPeriod: 100000, CPUQuota: 10000, PidsLimit: 64,
				CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, ExtraHosts: []string{"host.docker.internal:host-gateway"}, DNS: d.config.Networking.DNS, LogConfig: docker.ContainerLogConfig{Type: "none"}},
		}
		var trust *docker.Trust
		if endpoint.Scheme == "https" {
			trust, err = d.config.Networking.PrepareTrust(&config, image.Config.Env, "")
			if err != nil {
				return "", nil, fmt.Errorf("prepare credential proxy TLS trust: %w", err)
			}
		}
		var created struct {
			ID string `json:"Id"`
		}
		if err := d.client.JSON(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), config, &created); err != nil {
			return "", nil, fmt.Errorf("creating build credential proxy: %w", err)
		}
		state.ID = created.ID
		if err := trust.Install(ctx, d.client, state.ID); err != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			_ = d.client.RemoveContainer(cleanup, state.ID)
			return "", nil, fmt.Errorf("install credential proxy TLS trust: %w", err)
		}
		if err := d.client.JSON(ctx, "POST", "/containers/"+url.PathEscape(state.ID)+"/start", nil, nil); err != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			_ = d.client.RemoveContainer(cleanup, state.ID)
			return "", nil, fmt.Errorf("starting build credential proxy: %w", err)
		}
	}
	if err := d.metadataReady(ctx, state.ID); err != nil {
		if fresh {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			_ = d.client.RemoveContainer(cleanup, state.ID)
		}
		return "", nil, err
	}
	rewritten := *endpoint
	rewritten.Scheme = "http"
	rewritten.Host = "127.0.0.1:" + metadataPort
	environment[index] = "AWS_CONTAINER_CREDENTIALS_FULL_URI=" + rewritten.String()
	return state.ID, environment, nil
}

func (d *DockerExecutor) metadataReady(ctx context.Context, id string) error {
	ready, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := d.probeMetadata(ready, id)
		if err == nil {
			return nil
		}
		select {
		case <-ready.Done():
			return fmt.Errorf("build credential proxy is not ready: %w", errors.Join(ready.Err(), err))
		case <-ticker.C:
		}
	}
}
func (d *DockerExecutor) probeMetadata(ctx context.Context, id string) error {
	// Any HTTP status proves the complete localhost->proxy->configured endpoint
	// path. Probe '/' without a token so no credentials enter readiness output.
	input := struct {
		AttachStdout, AttachStderr bool
		Cmd                        []string
	}{true, true, []string{"curl", "--silent", "--show-error", "--max-time", "2", "--output", "/dev/null", "--write-out", "%{http_code}", "http://127.0.0.1:" + metadataPort + "/"}}
	var created struct {
		ID string `json:"Id"`
	}
	if err := d.client.JSON(ctx, "POST", "/containers/"+url.PathEscape(id)+"/exec", input, &created); err != nil {
		return err
	}
	response, err := d.client.Request(ctx, "POST", "/exec/"+url.PathEscape(created.ID)+"/start", strings.NewReader(`{"Detach":false,"Tty":false}`), "application/json")
	if err != nil {
		return err
	}
	var stdout bytes.Buffer
	copyErr := docker.CopyStream(&stdout, io.Discard, io.LimitReader(response.Body, 8192))
	closeErr := response.Body.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	var status struct {
		Running  bool
		ExitCode int
	}
	if err := d.client.JSON(ctx, "GET", "/exec/"+url.PathEscape(created.ID)+"/json", nil, &status); err != nil {
		return err
	}
	code, parseErr := strconv.Atoi(strings.TrimSpace(stdout.String()))
	if status.Running || status.ExitCode != 0 || parseErr != nil || code < 100 || code > 599 {
		return fmt.Errorf("native credential proxy HTTP readiness failed")
	}
	return nil
}
func (d *DockerExecutor) removeMetadata(ctx context.Context, arn string) error {
	state, err := d.nativeInspect(ctx, d.name(arn)+"-metadata")
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.Config.Labels[namespaceLabel] != d.config.Namespace || state.Config.Labels[arnLabel] != arn || state.Config.Labels[metadataLabel] != "true" {
		return fmt.Errorf("refusing to remove unowned build credential proxy")
	}
	return d.client.RemoveContainer(ctx, state.ID)
}
func (e *dockerExecution) checkMetadata(ctx context.Context, state containerState) error {
	id := state.Config.Labels[metadataIDLabel]
	if id == "" {
		return nil
	}
	proxy, err := e.executor.nativeInspect(ctx, id)
	if err != nil {
		return fmt.Errorf("retained build credential proxy unavailable: %w", err)
	}
	if proxy.Config.Labels[namespaceLabel] != e.executor.config.Namespace || proxy.Config.Labels[arnLabel] != e.arn || proxy.Config.Labels[metadataLabel] != "true" || !proxy.State.Running {
		return fmt.Errorf("retained build credential proxy ownership or running state changed")
	}
	return e.executor.metadataReady(ctx, id)
}
