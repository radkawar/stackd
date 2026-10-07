// Package docker provides the shared native Docker Engine HTTP transport.
package docker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config selects an Engine independently of the user's Docker CLI configuration.
// Host accepts unix:///path, tcp://host:port, http://host:port or https://host:port.
// Empty Host uses unix:///var/run/docker.sock. TLSConfig enables HTTPS for tcp
// hosts and configures HTTPS hosts; it is rejected for plain HTTP hosts.
type Config struct {
	Host      string
	TLSConfig *tls.Config
}

// Client is a caller-owned Engine transport shared by concrete runtime adapters.
// Construct it with New. Close all consumers and their resources before Close.
type Client struct {
	client  *http.Client
	base    string
	version string
}

// Error is a non-successful native Engine response.
type Error struct {
	StatusCode int
	Message    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("Docker Engine HTTP %d: %s", e.StatusCode, e.Message)
}

// New validates Linux and memory, swap and CPU CFS limit support. It selects the
// highest common API in the supported 1.41–1.44 range using the Engine's advertised
// minimum and maximum. Validation is bounded by ctx and a 30-second timeout;
// the returned client does not retain the constructor's context.
func New(ctx context.Context, config Config) (*Client, error) {
	if config.Host == "" {
		config.Host = "unix:///var/run/docker.sock"
	}
	u, err := url.Parse(config.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid Docker host: %w", err)
	}
	transport := &http.Transport{TLSClientConfig: config.TLSConfig, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, MaxIdleConnsPerHost: 16, IdleConnTimeout: 90 * time.Second}
	base := ""
	switch u.Scheme {
	case "unix":
		if u.Path == "" || u.Host != "" {
			return nil, fmt.Errorf("docker unix host requires an absolute socket path")
		}
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", u.Path)
		}
		base = "http://docker"
	case "tcp", "http", "https":
		if u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("docker TCP host must be a plain engine origin")
		}
		if u.Scheme == "tcp" {
			u.Scheme = "http"
			if config.TLSConfig != nil {
				u.Scheme = "https"
			}
		}
		if u.Scheme == "http" && config.TLSConfig != nil {
			return nil, fmt.Errorf("docker TLSConfig requires https or tcp transport")
		}
		base = strings.TrimRight(u.String(), "/")
	default:
		return nil, fmt.Errorf("unsupported Docker host scheme %q", u.Scheme)
	}
	engine := &Client{client: &http.Client{Transport: transport}, base: base}
	ready := false
	defer func() {
		if !ready {
			engine.Close()
		}
	}()
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var version struct {
		APIVersion    string `json:"ApiVersion"`
		MinAPIVersion string `json:"MinAPIVersion"`
		OS            string `json:"Os"`
	}
	if err := engine.JSON(checkCtx, "GET", "/version", nil, &version); err != nil {
		return nil, fmt.Errorf("docker engine unavailable at %s: %w", config.Host, err)
	}
	engine.version, err = compatibleAPIVersion(version.APIVersion, version.MinAPIVersion)
	if err != nil {
		return nil, err
	}
	if version.OS != "linux" {
		return nil, fmt.Errorf("requires a Linux Docker engine, got %q", version.OS)
	}
	var info struct{ MemoryLimit, SwapLimit, CPUCfsQuota, CPUCfsPeriod bool }
	if err := engine.JSON(checkCtx, "GET", "/info", nil, &info); err != nil {
		return nil, fmt.Errorf("checking Docker capabilities: %w", err)
	}
	if !info.MemoryLimit || !info.SwapLimit || !info.CPUCfsQuota || !info.CPUCfsPeriod {
		return nil, fmt.Errorf("docker engine lacks required memory, swap, or CPU CFS limit capabilities")
	}
	ready = true
	return engine, nil
}

func compatibleAPIVersion(maximum, minimum string) (string, error) {
	major, minor, ok := parseAPIVersion(maximum)
	if !ok || major < 1 || (major == 1 && minor < 41) {
		return "", fmt.Errorf("requires Docker API >=1.41; engine reports %q", maximum)
	}
	selected := 44
	if major == 1 {
		selected = min(selected, minor)
	}
	if minimum != "" {
		minMajor, minMinor, valid := parseAPIVersion(minimum)
		if !valid || minMajor < 1 || minMajor > major || (minMajor == major && minMinor > minor) {
			return "", fmt.Errorf("invalid Docker API range %q–%q", minimum, maximum)
		}
		if minMajor > 1 || minMinor > 44 {
			return "", fmt.Errorf("docker engine requires API %s; client supports 1.41–1.44", minimum)
		}
	}
	return "/v1." + strconv.Itoa(selected), nil
}

func parseAPIVersion(value string) (int, int, bool) {
	majorText, minorText, ok := strings.Cut(value, ".")
	if !ok {
		return 0, 0, false
	}
	major, e1 := strconv.Atoi(majorText)
	minor, e2 := strconv.Atoi(minorText)
	return major, minor, e1 == nil && e2 == nil && major >= 0 && minor >= 0
}

// Close releases idle transport connections. It does not interrupt active
// requests or remove containers, volumes or any other Engine resources.
func (d *Client) Close() {
	if d != nil && d.client != nil {
		d.client.CloseIdleConnections()
	}
}

// Request sends a native Engine request. The caller must close a successful
// response body. Non-2xx responses are closed and returned as *Error.
func (d *Client) Request(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	return d.RequestHeaders(ctx, method, path, body, contentType, nil)
}

// RequestHeaders sends an Engine request with caller-supplied native headers,
// such as X-Registry-Auth for an authenticated image pull. Header values are
// copied into the request and are never included in transport error messages.
// As with Request, the caller owns and closes a successful response body. An
// explicitly requested Docker TCP upgrade also accepts HTTP 101; that body is a
// duplex io.ReadWriteCloser. Ordinary requests still require a 2xx response.
func (d *Client) RequestHeaders(ctx context.Context, method, path string, body io.Reader, contentType string, headers http.Header) (*http.Response, error) {
	if d == nil || d.client == nil {
		return nil, fmt.Errorf("docker engine client is not initialized")
	}
	req, err := http.NewRequestWithContext(ctx, method, d.base+d.version+path, body)
	if err != nil {
		return nil, err
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	response, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	upgraded := response.StatusCode == http.StatusSwitchingProtocols &&
		strings.EqualFold(req.Header.Get("Connection"), "Upgrade") &&
		strings.EqualFold(req.Header.Get("Upgrade"), "tcp")
	if !upgraded && (response.StatusCode < 200 || response.StatusCode >= 300) {
		defer response.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(response.Body, 8192))
		var payload struct{ Message string }
		json.Unmarshal(data, &payload)
		if payload.Message == "" {
			payload.Message = string(data)
		}
		return nil, &Error{StatusCode: response.StatusCode, Message: payload.Message}
	}
	return response, nil
}

// JSON sends a JSON Engine request and closes its response. Nil input sends no
// body; nil output discards the response. Decoding and draining are capped at 4MiB.
func (d *Client) JSON(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	response, err := d.Request(ctx, method, path, body, "application/json")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if output != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(output)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<20))
	return err
}

// RemoveContainer force-removes an owned container and its anonymous volumes.
// An empty ID or an already absent container is a successful no-op.
// An earlier canceled request can leave native removal in progress. In that
// state, wait for the Engine's removal completion before dependent cleanup.
func (d *Client) RemoveContainer(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	path := "/containers/" + url.PathEscape(id)
	err := d.JSON(ctx, "DELETE", path+"?force=true&v=true", nil, nil)
	var remote *Error
	if !errors.As(err, &remote) {
		return err
	}
	if remote.StatusCode == http.StatusNotFound {
		return nil
	}
	if remote.StatusCode != http.StatusConflict {
		return err
	}
	var state struct{ State struct{ Status string } }
	if inspectErr := d.JSON(ctx, "GET", path+"/json", nil, &state); inspectErr != nil {
		if errors.As(inspectErr, &remote) && remote.StatusCode == http.StatusNotFound {
			return nil
		}
		return inspectErr
	}
	if state.State.Status != "removing" {
		return err
	}
	var result struct{ Error *struct{ Message string } }
	err = d.JSON(ctx, "POST", path+"/wait?condition=removed", nil, &result)
	if errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound {
		return nil
	}
	if err == nil && result.Error != nil {
		return fmt.Errorf("waiting for container removal: %s", result.Error.Message)
	}
	return err
}
