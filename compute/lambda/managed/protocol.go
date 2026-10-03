// Package managed implements Lambda's concurrent Runtime API inside a retained
// EC2 guest. It is not a host-container substitute for a managed instance.
package managed

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	runtime "stackd/compute/lambda"
)

// Identity is an immutable guest incarnation. Token is a controller capability,
// not an AWS credential. All guest management calls verify all three fields.
type Identity struct{ ProviderARN, Generation, Token string }

// Deployment identifies one retained immutable execution environment. Its role
// session can rotate through the separately authenticated credentials endpoint.
type Deployment struct {
	ID             string
	Revision       string
	Specification  runtime.Specification
	MaxConcurrency int
	VCPUs          int
}

type Invocation struct {
	RequestID, FunctionARN, ClientContext, TraceID string
	Payload                                        []byte
	Timeout                                        time.Duration
}
type Outcome struct {
	Result runtime.Result
	Report runtime.Report
}
type Observation struct {
	ID, Revision             string
	Ready                    bool
	InFlight, MaxConcurrency int
	CPUTimeNS                uint64
	MemoryBytes              uint64
	ObservedAt               time.Time
	CredentialsExpire        time.Time
	LogGroup, LogStream      string
}

type RemoteError struct {
	Status  int
	Message string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("managed guest HTTP %d: %s", e.Status, e.Message)
}

// Client pins the guest certificate and checks incarnation on every request.
// Closing a controller connection never destroys the retained guest environment.
type Client struct {
	endpoint string
	identity Identity
	http     *http.Client
}

func NewClient(endpoint string, identity Identity, certificate []byte) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("managed guest requires an HTTPS origin")
	}
	if identity.ProviderARN == "" || identity.Generation == "" || len(identity.Token) < 32 {
		return nil, errors.New("managed guest identity is incomplete")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, errors.New("managed guest certificate is invalid")
	}
	return &Client{endpoint: endpoint, identity: identity, http: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "lambda-guest." + identity.Generation + ".internal", MinVersion: tls.VersionTLS13}, MaxIdleConnsPerHost: 128}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.identity.Token)
	req.Header.Set("X-Stackd-Capacity-Provider", c.identity.ProviderARN)
	req.Header.Set("X-Stackd-Guest-Generation", c.identity.Generation)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
		return &RemoteError{res.StatusCode, string(data)}
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(out)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(res.Body, 8192))
	return err
}
func (c *Client) Ready(ctx context.Context) error {
	return c.call(ctx, http.MethodGet, "/v1/ready", nil, nil)
}
func (c *Client) Prepare(ctx context.Context, d Deployment) (Observation, error) {
	d.Specification.Logs = nil
	var out Observation
	err := c.call(ctx, http.MethodPut, "/v1/environments/"+url.PathEscape(d.ID), d, &out)
	return out, err
}
func (c *Client) Observe(ctx context.Context, id string) (Observation, error) {
	var out Observation
	err := c.call(ctx, http.MethodGet, "/v1/environments/"+url.PathEscape(id), nil, &out)
	return out, err
}
func (c *Client) Invoke(ctx context.Context, id string, in runtime.Invocation) (Outcome, error) {
	return c.InvokeWithTimeout(ctx, id, in, 0)
}
func (c *Client) InvokeWithTimeout(ctx context.Context, id string, in runtime.Invocation, timeout time.Duration) (Outcome, error) {
	if in.Stream != nil {
		return Outcome{}, errors.New("managed guest response streaming is not configured")
	}
	var out Outcome
	err := c.call(ctx, http.MethodPost, "/v1/environments/"+url.PathEscape(id)+"/invocations", Invocation{RequestID: in.RequestID, FunctionARN: in.FunctionARN, ClientContext: in.ClientContext, TraceID: in.TraceID, Payload: in.Payload, Timeout: timeout}, &out)
	return out, err
}
func (c *Client) Remove(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodDelete, "/v1/environments/"+url.PathEscape(id), nil, nil)
}
func (c *Client) RefreshCredentials(ctx context.Context, id string, credentials runtime.Credentials) error {
	return c.call(ctx, http.MethodPut, "/v1/environments/"+url.PathEscape(id)+"/credentials", credentials, nil)
}
func (c *Client) Logs(ctx context.Context, id string) (LogBatch, error) {
	var out LogBatch
	err := c.call(ctx, http.MethodGet, "/v1/environments/"+url.PathEscape(id)+"/logs", nil, &out)
	return out, err
}
func (c *Client) AcknowledgeLogs(ctx context.Context, id string, offset int64) error {
	return c.call(ctx, http.MethodPost, "/v1/environments/"+url.PathEscape(id)+"/logs", struct{ Offset int64 }{offset}, nil)
}
