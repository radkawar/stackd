// Package ecrcredentials implements the native kubelet exec credential-provider
// protocol for stackd's private, path-scoped ECR registry.
package ecrcredentials

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

const APIVersion = "credentialprovider.kubelet.k8s.io/v1"

// Config is private node execution material, not an EKS API field. Credentials
// belong to an explicit least-privilege local node principal, never the workload.
type Config struct {
	Endpoint        string `json:"endpoint"`
	Region          string `json:"region"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken,omitempty"`
}

// Registry returns the exact HTTPS registry authority; URL paths are encoded in
// image names by stackd, not configured as endpoint prefixes.
func (c Config) Registry() (string, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("ECR endpoint must be an HTTPS origin without credentials, path, query or fragment")
	}
	if c.Region == "" || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return "", errors.New("ECR region and explicit access-key credentials are required")
	}
	return u.Host, nil
}

// Load reads only the explicitly selected private credentials file. It never
// discovers ambient profiles, environment credentials or instance metadata.
func Load(path string) (Config, error) {
	var config Config
	info, err := os.Lstat(path)
	if err != nil {
		return config, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return config, errors.New("ECR credentials must be a private 0600 regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	if json.Unmarshal(data, &config) != nil {
		return config, errors.New("invalid ECR credentials JSON")
	}
	_, err = config.Registry()
	return config, err
}

type Request struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Image      string `json:"image"`
}
type Auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Response struct {
	APIVersion    string          `json:"apiVersion"`
	Kind          string          `json:"kind"`
	CacheKeyType  string          `json:"cacheKeyType"`
	CacheDuration string          `json:"cacheDuration"`
	Auth          map[string]Auth `json:"auth"`
}

// Provide obtains fresh ECR authorization via the signed AWS API. A zero cache
// duration deliberately rechecks current IAM and avoids wall-clock assumptions
// when stackd uses a manually advanced service clock.
func Provide(ctx context.Context, config Config, ca []byte, request Request) (Response, error) {
	response := Response{APIVersion: APIVersion, Kind: "CredentialProviderResponse", CacheKeyType: "Image", CacheDuration: "0s", Auth: map[string]Auth{}}
	registry, err := config.Registry()
	if err != nil {
		return response, err
	}
	if request.APIVersion != APIVersion || request.Kind != "CredentialProviderRequest" {
		return response, errors.New("unsupported kubelet credential-provider request")
	}
	if !strings.HasPrefix(request.Image, registry+"/") {
		return response, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return response, errors.New("invalid ECR CA certificate")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sdk := ecr.New(ecr.Options{Region: config.Region, BaseEndpoint: aws.String(config.Endpoint), Credentials: credentials.NewStaticCredentialsProvider(config.AccessKeyID, config.SecretAccessKey, config.SessionToken), HTTPClient: client, RetryMaxAttempts: 1})
	token, err := sdk.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		// SDK errors may include response bodies. Do not send server-controlled
		// credentials or reflected request material to kubelet logs.
		return response, errors.New("ECR GetAuthorizationToken failed (check endpoint TLS, node credentials and IAM)")
	}
	if len(token.AuthorizationData) != 1 || token.AuthorizationData[0].AuthorizationToken == nil {
		return response, errors.New("ECR returned invalid authorization data")
	}
	raw, err := base64.StdEncoding.DecodeString(*token.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		return response, errors.New("ECR returned invalid authorization encoding")
	}
	username, password, ok := strings.Cut(string(raw), ":")
	if !ok || username != "AWS" || password == "" {
		return response, errors.New("ECR returned invalid authorization credentials")
	}
	response.Auth[registry] = Auth{Username: username, Password: password}
	return response, nil
}

// Run serves one versioned request, as required by kubelet exec providers.
func Run(ctx context.Context, configPath, caPath string, in io.Reader, out io.Writer) error {
	config, err := Load(configPath)
	if err != nil {
		return err
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}
	var request Request
	if err = json.NewDecoder(io.LimitReader(in, 1<<20)).Decode(&request); err != nil {
		return errors.New("invalid kubelet credential-provider request JSON")
	}
	response, err := Provide(ctx, config, ca, request)
	if err != nil {
		return err
	}
	if err = json.NewEncoder(out).Encode(response); err != nil {
		return fmt.Errorf("writing kubelet credential-provider response: %w", err)
	}
	return nil
}
