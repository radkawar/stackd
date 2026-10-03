package iam

import (
	"bytes"
	"context"
	"crypto/sha1" // OIDC thumbprints are the SHA-1 digest specified by IAM.
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"stackd/clock"
)

type httpOIDCDiscovery struct {
	transport *http.Transport
	clock     clock.Clock
}

// NewHTTPOIDCDiscovery explicitly enables HTTPS discovery. The transport is
// cloned, including its TLS configuration; nil selects Go's default transport.
// Each discovery uses isolated TLS trust and a bounded, cancellable HTTP client.
func NewHTTPOIDCDiscovery(transport *http.Transport) (OIDCDiscovery, error) {
	return NewHTTPOIDCDiscoveryWithClock(transport, clock.Real{})
}

// NewHTTPOIDCDiscoveryWithClock uses service time for HTTP cache expiration.
// Network cancellation and external HTTPS certificate validity use wall time;
// advancing an emulator clock does not expire the upstream server's TLS chain.
func NewHTTPOIDCDiscoveryWithClock(transport *http.Transport, source clock.Clock) (OIDCDiscovery, error) {
	if source == nil {
		source = clock.Real{}
	}
	if transport == nil {
		var ok bool
		transport, ok = http.DefaultTransport.(*http.Transport)
		if !ok || transport == nil {
			return nil, fmt.Errorf("default HTTP transport is not an *http.Transport; supply an explicit transport")
		}
	}
	// Go bypasses TLSClientConfig when a custom TLS dialer is installed. Keep
	// ordinary DialContext customization available, but retain ownership of the
	// TLS handshake so neither certificate checks nor thumbprints can be skipped.
	//lint:ignore SA1019 The deprecated dialer still bypasses TLSClientConfig and must be rejected alongside DialTLSContext.
	if transport.DialTLSContext != nil || transport.DialTLS != nil {
		return nil, fmt.Errorf("OIDC discovery does not accept custom TLS dialers; customize DialContext instead")
	}
	retained := transport.Clone()
	if retained.TLSClientConfig != nil && retained.TLSClientConfig.RootCAs != nil {
		retained.TLSClientConfig.RootCAs = retained.TLSClientConfig.RootCAs.Clone()
	}
	return &httpOIDCDiscovery{transport: retained, clock: source}, nil
}

func (d *httpOIDCDiscovery) Discover(ctx context.Context, request OIDCDiscoveryRequest) (OIDCDiscoveryResult, error) {
	issuer, err := discoveryURL(request.IssuerURL)
	if err != nil {
		return OIDCDiscoveryResult{}, err
	}
	transport := d.transport.Clone()
	defer transport.CloseIdleConnections()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if transport.TLSClientConfig != nil {
		tlsConfig = transport.TLSClientConfig.Clone()
	}
	// Verification below always checks the hostname, certificate lifetime,
	// server usage and signatures. InsecureSkipVerify only replaces Go's
	// fixed root selection with IAM's public-CA-or-configured-thumbprint rule.
	tlsConfig.InsecureSkipVerify = true
	customVerification := tlsConfig.VerifyConnection
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if err := verifyOIDCTLS(state, tlsConfig.RootCAs, request.Thumbprints); err != nil {
			return err
		}
		if customVerification != nil {
			return customVerification(state)
		}
		return nil
	}
	transport.TLSClientConfig = tlsConfig
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host || req.URL.User != nil {
			return fmt.Errorf("OIDC redirect leaves the configured HTTPS host")
		}
		return nil
	}}
	metadataURL := strings.TrimSuffix(issuer.String(), "/") + "/.well-known/openid-configuration"
	configuration, thumbprints, expiry, err := fetchOIDCJSON(ctx, client, metadataURL, d.clock)
	if err != nil {
		return OIDCDiscoveryResult{}, err
	}
	result, err := parseOIDCConfiguration(request.IssuerURL, configuration, expiry)
	if err != nil {
		return OIDCDiscoveryResult{}, err
	}
	keys, keyThumbprints, keyExpiry, err := fetchOIDCJSON(ctx, client, result.JWKSURL, d.clock)
	if err != nil {
		return OIDCDiscoveryResult{}, err
	}
	for _, thumbprint := range keyThumbprints {
		if !slices.Contains(thumbprints, thumbprint) {
			thumbprints = append(thumbprints, thumbprint)
		}
	}
	if keyExpiry.Before(expiry) {
		result.CacheUntil = keyExpiry
	}
	result.Thumbprints = thumbprints
	return parseOIDCKeys(result, keys)
}

// ParseOIDCDiscovery applies the same discovery and JWK validation used by
// HTTPS discovery to documents obtained from an explicitly trusted transport.
// TLS verification and observed certificate thumbprints remain transport-owned.
func ParseOIDCDiscovery(issuerURL string, configuration, jwks []byte, cacheUntil time.Time) (OIDCDiscoveryResult, error) {
	result, err := parseOIDCConfiguration(issuerURL, configuration, cacheUntil)
	if err != nil {
		return OIDCDiscoveryResult{}, err
	}
	return parseOIDCKeys(result, jwks)
}

func parseOIDCConfiguration(issuerURL string, configuration []byte, cacheUntil time.Time) (OIDCDiscoveryResult, error) {
	if _, err := discoveryURL(issuerURL); err != nil {
		return OIDCDiscoveryResult{}, err
	}
	if err := uniqueOIDCJSON(configuration); err != nil {
		return OIDCDiscoveryResult{}, err
	}
	var metadata struct {
		Issuer     string   `json:"issuer"`
		JWKS       string   `json:"jwks_uri"`
		Algorithms []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.Unmarshal(configuration, &metadata); err != nil {
		return OIDCDiscoveryResult{}, err
	}
	if metadata.Issuer != issuerURL {
		return OIDCDiscoveryResult{}, fmt.Errorf("discovery issuer does not match configured provider")
	}
	if _, err := discoveryURL(metadata.JWKS); err != nil {
		return OIDCDiscoveryResult{}, fmt.Errorf("invalid configured JWKS URL: %w", err)
	}
	return OIDCDiscoveryResult{IssuerURL: metadata.Issuer, JWKSURL: metadata.JWKS, SigningAlgorithms: metadata.Algorithms, CacheUntil: cacheUntil}, nil
}

func parseOIDCKeys(result OIDCDiscoveryResult, data []byte) (OIDCDiscoveryResult, error) {
	if err := uniqueOIDCJSON(data); err != nil {
		return OIDCDiscoveryResult{}, err
	}
	var jwks struct {
		Keys []struct {
			ID           string   `json:"kid"`
			Type         string   `json:"kty"`
			Use          string   `json:"use"`
			Algorithm    string   `json:"alg"`
			N            string   `json:"n"`
			E            string   `json:"e"`
			Curve        string   `json:"crv"`
			X            string   `json:"x"`
			Y            string   `json:"y"`
			Certificates []string `json:"x5c"`
			Operations   []string `json:"key_ops"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &jwks); err != nil {
		return OIDCDiscoveryResult{}, err
	}
	if len(jwks.Keys) == 0 {
		return OIDCDiscoveryResult{}, fmt.Errorf("OIDC JWKS contains no keys")
	}
	for _, key := range jwks.Keys {
		public := OIDCSigningKey{ID: key.ID, Type: key.Type, Use: key.Use, Algorithm: key.Algorithm, N: key.N, E: key.E, Curve: key.Curve, X: key.X, Y: key.Y, Operations: key.Operations}
		for _, value := range key.Certificates {
			der, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return OIDCDiscoveryResult{}, fmt.Errorf("invalid JWK certificate encoding")
			}
			if _, err := x509.ParseCertificate(der); err != nil {
				return OIDCDiscoveryResult{}, fmt.Errorf("invalid JWK certificate")
			}
			public.Certificates = append(public.Certificates, der)
		}
		result.SigningKeys = append(result.SigningKeys, public)
	}
	return result, nil
}

func discoveryURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("OIDC metadata requires an absolute HTTPS URL without credentials or fragment")
	}
	return parsed, nil
}

// OIDCChainThumbprint returns IAM's SHA-1 thumbprint of the top intermediate,
// or the sole certificate for a self-signed endpoint. The caller must supply a
// nonempty certificate chain in leaf-to-root order.
func OIDCChainThumbprint(chain []*x509.Certificate) string {
	last := len(chain) - 1
	if last > 0 && chain[last].CheckSignatureFrom(chain[last]) == nil {
		last--
	}
	sum := sha1.Sum(chain[last].Raw)
	return hex.EncodeToString(sum[:])
}

func verifyOIDCTLS(state tls.ConnectionState, roots *x509.CertPool, thumbprints []string) error {
	chain := state.PeerCertificates
	if len(chain) == 0 {
		return fmt.Errorf("OIDC endpoint supplied no certificate")
	}
	intermediates := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		if err := chain[i-1].CheckSignatureFrom(chain[i]); err != nil {
			return fmt.Errorf("invalid OIDC certificate chain: %w", err)
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(chain[i].Raw, chain[j].Raw) {
				return fmt.Errorf("duplicate OIDC certificate")
			}
		}
		intermediates.AddCert(chain[i])
	}
	options := x509.VerifyOptions{DNSName: state.ServerName, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if _, err := chain[0].Verify(options); err == nil {
		return nil
	}
	thumbprint := OIDCChainThumbprint(chain)
	if len(thumbprints) != 0 && !slices.ContainsFunc(thumbprints, func(value string) bool { return strings.EqualFold(value, thumbprint) }) {
		return fmt.Errorf("OIDC endpoint certificate does not match a configured thumbprint")
	}
	// Empty pins are used only by explicitly requested automatic registration.
	// Trust the observed CA after verifying the full chain and hostname.
	options.Roots = x509.NewCertPool()
	anchor := len(chain) - 1
	if anchor > 0 && chain[anchor].CheckSignatureFrom(chain[anchor]) == nil {
		anchor--
	}
	options.Roots.AddCert(chain[anchor])
	_, err := chain[0].Verify(options)
	return err
}

func fetchOIDCJSON(ctx context.Context, client *http.Client, endpoint string, source clock.Clock) ([]byte, []string, time.Time, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	defer response.Body.Close()
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return nil, nil, time.Time{}, fmt.Errorf("OIDC endpoint did not use TLS")
	}
	if err := response.TLS.PeerCertificates[0].VerifyHostname(request.URL.Hostname()); err != nil {
		return nil, nil, time.Time{}, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, nil, time.Time{}, fmt.Errorf("OIDC endpoint returned HTTP %d", response.StatusCode)
	}
	const maximum = 1 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	if len(data) > maximum {
		return nil, nil, time.Time{}, fmt.Errorf("OIDC response exceeds maximum size")
	}
	now := source.Now().UTC()
	expiry := now
	for _, part := range strings.Split(response.Header.Get("Cache-Control"), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if key == "no-cache" || key == "no-store" {
			return data, []string{OIDCChainThumbprint(response.TLS.PeerCertificates)}, now, nil
		}
		if ok && key == "max-age" {
			if seconds, err := strconv.ParseInt(strings.Trim(value, "\""), 10, 32); err == nil && seconds > 0 {
				expiry = now.Add(time.Duration(seconds) * time.Second)
			}
		}
	}
	return data, []string{OIDCChainThumbprint(response.TLS.PeerCertificates)}, expiry, nil
}

// Duplicate security-relevant JSON members are rejected instead of allowing
// different discovery/JWT implementations to interpret conflicting values.
func uniqueOIDCJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var value func() error
	value = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				token, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate OIDC JSON member")
				}
				seen[key] = true
				if err := value(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := value(); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("invalid OIDC JSON")
		}
		_, err = decoder.Token()
		return err
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing OIDC JSON data")
	}
	return nil
}
