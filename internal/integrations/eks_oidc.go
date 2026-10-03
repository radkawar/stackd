package integrations

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"stackd/clock"
	"stackd/internal/services/eks"
	"stackd/internal/services/iam"
)

// EKSServiceAccountIssuerSource reads public documents from the cluster's real
// Kubernetes issuer. A foreign issuer returns eks.ErrNotServiceAccountIssuer.
type EKSServiceAccountIssuerSource interface {
	ServiceAccountIssuerDocuments(context.Context, string) ([]byte, []byte, error)
}

// EKSServiceAccountIssuerCertificate supplies the configured public frontend TLS
// certificate chain as read-only PEM. It never supplies a private key.
type EKSServiceAccountIssuerCertificate interface {
	ServiceAccountIssuerCertificate() []byte
}

// EKSServiceAccountIssuers resolves locally owned issuers without an Internet
// fallback. IAM still owns provider configuration; STS still verifies the JWT and
// evaluates the current provider and role authority before issuing credentials.
type EKSServiceAccountIssuers struct {
	EKS         EKSServiceAccountIssuerSource
	next        iam.OIDCDiscovery
	thumbprints []string
	clock       clock.Clock
}

// NewEKSServiceAccountIssuers parses the actual frontend certificate once.
// Assembly sets EKS before exposing this source to requests.
func NewEKSServiceAccountIssuers(source EKSServiceAccountIssuerCertificate, next iam.OIDCDiscovery, serviceClock clock.Clock) (*EKSServiceAccountIssuers, error) {
	d := &EKSServiceAccountIssuers{next: next, clock: serviceClock}
	var certificate []byte
	if source != nil {
		certificate = source.ServiceAccountIssuerCertificate()
	}
	var chain []*x509.Certificate
	for len(certificate) != 0 {
		block, rest := pem.Decode(certificate)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("EKS issuer frontend certificate is not certificate PEM")
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("EKS issuer frontend certificate: %w", err)
		}
		chain = append(chain, parsed)
		certificate = rest
	}
	if len(chain) != 0 {
		d.thumbprints = []string{iam.OIDCChainThumbprint(chain)}
	}
	return d, nil
}

func (d *EKSServiceAccountIssuers) Discover(ctx context.Context, request iam.OIDCDiscoveryRequest) (iam.OIDCDiscoveryResult, error) {
	configuration, keys, err := d.EKS.ServiceAccountIssuerDocuments(ctx, request.IssuerURL)
	if errors.Is(err, eks.ErrNotServiceAccountIssuer) {
		if d.next == nil {
			return iam.OIDCDiscoveryResult{}, errors.New("no OIDC discovery source configured for this issuer")
		}
		return d.next.Discover(ctx, request)
	}
	if err != nil {
		return iam.OIDCDiscoveryResult{}, err
	}
	// Reuse STS's existing key cache with the same service-time lifetime advertised
	// by the public issuer. IAM provider and role authority are still read afresh.
	result, err := iam.ParseOIDCDiscovery(request.IssuerURL, configuration, keys, d.clock.Now().Add(eks.ServiceAccountIssuerCacheLifetime))
	if err != nil {
		return iam.OIDCDiscoveryResult{}, err
	}
	if len(d.thumbprints) != 0 {
		result.Thumbprints = append([]string(nil), d.thumbprints...)
	} else if len(request.Thumbprints) == 0 {
		return iam.OIDCDiscoveryResult{}, errors.New("EKS issuer automatic thumbprint discovery requires a configured frontend TLS certificate")
	}
	return result, nil
}
