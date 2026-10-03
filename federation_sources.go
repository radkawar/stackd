package stackd

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
	"stackd/internal/services/sts"
)

// iamFederation adapts IAM's typed transaction domain to the STS consumer.
// No provider discovery or other network calls run inside the authority callback.
type iamFederation struct {
	service     *iam.Service
	credentials *identity.Store
	discovery   OIDCDiscovery
}

func (f iamFederation) WithFederationSession(ctx context.Context, provider sts.FederationProviderReference, roleARN string, fn func(context.Context, sts.RoleSnapshot, sts.FederatedCredentialIssuer) error) error {
	err := f.service.WithFederationSession(ctx, iam.FederationProviderReference{ARN: provider.ARN, ID: provider.ID, Version: provider.Version}, roleARN, func(ctx context.Context, role iam.RoleSnapshot, repository identity.Repository) error {
		current := sts.RoleSnapshot{ARN: role.ARN, ID: role.ID, Name: role.Name, TrustPolicy: role.TrustPolicy, TrustPrincipalIDs: role.TrustPrincipalIDs, MaxSessionDuration: role.MaxSessionDuration, Tags: role.Tags, EvaluationTime: &role.EvaluationTime, ServiceLinkedRole: role.ServiceLinkedRole}
		return fn(ctx, current, f.credentials.WithRepositoryAt(repository, role.EvaluationTime))
	})
	if errors.Is(err, iam.ErrFederationRoleNotFound) {
		return &awswire.Error{Code: "AccessDenied", Message: "The requested role does not exist or cannot be assumed.", StatusCode: 403}
	}
	if errors.Is(err, iam.ErrRecordNotFound) || errors.Is(err, iam.ErrFederationProviderChanged) {
		return &awswire.Error{Code: "InvalidIdentityToken", Message: "The identity provider changed before credentials could be issued.", StatusCode: 400}
	}
	return err
}

func (f iamFederation) OIDCProviderForFederation(ctx context.Context, reference string) (sts.OIDCProviderSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return sts.OIDCProviderSnapshot{}, err
	}
	switch reference {
	case "accounts.google.com", "cognito-identity.amazonaws.com":
		return sts.OIDCProviderSnapshot{ARN: reference, ID: reference, Version: "builtin-v1", IssuerURL: "https://" + reference}, nil
	}
	provider, err := f.service.OIDCProviderForFederation(ctx, reference)
	if err != nil {
		return sts.OIDCProviderSnapshot{}, federationSourceError(err)
	}
	return sts.OIDCProviderSnapshot{ARN: provider.ARN, ID: provider.ID, Version: iam.OIDCProviderVersion(provider), IssuerURL: "https://" + provider.URL, ClientIDs: provider.ClientIDs, Thumbprints: provider.Thumbprints}, nil
}

func (f iamFederation) ResolveOIDCSigningKeys(ctx context.Context, reference string) (sts.OIDCKeySet, error) {
	before, err := f.OIDCProviderForFederation(ctx, reference)
	if err != nil {
		return sts.OIDCKeySet{}, err
	}
	var discovered OIDCDiscoveryResult
	switch reference {
	case "accounts.google.com", "cognito-identity.amazonaws.com":
		if f.discovery == nil {
			return sts.OIDCKeySet{}, fmt.Errorf("no OIDC discovery source configured")
		}
		discovered, err = f.discovery.Discover(ctx, OIDCDiscoveryRequest{IssuerURL: before.IssuerURL})
	default:
		discovered, err = f.service.ResolveOIDCSigningKeys(ctx, reference)
	}
	if err != nil {
		return sts.OIDCKeySet{}, federationSourceError(err)
	}
	after, err := f.OIDCProviderForFederation(ctx, reference)
	if err != nil {
		return sts.OIDCKeySet{}, err
	}
	if before.ID != after.ID || before.Version != after.Version || discovered.IssuerURL != before.IssuerURL {
		return sts.OIDCKeySet{}, &awswire.Error{Code: "InvalidIdentityToken", Message: "The identity provider changed during discovery.", StatusCode: 400}
	}
	result := sts.OIDCKeySet{IssuerURL: before.IssuerURL, ProviderID: before.ID, ProviderVersion: before.Version, SigningAlgorithms: slices.Clone(discovered.SigningAlgorithms), CacheUntil: discovered.CacheUntil}
	for _, key := range discovered.SigningKeys {
		out := sts.OIDCSigningKey(key)
		out.Operations = slices.Clone(key.Operations)
		out.Certificates = cloneFederationBytes(key.Certificates)
		result.Keys = append(result.Keys, out)
	}
	return result, nil
}

func (f iamFederation) SAMLProviderForFederation(ctx context.Context, reference string) (sts.SAMLProviderSnapshot, error) {
	provider, err := f.service.SAMLProviderForFederation(ctx, reference)
	if err != nil {
		return sts.SAMLProviderSnapshot{}, federationSourceError(err)
	}
	result := sts.SAMLProviderSnapshot{ARN: provider.ARN, ID: provider.UUID, Version: iam.SAMLProviderVersion(provider), AssertionEncryptionMode: provider.AssertionEncryptionMode, ValidUntil: provider.ValidUntil}
	for _, issuer := range provider.Issuers {
		result.Issuers = append(result.Issuers, sts.SAMLIssuerSnapshot{EntityID: issuer.EntityID, SigningCertificates: cloneFederationBytes(issuer.SigningCertificates)})
	}
	for _, key := range provider.PrivateKeys {
		result.PrivateKeys = append(result.PrivateKeys, sts.SAMLDecryptionKey{ID: key.ID, PKCS8DER: slices.Clone(key.PKCS8DER)})
	}
	return result, nil
}

func federationSourceError(err error) error {
	if errors.Is(err, iam.ErrFederationProviderChanged) {
		return &awswire.Error{Code: "InvalidIdentityToken", Message: "The identity provider changed during discovery.", StatusCode: 400}
	}
	if errors.Is(err, iam.ErrRecordNotFound) {
		return sts.ErrFederationProviderNotFound
	}
	return err
}

func cloneFederationBytes(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	result := make([][]byte, len(values))
	for i, value := range values {
		result[i] = slices.Clone(value)
	}
	return result
}
