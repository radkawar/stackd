package sts

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/jwt"
)

func verifyOIDCJWT(token jwt.Token, provider OIDCProviderSnapshot, keys OIDCKeySet, now time.Time) (oidcIdentity, *awswire.Error) {
	verified, apiErr := validateOIDCClaims(token.Claims, now)
	if apiErr != nil {
		return oidcIdentity{}, apiErr
	}
	expected := provider.IssuerURL
	issuer := verified.issuer
	// Google explicitly accepts either spelling of its built-in issuer. Other
	// issuer URLs are exact, including case and path/trailing-slash components.
	if provider.ARN == "accounts.google.com" && issuer == "accounts.google.com" {
		issuer = "https://accounts.google.com"
	}
	if issuer != expected || keys.IssuerURL != expected || keys.ProviderID != provider.ID || keys.ProviderVersion != provider.Version {
		return oidcIdentity{}, invalidOIDCToken("The token or key set does not match the configured identity provider.")
	}
	if !oidcBuiltinProvider(provider.ARN) && !slices.Contains(provider.ClientIDs, verified.audience) {
		return oidcIdentity{}, invalidOIDCToken("The web identity token audience is not registered with the provider.")
	}
	if apiErr := verifyOIDCSignature(token, keys.Keys, keys.SigningAlgorithms); apiErr != nil {
		return oidcIdentity{}, apiErr
	}
	return verified, nil
}
func oidcBuiltinProvider(principal string) bool {
	return principal == "accounts.google.com" || principal == "cognito-identity.amazonaws.com"
}

func (s *Service) verifyConfiguredOIDC(ctx context.Context, token jwt.Token, provider OIDCProviderSnapshot) (oidcIdentity, *awswire.Error) {
	if s.oidcProviders == nil {
		return oidcIdentity{}, oidcProviderError("No OIDC provider source is configured.")
	}
	if err := ctx.Err(); err != nil {
		return oidcIdentity{}, oidcProviderError("Identity provider verification was canceled.")
	}
	keys, cached, err := s.oidcKeys.resolve(ctx, s.oidcProviders, provider, s.now(), false)
	if err != nil {
		return oidcIdentity{}, oidcSourceError(err)
	}
	verified, apiErr := verifyOIDCJWT(token, provider, keys, s.now())
	if apiErr != nil && cached {
		// A cached key set may predate a signing-key rotation. Fetch at most once
		// more, and still bind refreshed keys to this exact provider configuration.
		keys, _, err = s.oidcKeys.resolve(ctx, s.oidcProviders, provider, s.now(), true)
		if err != nil {
			return oidcIdentity{}, oidcSourceError(err)
		}
		verified, apiErr = verifyOIDCJWT(token, provider, keys, s.now())
	}
	if apiErr != nil {
		return oidcIdentity{}, apiErr
	}
	current, err := s.oidcProviders.OIDCProviderForFederation(ctx, provider.ARN)
	if err != nil {
		return oidcIdentity{}, oidcSourceError(err)
	}
	if current.ID != provider.ID || current.Version != provider.Version || current.IssuerURL != provider.IssuerURL || !slices.Equal(current.ClientIDs, provider.ClientIDs) || !slices.Equal(current.Thumbprints, provider.Thumbprints) {
		return oidcIdentity{}, invalidOIDCToken("The identity provider changed during token verification.")
	}
	return verified, nil
}
func oidcSourceError(err error) *awswire.Error {
	if errors.Is(err, ErrFederationProviderNotFound) {
		return invalidOIDCToken("No OpenIDConnect provider found for the configured issuer.")
	}
	var apiErr *awswire.Error
	if errors.As(err, &apiErr) {
		return apiErr
	}
	// Do not echo discovery errors: HTTP errors may contain token-bearing URLs.
	return oidcProviderError("Unable to retrieve the identity provider's verification keys.")
}

func oidcIssuerPrincipal(issuer, partition, accountID string) (string, *awswire.Error) {
	if issuer == "accounts.google.com" || issuer == "https://accounts.google.com" {
		return "accounts.google.com", nil
	}
	if issuer == "cognito-identity.amazonaws.com" || issuer == "https://cognito-identity.amazonaws.com" {
		return "cognito-identity.amazonaws.com", nil
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || (parsed.Port() != "" && parsed.Port() != "443") || strings.Contains(parsed.Hostname(), ":") {
		return "", invalidOIDCToken("The token issuer must identify a configured HTTPS provider.")
	}
	return "arn:" + partition + ":iam::" + accountID + ":oidc-provider/" + parsed.Hostname() + parsed.EscapedPath(), nil
}
