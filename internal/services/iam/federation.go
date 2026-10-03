package iam

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) federationHandlers() map[string]handler {
	return map[string]handler{
		"CreateOpenIDConnectProvider": s.createOIDCProvider, "GetOpenIDConnectProvider": getOIDCProvider, "ListOpenIDConnectProviders": listOIDCProviders, "DeleteOpenIDConnectProvider": deleteOIDCProvider,
		"AddClientIDToOpenIDConnectProvider": addOIDCClientID, "RemoveClientIDFromOpenIDConnectProvider": removeOIDCClientID, "UpdateOpenIDConnectProviderThumbprint": updateOIDCThumbprints,
		"CreateSAMLProvider": createSAMLProvider, "GetSAMLProvider": getSAMLProvider, "ListSAMLProviders": listSAMLProviders, "DeleteSAMLProvider": deleteSAMLProvider, "UpdateSAMLProvider": updateSAMLProvider,
		"TagOpenIDConnectProvider": tagResource, "UntagOpenIDConnectProvider": untagResource, "ListOpenIDConnectProviderTags": listResourceTags,
		"TagSAMLProvider": tagResource, "UntagSAMLProvider": untagResource, "ListSAMLProviderTags": listResourceTags,
	}
}

// SetOIDCDiscovery installs the explicit provider-discovery dependency. A nil
// source disables outbound provider requests; it never selects a network fallback.
func (s *Service) SetOIDCDiscovery(source OIDCDiscovery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oidcDiscovery = source
}

func federationNeedsPreparation(ctx context.Context) bool {
	in, ok := awsapi.Input[iamapi.CreateOpenIDConnectProviderInput](ctx)
	return ok && len(in.ThumbprintList) == 0
}

type preparedOIDCKey struct{}

func (s *Service) prepareFederationRequest(ctx context.Context) (context.Context, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.CreateOpenIDConnectProviderInput](ctx)
	if err != nil {
		return ctx, err
	}
	issuer, err := oidcURL(inputString(input.Url))
	if err != nil {
		return ctx, err
	}
	s.mu.Lock()
	source := s.oidcDiscovery
	s.mu.Unlock()
	if source == nil {
		return ctx, oidcCommunicationError("No OIDC discovery source is configured.")
	}
	result, discoveryErr := source.Discover(ctx, OIDCDiscoveryRequest{IssuerURL: "https://" + issuer})
	if discoveryErr != nil {
		return ctx, oidcCommunicationError(discoveryErr.Error())
	}
	if result.IssuerURL != "https://"+issuer {
		return ctx, oidcCommunicationError("The discovery issuer does not match the configured provider URL.")
	}
	thumbprints, err := oidcThumbprints(result.Thumbprints)
	if err != nil {
		return ctx, oidcCommunicationError("Unable to obtain the provider certificate thumbprint.")
	}
	return context.WithValue(ctx, preparedOIDCKey{}, thumbprints), nil
}
func oidcCommunicationError(message string) *awswire.Error {
	return &awswire.Error{Code: "OpenIdIdpCommunicationError", StatusCode: 400, Message: message}
}

// OIDCProviderForFederation returns a detached configured provider snapshot in
// the current partition. STS verifies role/account trust before minting a session.
func (s *Service) OIDCProviderForFederation(ctx context.Context, arn string) (OIDCProviderRecord, error) {
	scope, err := federationScope(ctx, arn, "oidc-provider/")
	if err != nil {
		return OIDCProviderRecord{}, err
	}
	var result OIDCProviderRecord
	err = s.view(ctx, func(tx ReadTx) error { var err error; result, err = tx.OIDCProvider(scope, arn); return err })
	return result, err
}

// SAMLProviderForFederation returns detached metadata and decryption keys to a
// trusted STS consumer. Keys are never returned by public IAM operations.
func (s *Service) SAMLProviderForFederation(ctx context.Context, arn string) (SAMLProviderRecord, error) {
	scope, err := federationScope(ctx, arn, "saml-provider/")
	if err != nil {
		return SAMLProviderRecord{}, err
	}
	var result SAMLProviderRecord
	err = s.view(ctx, func(tx ReadTx) error { var err error; result, err = tx.SAMLProvider(scope, arn); return err })
	return result, err
}
func federationScope(ctx context.Context, arn, prefix string) (Scope, error) {
	m := awsctx.FromContext(ctx)
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != m.Partition || parts[2] != "iam" || parts[3] != "" || !strings.HasPrefix(parts[5], prefix) {
		return Scope{}, fmt.Errorf("invalid federation provider ARN")
	}
	return Scope{Partition: m.Partition, AccountID: parts[4]}, nil
}

// ResolveOIDCSigningKeys obtains keys only from the configured issuer's discovery
// document. No token-provided URL is used. The provider snapshot is revalidated
// after discovery so deletion/recreation and concurrent trust changes fail closed.
func (s *Service) ResolveOIDCSigningKeys(ctx context.Context, arn string) (OIDCDiscoveryResult, error) {
	provider, err := s.OIDCProviderForFederation(ctx, arn)
	if err != nil {
		return OIDCDiscoveryResult{}, err
	}
	s.mu.Lock()
	source := s.oidcDiscovery
	s.mu.Unlock()
	if source == nil {
		return OIDCDiscoveryResult{}, fmt.Errorf("no OIDC discovery source configured")
	}
	result, err := source.Discover(ctx, OIDCDiscoveryRequest{IssuerURL: "https://" + provider.URL, Thumbprints: slices.Clone(provider.Thumbprints)})
	if err != nil {
		return OIDCDiscoveryResult{}, err
	}
	if result.IssuerURL != "https://"+provider.URL {
		return OIDCDiscoveryResult{}, fmt.Errorf("OIDC issuer does not match configured provider")
	}
	current, err := s.OIDCProviderForFederation(ctx, arn)
	if err != nil {
		return OIDCDiscoveryResult{}, err
	}
	if current.ID != provider.ID || !slices.Equal(current.Thumbprints, provider.Thumbprints) || !slices.Equal(current.ClientIDs, provider.ClientIDs) {
		return OIDCDiscoveryResult{}, ErrFederationProviderChanged
	}
	return cloneOIDCDiscovery(result), nil
}
func cloneOIDCDiscovery(result OIDCDiscoveryResult) OIDCDiscoveryResult {
	result.SigningAlgorithms = slices.Clone(result.SigningAlgorithms)
	result.Thumbprints = slices.Clone(result.Thumbprints)
	result.SigningKeys = slices.Clone(result.SigningKeys)
	for i := range result.SigningKeys {
		result.SigningKeys[i].Certificates = cloneFederationBytes(result.SigningKeys[i].Certificates)
		result.SigningKeys[i].Operations = slices.Clone(result.SigningKeys[i].Operations)
	}
	return result
}

func federationAuthorizationResource(ctx context.Context, a *account, m awsctx.Metadata) (string, []Tag, bool) {
	decoded, _ := awsapi.FromContext(ctx)
	var arn string
	var oidc bool
	switch in := decoded.Input.(type) {
	case *iamapi.ListOpenIDConnectProvidersInput, *iamapi.ListSAMLProvidersInput:
		return "*", nil, true
	case *iamapi.CreateOpenIDConnectProviderInput:
		issuer, err := oidcURL(inputString(in.Url))
		if err != nil {
			return "*", nil, true
		}
		return "arn:" + m.Partition + ":iam::" + m.AccountID + ":oidc-provider/" + issuer, nil, true
	case *iamapi.CreateSAMLProviderInput:
		return "arn:" + m.Partition + ":iam::" + m.AccountID + ":saml-provider/" + inputString(in.Name), nil, true
	case *iamapi.GetOpenIDConnectProviderInput:
		arn, oidc = inputString(in.OpenIDConnectProviderArn), true
	case *iamapi.DeleteOpenIDConnectProviderInput:
		arn, oidc = inputString(in.OpenIDConnectProviderArn), true
	case *iamapi.AddClientIDToOpenIDConnectProviderInput:
		arn, oidc = inputString(in.OpenIDConnectProviderArn), true
	case *iamapi.RemoveClientIDFromOpenIDConnectProviderInput:
		arn, oidc = inputString(in.OpenIDConnectProviderArn), true
	case *iamapi.UpdateOpenIDConnectProviderThumbprintInput:
		arn, oidc = inputString(in.OpenIDConnectProviderArn), true
	case *iamapi.TagOpenIDConnectProviderInput:
		arn, oidc = inputString(in.OpenIDConnectProviderArn), true
	case *iamapi.UntagOpenIDConnectProviderInput:
		arn, oidc = inputString(in.OpenIDConnectProviderArn), true
	case *iamapi.ListOpenIDConnectProviderTagsInput:
		arn, oidc = inputString(in.OpenIDConnectProviderArn), true
	case *iamapi.GetSAMLProviderInput:
		arn = inputString(in.SAMLProviderArn)
	case *iamapi.DeleteSAMLProviderInput:
		arn = inputString(in.SAMLProviderArn)
	case *iamapi.UpdateSAMLProviderInput:
		arn = inputString(in.SAMLProviderArn)
	case *iamapi.TagSAMLProviderInput:
		arn = inputString(in.SAMLProviderArn)
	case *iamapi.UntagSAMLProviderInput:
		arn = inputString(in.SAMLProviderArn)
	case *iamapi.ListSAMLProviderTagsInput:
		arn = inputString(in.SAMLProviderArn)
	default:
		return "", nil, false
	}
	if oidc {
		if p := a.oidcProviders[arn]; p != nil {
			return arn, p.Tags, true
		}
	} else if p := a.samlProviders[arn]; p != nil {
		return arn, p.Tags, true
	}
	return arn, nil, true
}
