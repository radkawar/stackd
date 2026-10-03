package iam

import (
	"context"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

// ValidateFederatedPrincipal resolves role trust providers without treating
// external identities as IAM users or roles. Providers must share the role scope.
func (s *Service) ValidateFederatedPrincipal(ctx context.Context, reference string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch reference {
	case "accounts.google.com", "cognito-identity.amazonaws.com", "www.amazon.com", "graph.facebook.com":
		return nil
	}
	parts := strings.SplitN(reference, ":", 6)
	m := awsctx.FromContext(ctx)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != m.Partition || parts[2] != "iam" || parts[3] != "" || parts[4] != m.AccountID {
		return authorization.ErrInvalidPrincipal
	}
	switch {
	case strings.HasPrefix(parts[5], "oidc-provider/"):
		_, err := s.OIDCProviderForFederation(ctx, reference)
		return err
	case strings.HasPrefix(parts[5], "saml-provider/"):
		_, err := s.SAMLProviderForFederation(ctx, reference)
		return err
	default:
		return authorization.ErrInvalidPrincipal
	}
}
