package integrations

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/awsctx"
	"stackd/internal/jwt"
	"stackd/internal/services/iam"
)

// CognitoPublicKeys exposes public pool material without token/session admission.
type CognitoPublicKeys interface {
	PublicSigningKeys(context.Context, string) (jwt.KeySet, string, error)
}

// GatewayKeys resolves configured issuers. Discovery is explicitly injected;
// token headers can never select a network endpoint or establish trust.
type GatewayKeys struct {
	Cognito   CognitoPublicKeys
	Discovery iam.OIDCDiscovery
}

func (k GatewayKeys) UserPool(ctx context.Context, resource string) (jwt.KeySet, error) {
	parsed, err := arn.Parse(resource)
	if err != nil || parsed.Service != "cognito-idp" || !strings.HasPrefix(parsed.Resource, "userpool/") {
		return jwt.KeySet{}, errors.New("invalid Cognito user pool ARN")
	}
	if k.Cognito == nil {
		return jwt.KeySet{}, errors.New("public Cognito key source is not configured")
	}
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.Region = parsed.Partition, parsed.Region
	keys, owner, err := k.Cognito.PublicSigningKeys(awsctx.WithMetadata(ctx, metadata), strings.TrimPrefix(parsed.Resource, "userpool/"))
	if err != nil {
		return jwt.KeySet{}, err
	}
	if owner != resource {
		return jwt.KeySet{}, errors.New("user pool ARN does not match public key owner")
	}
	return keys, nil
}

func (k GatewayKeys) Issuer(ctx context.Context, issuer string) (jwt.KeySet, error) {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return jwt.KeySet{}, err
	}
	poolID := strings.TrimPrefix(parsed.Path, "/")
	if region, _, ok := strings.Cut(poolID, "_"); ok && !strings.Contains(poolID, "/") && k.Cognito != nil {
		metadata := awsctx.FromContext(ctx)
		metadata.Region = region
		keys, _, err := k.Cognito.PublicSigningKeys(awsctx.WithMetadata(ctx, metadata), poolID)
		if err == nil && keys.Issuer == issuer {
			return keys, nil
		}
	}
	if k.Discovery == nil {
		return jwt.KeySet{}, errors.New("external OIDC discovery is not configured")
	}
	found, err := k.Discovery.Discover(ctx, iam.OIDCDiscoveryRequest{IssuerURL: issuer})
	if err != nil {
		return jwt.KeySet{}, err
	}
	result := jwt.KeySet{Issuer: found.IssuerURL, Keys: make(map[string]*rsa.PublicKey)}
	for _, key := range found.SigningKeys {
		if key.Type != "RSA" || key.ID == "" || (key.Use != "" && key.Use != "sig") {
			continue
		}
		public, err := jwt.RSAKey(key.N, key.E)
		if err != nil {
			return jwt.KeySet{}, err
		}
		result.Keys[key.ID] = public
	}
	return result, nil
}
