package integrations

import (
	"context"
	"errors"
	"net/http"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/gateway"
	"stackd/internal/identity"
	"stackd/internal/jwt"
	"stackd/internal/services/iam"
)

// AppSyncCredentials is the credential authority needed by live subscriptions.
// Resolve checks current key status and temporary credential expiration.
type AppSyncCredentials interface {
	Resolve(context.Context, string) (identity.Credential, error)
}

// AppSyncIAM reuses the gateway's only SigV4 verifier and the issuing authority.
type AppSyncIAM struct {
	Gateway     *gateway.Gateway
	Credentials AppSyncCredentials
}

func (a AppSyncIAM) Authenticate(r *http.Request, signingName, region string) (*http.Request, *awswire.Error) {
	if a.Gateway == nil || a.Credentials == nil {
		return nil, &awswire.Error{Code: "UnauthorizedException", Message: "IAM authentication is not configured", StatusCode: http.StatusUnauthorized}
	}
	return a.Gateway.Authenticate(r, signingName, region)
}

func (a AppSyncIAM) Revalidate(ctx context.Context) error {
	if a.Credentials == nil {
		return errors.New("IAM credential authority is not configured")
	}
	previous := awsctx.FromContext(ctx)
	credential, err := a.Credentials.Resolve(ctx, previous.AccessKeyID)
	if err != nil {
		return err
	}
	current, err := identity.RequestMetadata(credential, previous.AccessKeyID, previous.Region, previous.RequestID)
	if err != nil {
		return err
	}
	if current.AccountID != previous.AccountID || current.PrincipalID != previous.PrincipalID || current.PrincipalARN != previous.PrincipalARN || current.IssuerID != previous.IssuerID || current.SessionType != previous.SessionType || !current.TokenIssueTime.Equal(previous.TokenIssueTime) {
		return errors.New("authenticated credential identity changed")
	}
	return nil
}

// AppSyncKeys selects Cognito pools by configured partition/region/ID and reuses
// the existing configured OIDC discovery. Cross-account pools are supported:
// AppSync's pool config names no account, and Cognito owns the unique pool ID.
type AppSyncKeys struct {
	Cognito   CognitoPublicKeys
	Discovery iam.OIDCDiscovery
}

func (k AppSyncKeys) UserPool(ctx context.Context, partition, region, poolID string) (jwt.KeySet, error) {
	if k.Cognito == nil {
		return jwt.KeySet{}, errors.New("cognito public key authority is not configured")
	}
	keys, _, err := k.Cognito.PublicSigningKeys(awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: partition, Region: region}), poolID)
	return keys, err
}

func (k AppSyncKeys) Issuer(ctx context.Context, issuer string) (jwt.KeySet, error) {
	return GatewayKeys(k).Issuer(ctx, issuer)
}
