package integrations

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/cognitoidentity"
	"stackd/internal/services/sts"
)

type CognitoIdentityTokens struct{ Cognito cognitoidentity.TokenVerifier }

func (a CognitoIdentityTokens) VerifyIdentityToken(ctx context.Context, poolID, clientID, token string, check bool) (map[string]any, error) {
	if a.Cognito == nil {
		return nil, errors.New("cognito user-pool authority unavailable")
	}
	region, _, ok := strings.Cut(poolID, "_")
	if !ok {
		return nil, errors.New("invalid user-pool identifier")
	}
	metadata := awsctx.FromContext(ctx)
	metadata.Region = region
	return a.Cognito.VerifyIdentityToken(awsctx.WithMetadata(ctx, metadata), poolID, clientID, token, check)
}

type CognitoIdentitySTS interface {
	IssueFederatedRole(context.Context, sts.FederatedRoleRequest) (identity.Credential, error)
}
type CognitoIdentityCredentials struct{ STS CognitoIdentitySTS }

func (a CognitoIdentityCredentials) IssueIdentityCredentials(ctx context.Context, in cognitoidentity.CredentialRequest) (identity.Credential, error) {
	if a.STS == nil {
		return identity.Credential{}, errors.New("STS federation authority unavailable")
	}
	const provider = "cognito-identity.amazonaws.com"
	amr := "unauthenticated"
	if in.Authenticated {
		amr = "authenticated"
	}
	claims := map[string][]string{provider + ":aud": {in.PoolID}, provider + ":sub": {in.IdentityID}, provider + ":amr": {amr}}
	var deadline *time.Time
	if !in.Expires.IsZero() {
		deadline = &in.Expires
	}
	return a.STS.IssueFederatedRole(ctx, sts.FederatedRoleRequest{Action: "sts:AssumeRoleWithWebIdentity", ProviderARN: provider, ProviderID: provider, ProviderVersion: "builtin-v1", RoleARN: in.RoleARN, SessionName: "CognitoIdentityCredentials", Subject: in.IdentityID, Duration: time.Hour, AuthenticationNotAfter: deadline, TrustContext: claims, SessionContext: claims, Tags: in.Tags})
}
