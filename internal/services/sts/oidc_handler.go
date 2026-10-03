package sts

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/internal/awsapi"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/jwt"
)

var oidcRoleResource = regexp.MustCompile(`^role/(?:[\x21-\x7E]+/)?[A-Za-z0-9_+=,.@-]{1,64}$`)
var oidcRolePartition = regexp.MustCompile(`^[a-z0-9-]+$`)
var oidcRoleAccount = regexp.MustCompile(`^[0-9]{12}$`)

func (s *Service) assumeRoleWithWebIdentity(ctx context.Context) (output *stsapi.AssumeRoleWithWebIdentityOutput, failure *awswire.Error) {
	defer func() {
		if failure != nil {
			if err := s.appendAPICall(ctx, s.now(), "AssumeRoleWithWebIdentity", nil, failure); err != nil {
				output, failure = nil, stsAuditFailure()
			}
		}
	}()
	input, ok := awsapi.Input[stsapi.AssumeRoleWithWebIdentityInput](ctx)
	if !ok {
		return nil, stsValidation("Missing AssumeRoleWithWebIdentity input.")
	}
	roleARN := value(input.RoleArn)
	role, err := arn.Parse(roleARN)
	if err != nil || role.Service != "iam" || role.Region != "" || !oidcRoleAccount.MatchString(role.AccountID) || !oidcRolePartition.MatchString(role.Partition) || !oidcRoleResource.MatchString(role.Resource) {
		return nil, stsValidation("RoleArn must identify an IAM role.")
	}
	metadata := awsctx.FromContext(ctx)
	if metadata.Partition != "" && metadata.Partition != role.Partition {
		return nil, stsValidation("The requested role is in a different AWS partition.")
	}
	duration := time.Hour
	if input.DurationSeconds != nil {
		duration = time.Duration(*input.DurationSeconds) * time.Second
	}
	if duration < 15*time.Minute || duration > 12*time.Hour {
		return nil, stsValidation("DurationSeconds must be between 900 and 43200 seconds.")
	}
	// For this unsigned action the validated role ARN selects the provider's
	// storage scope. Neither the ARN nor the JWT supplies an AWS caller identity.
	metadata.AccountID, metadata.Partition = role.AccountID, role.Partition
	ctx = awsctx.WithMetadata(ctx, metadata)
	verified, provider, apiErr := s.authenticateWebIdentity(ctx, value(input.WebIdentityToken), value(input.ProviderId))
	if apiErr != nil {
		return nil, apiErr
	}
	roleAuthorizedByIDP, apiErr := verified.authorizeRole(roleARN)
	if apiErr != nil {
		return nil, apiErr
	}
	ctx = context.WithValue(ctx, federationAuditKey{}, federationAudit{
		Identity:       webIdentityAudit(provider.ARN, verified.audience, verified.subject),
		SourceIdentity: verified.sourceIdentity, Tags: verified.tags, TransitiveTagKeys: verified.transitive,
	})
	return issueFederatedRole(s, ctx, FederatedRoleRequest{
		Action: "sts:AssumeRoleWithWebIdentity", ProviderARN: provider.ARN, ProviderID: provider.ID, ProviderVersion: provider.Version,
		RoleARN: roleARN, SessionName: value(input.RoleSessionName), SourceIdentity: verified.sourceIdentity, Subject: verified.subject,
		Duration: duration, Policy: value(input.Policy), PolicyARNs: input.PolicyArns, HasSessionPolicy: input.Policy != nil || len(input.PolicyArns) > 0,
		Tags: verified.tags, TransitiveTagKeys: verified.transitive, TrustContext: verified.trustContext, SessionContext: verified.sessionContext,
		RoleAuthorizedByIDP:    roleAuthorizedByIDP,
		AuthenticationNotAfter: verified.authenticationNotAfter,
	}, func(issued FederatedRoleResult) *stsapi.AssumeRoleWithWebIdentityOutput {
		// JWT expiry limits authentication, not the lifetime of minted credentials.
		output := &stsapi.AssumeRoleWithWebIdentityOutput{
			Credentials:     credentialOutput(issued.Credential),
			AssumedRoleUser: &stsapi.AssumedRoleUser{Arn: ptr(stsapi.ArnType(issued.Credential.PrincipalARN)), AssumedRoleId: ptr(stsapi.AssumedRoleIdType(issued.Credential.PrincipalID))},
			Audience:        ptr(stsapi.Audience(verified.audience)), Provider: ptr(stsapi.Issuer(provider.ARN)),
			SubjectFromWebIdentityToken: ptr(stsapi.WebIdentitySubjectType(verified.subject)), PackedPolicySize: ptr(stsapi.NonNegativeIntegerType(issued.PackedPolicySize)),
		}
		if verified.sourceIdentity != "" {
			output.SourceIdentity = ptr(stsapi.SourceIdentityType(verified.sourceIdentity))
		}
		return output
	})
}

func (s *Service) authenticateWebIdentity(ctx context.Context, raw, providerID string) (oidcIdentity, OIDCProviderSnapshot, *awswire.Error) {
	if providerID != "" {
		return s.authenticateOAuthIdentity(ctx, raw, providerID)
	}
	token, apiErr := parseOIDCJWT(raw)
	if apiErr != nil {
		return oidcIdentity{}, OIDCProviderSnapshot{}, apiErr
	}
	issuer, ok := jwt.String(token.Claims, "iss")
	if !ok {
		return oidcIdentity{}, OIDCProviderSnapshot{}, invalidOIDCToken("The issuer claim must be a string.")
	}
	issuerURL, err := url.Parse(issuer)
	if err == nil && strings.HasSuffix(strings.ToLower(issuerURL.Hostname()), ".tokens.sts.global.api.aws") {
		return oidcIdentity{}, OIDCProviderSnapshot{}, invalidOIDCToken("Outbound web identity tokens cannot be used for AWS federation.")
	}
	if s.outboundWebIdentity != nil {
		outbound, err := s.outboundWebIdentity.IsOutboundWebIdentityIssuer(ctx, issuer)
		if err != nil {
			return oidcIdentity{}, OIDCProviderSnapshot{}, oidcProviderError("Unable to resolve the token issuer.")
		}
		if outbound {
			return oidcIdentity{}, OIDCProviderSnapshot{}, invalidOIDCToken("Outbound web identity tokens cannot be used for AWS federation.")
		}
	}
	m := awsctx.FromContext(ctx)
	principal, apiErr := oidcIssuerPrincipal(issuer, m.Partition, m.AccountID)
	if apiErr != nil {
		return oidcIdentity{}, OIDCProviderSnapshot{}, apiErr
	}
	if s.oidcProviders == nil {
		return oidcIdentity{}, OIDCProviderSnapshot{}, oidcProviderError("No OIDC provider source is configured.")
	}
	provider, err := s.oidcProviders.OIDCProviderForFederation(ctx, principal)
	if err != nil {
		return oidcIdentity{}, OIDCProviderSnapshot{}, oidcSourceError(err)
	}
	if provider.ARN != principal || provider.ID == "" || provider.Version == "" {
		return oidcIdentity{}, OIDCProviderSnapshot{}, invalidOIDCToken("The requested OIDC provider could not be verified.")
	}
	verified, apiErr := s.verifyConfiguredOIDC(ctx, token, provider)
	return verified, provider, apiErr
}

func (s *Service) authenticateOAuthIdentity(ctx context.Context, raw, providerID string) (oidcIdentity, OIDCProviderSnapshot, *awswire.Error) {
	if providerID != "www.amazon.com" && providerID != "graph.facebook.com" {
		return oidcIdentity{}, OIDCProviderSnapshot{}, stsDenied("Unrecognized OAuth provider. Do not include a provider parameter when submitting OpenIDConnect ID tokens")
	}
	if providerID == "www.amazon.com" {
		if _, err := parseOIDCJWT(raw); err == nil {
			return oidcIdentity{}, OIDCProviderSnapshot{}, invalidOIDCToken("Provided Token is not a Login With Amazon token")
		}
	}
	if s.oauthTokens == nil {
		return oidcIdentity{}, OIDCProviderSnapshot{}, oidcProviderError("No OAuth token verification source is configured.")
	}
	verified, err := s.oauthTokens.VerifyOAuthAccessToken(ctx, providerID, raw)
	if err != nil {
		return oidcIdentity{}, OIDCProviderSnapshot{}, oidcSourceError(err)
	}
	if verified.ProviderID != providerID || verified.Subject == "" || verified.Audience == "" {
		return oidcIdentity{}, OIDCProviderSnapshot{}, invalidOIDCToken("The verified OAuth identity does not match the requested provider.")
	}
	// Introspection results may contain only that fixed provider's verified
	// claims. The common issuer also validates every trust/session context key.
	for key := range verified.TrustContext {
		if !strings.HasPrefix(strings.ToLower(key), providerID+":") {
			return oidcIdentity{}, OIDCProviderSnapshot{}, invalidOIDCToken("Invalid OAuth identity context.")
		}
	}
	return oidcIdentity{issuer: providerID, subject: verified.Subject, audience: verified.Audience, trustContext: verified.TrustContext, sessionContext: verified.SessionContext, authenticationNotAfter: verified.ExpiresAt}, OIDCProviderSnapshot{ARN: providerID, ID: providerID, Version: "builtin-v1"}, nil
}
