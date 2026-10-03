package sts

import (
	"context"
	"errors"
	"time"

	"stackd/internal/awsapi"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

func (s *Service) getSessionToken(ctx context.Context) (*stsapi.GetSessionTokenOutput, *awswire.Error) {
	return withSignedSession(s, ctx, "GetSessionToken", (*signedSession).getSessionToken)
}

func (s *signedSession) getSessionToken(ctx context.Context) (*stsapi.GetSessionTokenOutput, *awswire.Error) {
	input, ok := awsapi.Input[stsapi.GetSessionTokenInput](ctx)
	if !ok {
		return nil, stsValidation("Missing GetSessionToken input.")
	}
	duration := 12 * time.Hour
	if input.DurationSeconds != nil {
		duration = time.Duration(*input.DurationSeconds) * time.Second
	}
	parent, ctx, apiErr := s.parent(ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if parent.SessionToken != "" {
		return nil, stsCredentialError(identity.ErrSessionCredentials)
	}
	mfaTime, apiErr := s.verifyMFA(ctx, value(input.SerialNumber), value(input.TokenCode))
	if apiErr != nil {
		return nil, apiErr
	}
	legacy, apiErr := s.defaultRegionsOnly(ctx, parent.AccountID, s.now().UTC())
	if apiErr != nil {
		return nil, apiErr
	}
	c, err := s.credentials.IssueSession(ctx, parent, identity.SessionSpec{Duration: duration, MFAPresent: value(input.SerialNumber) != "", MFAAuthenticatedAt: mfaTime, DefaultRegionsOnly: legacy})
	if err != nil {
		return nil, stsCredentialError(err)
	}
	return &stsapi.GetSessionTokenOutput{Credentials: credentialOutput(c)}, nil
}

func (s *signedSession) parent(ctx context.Context) (identity.Credential, context.Context, *awswire.Error) {
	m := awsctx.FromContext(ctx)
	c, err := s.credentials.Resolve(ctx, m.AccessKeyID)
	if err != nil {
		return identity.Credential{}, ctx, stsCredentialError(err)
	}
	if c.AccountID != m.AccountID || c.PrincipalID != m.PrincipalID {
		return identity.Credential{}, ctx, stsCredentialError(identity.ErrInvalidPrincipal)
	}
	// Bootstrap roots are partition-agnostic signing fixtures. Issued tokens
	// retain the partition of the verified request, like all other credentials.
	if c.SessionType == "" && (c.AccessKeyID == "test" || c.AccessKeyID == c.AccountID) {
		c.PrincipalARN = m.PrincipalARN
	}
	m.PrincipalARN, m.PrincipalID, m.UserName = c.PrincipalARN, c.PrincipalID, c.UserName
	m.SessionType, m.IssuerARN, m.IssuerID = string(c.SessionType), c.IssuerARN, c.IssuerID
	m.SessionPolicies, m.SessionPolicyARNs, m.HasSessionPolicy = c.SessionPolicies, c.SessionPolicyARNs, c.HasSessionPolicy
	m.SessionContext, m.SessionTags, m.TransitiveTagKeys = c.SessionContext, c.SessionTags, c.TransitiveTagKeys
	m.FederatedProvider = c.FederatedProvider
	m.SourceIdentity, m.MFAPresent, m.MFAAuthenticatedAt = c.SourceIdentity, c.MFAPresent, c.MFAAuthenticatedAt
	m.TokenIssueTime = time.Time{}
	if c.SessionType != "" {
		m.TokenIssueTime = c.CreateDate
	}
	return c, awsctx.WithMetadata(ctx, m), nil
}

func (s *signedSession) verifyMFA(ctx context.Context, serial, code string) (time.Time, *awswire.Error) {
	if serial == "" && code == "" {
		return time.Time{}, nil
	}
	if serial == "" || code == "" {
		return time.Time{}, stsValidation("MFA requires both SerialNumber and TokenCode.")
	}
	if s.mfa == nil {
		return time.Time{}, &awswire.Error{Code: "NotImplemented", Message: "STS MFA authentication is not configured.", StatusCode: 501}
	}
	stamp, err := s.mfa.VerifyMFA(ctx, serial, code)
	if err != nil {
		var apiErr *awswire.Error
		if errors.Is(err, ErrMFAUnavailable) {
			s.mfaRejection = stsDenied("MultiFactorAuthentication failed, unable to validate MFA code.  Please verify your MFA serial number is valid and associated with this user.")
			return time.Time{}, s.mfaRejection
		}
		if errors.As(err, &apiErr) && apiErr.Code == "InvalidAuthenticationCode" {
			s.mfaRejection = stsDenied("MultiFactorAuthentication failed with invalid MFA one time pass code. ")
			return time.Time{}, s.mfaRejection
		}
		return time.Time{}, stsCredentialError(err)
	}
	return stamp, nil
}

func stsValidation(message string) *awswire.Error {
	return &awswire.Error{Code: "ValidationError", Message: message, StatusCode: 400}
}
func stsDenied(message string) *awswire.Error {
	return &awswire.Error{Code: "AccessDenied", Message: message, StatusCode: 403}
}
func stsCredentialError(err error) *awswire.Error {
	switch {
	case errors.Is(err, identity.ErrSessionCredentials):
		return stsDenied("Cannot issue this session type using temporary credentials.")
	case errors.Is(err, identity.ErrExpired):
		return &awswire.Error{Code: "ExpiredToken", Message: "The security token included in the request is expired.", StatusCode: 403}
	case errors.Is(err, identity.ErrNotFound), errors.Is(err, identity.ErrInactive), errors.Is(err, identity.ErrInvalidPrincipal):
		return &awswire.Error{Code: "InvalidClientTokenId", Message: "The security token included in the request is invalid.", StatusCode: 403}
	case errors.Is(err, identity.ErrInvalidDuration):
		return stsValidation("Invalid session duration.")
	default:
		return &awswire.Error{Code: "InternalFailure", Message: "Unable to issue session credentials.", StatusCode: 500}
	}
}
