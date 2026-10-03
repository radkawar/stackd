package sts

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"stackd/iam/policy"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/iam/catalog"
	"stackd/internal/identity"
)

// External federation has authenticated provider claims, not an IAM caller.
// Its trust decision still intersects the destination account's resource controls.
type federationResourceControls interface {
	AuthorizeResourceControls(context.Context, string, policy.Request) *awswire.Error
}

func issueFederatedRole[T any](s *Service, ctx context.Context, request FederatedRoleRequest, output func(FederatedRoleResult) *T) (*T, *awswire.Error) {
	if s.federation == nil {
		return nil, stsDenied("The IAM federation authority is unavailable.")
	}
	if request.Action != "sts:AssumeRoleWithWebIdentity" && request.Action != "sts:AssumeRoleWithSAML" {
		return nil, stsDenied("Invalid federation action.")
	}
	reference := FederationProviderReference{ARN: request.ProviderARN, ID: request.ProviderID, Version: request.ProviderVersion}
	var result *T
	err := s.federation.WithFederationSession(ctx, reference, request.RoleARN, func(ctx context.Context, role RoleSnapshot, issuer FederatedCredentialIssuer) error {
		// External authorities may omit an instant; freeze one at callback entry
		// so expiry and all trust conditions still use the same decision time.
		if role.EvaluationTime == nil {
			now := s.now().UTC()
			role.EvaluationTime = &now
		}
		if role.ARN != request.RoleARN || role.ID == "" || issuer == nil {
			return stsDenied("The requested role cannot be assumed.")
		}
		if deadline := request.AuthenticationNotAfter; deadline != nil && !s.federationTime(role).Before(*deadline) {
			return federationAuthenticationExpired(request)
		}
		if request.Duration < 15*time.Minute || request.Duration > 12*time.Hour || request.Duration > role.MaxSessionDuration {
			return stsValidation("DurationSeconds exceeds the role's MaxSessionDuration or is below 900 seconds.")
		}
		if !request.NotAfter.IsZero() && !request.NotAfter.After(s.federationTime(role)) {
			return &awswire.Error{Code: "ExpiredTokenException", Message: "The federation session has expired.", StatusCode: 400}
		}
		if !samlSessionName.MatchString(request.SessionName) {
			return stsValidation("Invalid RoleSessionName.")
		}
		if request.SourceIdentity != "" && (!oidcSourceIdentity.MatchString(request.SourceIdentity) || strings.HasPrefix(strings.ToLower(request.SourceIdentity), "aws:")) {
			return stsValidation("Invalid SourceIdentity.")
		}
		parts := strings.SplitN(role.ARN, ":", 6)
		if len(parts) != 6 {
			return stsDenied("Invalid role ARN.")
		}
		documents, apiErr := s.sessionPolicies(ctx, parts[4], request.Policy, request.PolicyARNs)
		if apiErr != nil {
			return apiErr
		}
		values, apiErr := s.federationTrustContext(ctx, request, role)
		if apiErr != nil {
			return apiErr
		}
		data, err := policy.TrustResourcePolicy([]byte(role.TrustPolicy))
		if err != nil {
			return stsDenied("The role trust policy cannot be evaluated.")
		}
		data, err = policy.RewriteResourcePrincipals(data, role.TrustPrincipalIDs)
		if err != nil {
			return stsDenied("The role trust policy cannot be evaluated.")
		}
		document, err := policy.ParseResource(data)
		if err != nil {
			return stsDenied("The role trust policy cannot be evaluated.")
		}
		actions := []string{request.Action}
		if len(request.Tags) != 0 {
			actions = append(actions, "sts:TagSession")
		}
		if request.SourceIdentity != "" {
			actions = append(actions, "sts:SetSourceIdentity")
		}
		principal := policy.Principal{Federated: request.ProviderARN, Partition: parts[1]}
		contextTypes := catalog.ContextTypes(values)
		for _, action := range actions {
			policyRequest := policy.Request{Action: action, Resource: role.ARN, Context: values, ContextTypes: contextTypes}
			decision, err := policy.EvaluateResource(document, policyRequest, principal)
			if err != nil || decision.Decision != policy.Allow {
				return stsDenied("The role trust policy does not allow " + action + ".")
			}
			if controls, ok := s.authorizer.(federationResourceControls); ok && !role.ServiceLinkedRole {
				if err := controls.AuthorizeResourceControls(ctx, parts[4], policyRequest); err != nil {
					return err
				}
			}
		}
		packed, apiErr := packedSize(request.Policy, request.PolicyARNs, request.Tags)
		if apiErr != nil {
			return apiErr
		}
		legacy, apiErr := s.defaultRegionsOnly(ctx, parts[4], s.federationTime(role))
		if apiErr != nil {
			return apiErr
		}
		credential, err := issuer.IssueFederatedRoleSession(ctx, identity.RoleSessionSpec{
			DefaultRegionsOnly: legacy,
			Role:               identity.Principal{AccountID: parts[4], ARN: role.ARN, ID: role.ID}, SessionName: request.SessionName,
			Duration: request.Duration, MaxSessionDuration: role.MaxSessionDuration, NotAfter: request.NotAfter,
			Policies: documents, PolicyARNs: sessionPolicyARNs(request.PolicyARNs), HasSessionPolicy: request.HasSessionPolicy,
			Tags: request.Tags, TransitiveTagKeys: request.TransitiveTagKeys, SourceIdentity: request.SourceIdentity, SessionContext: request.SessionContext, FederatedProvider: request.ProviderARN,
		})
		if err != nil {
			return stsCredentialError(err)
		}
		result = output(FederatedRoleResult{Credential: credential, PackedPolicySize: packed})
		if err := s.appendAPICall(ctx, s.federationTime(role), strings.TrimPrefix(request.Action, "sts:"), result, nil); err != nil {
			return stsAuditFailure()
		}
		return nil
	})
	if err != nil {
		var apiErr *awswire.Error
		if errors.As(err, &apiErr) {
			return nil, apiErr
		}
		return nil, stsDenied("The identity provider or role changed before credentials could be issued.")
	}
	return result, nil
}

func federationAuthenticationExpired(request FederatedRoleRequest) *awswire.Error {
	if request.Action == "sts:AssumeRoleWithSAML" {
		return samlExpired()
	}
	switch request.ProviderARN {
	case "www.amazon.com":
		return &awswire.Error{Code: "IDPRejectedClaim", StatusCode: 403, Message: "The Amazon access token has expired."}
	case "graph.facebook.com":
		return &awswire.Error{Code: "IDPRejectedClaim", StatusCode: 403, Message: "The Facebook access token has expired."}
	default:
		return &awswire.Error{Code: "ExpiredTokenException", StatusCode: 400, Message: "The web identity token has expired."}
	}
}

func (s *Service) federationTrustContext(ctx context.Context, request FederatedRoleRequest, role RoleSnapshot) (map[string][]string, *awswire.Error) {
	namespace := request.ProviderARN
	if request.Action == "sts:AssumeRoleWithSAML" {
		namespace = "saml"
	} else if _, suffix, ok := strings.Cut(namespace, ":oidc-provider/"); ok {
		namespace = suffix
	}
	prefix := strings.ToLower(namespace) + ":"
	values := make(map[string][]string, len(request.TrustContext)+12)
	for key, val := range request.TrustContext {
		canonical := strings.ToLower(key)
		if !strings.HasPrefix(canonical, prefix) {
			return nil, stsDenied("Invalid federation claim context.")
		}
		if _, exists := values[canonical]; exists {
			return nil, stsDenied("Duplicate federation claim context.")
		}
		values[canonical] = slices.Clone(val)
	}
	for key, val := range request.SessionContext {
		canonical := strings.ToLower(key)
		if !strings.HasPrefix(canonical, prefix) || !slices.Equal(val, values[canonical]) {
			return nil, stsDenied("Invalid federation session context.")
		}
	}
	values["sts:rolesessionname"] = []string{request.SessionName}
	if request.Action == "sts:AssumeRoleWithWebIdentity" {
		values["sts:roleauthorizedbyidp"] = []string{strconv.FormatBool(request.RoleAuthorizedByIDP)}
	}
	if request.SourceIdentity != "" {
		values["sts:sourceidentity"] = []string{request.SourceIdentity}
	}
	for key, value := range request.Tags {
		canonical := strings.ToLower(key)
		contextKey := "aws:requesttag/" + canonical
		if _, exists := values[contextKey]; exists || strings.HasPrefix(canonical, "aws:") {
			return nil, stsValidation("Invalid session tags.")
		}
		values[contextKey] = []string{value}
		values["aws:tagkeys"] = append(values["aws:tagkeys"], key)
	}
	if len(request.Tags) > 50 {
		return nil, stsValidation("At most 50 session tags may be supplied.")
	}
	if len(request.TransitiveTagKeys) != 0 {
		values["sts:transitivetagkeys"] = slices.Clone(request.TransitiveTagKeys)
	}
	for key, value := range role.Tags {
		values["aws:resourcetag/"+strings.ToLower(key)] = []string{value}
	}
	parts := strings.SplitN(role.ARN, ":", 6)
	values["aws:resourceaccount"] = []string{parts[4]}
	// Captured SAML and OIDC trust evaluation: the provider is the external
	// user identity. aws:PrincipalArn is absent; aws:userid holds the provider.
	values["aws:principalaccount"] = []string{parts[4]}
	values["aws:principaltype"] = []string{"User"}
	values["aws:principalisawsservice"] = []string{"false"}
	values["aws:userid"] = []string{request.ProviderARN}

	m := awsctx.FromContext(ctx)
	if m.Region != "" {
		values["aws:requestedregion"] = []string{m.Region}
	}
	if m.TransportKnown {
		if m.SourceIP != "" {
			values["aws:sourceip"] = []string{m.SourceIP}
		}
		values["aws:securetransport"] = []string{strconv.FormatBool(m.SecureTransport)}
		values["aws:useragent"] = []string{m.UserAgent}
	}
	now := s.federationTime(role).UTC()
	values["aws:currenttime"] = []string{now.Format(time.RFC3339)}
	values["aws:epochtime"] = []string{strconv.FormatInt(now.Unix(), 10)}
	return values, nil
}

func (s *Service) federationTime(role RoleSnapshot) time.Time {
	if role.EvaluationTime != nil {
		return *role.EvaluationTime
	}
	return s.now()
}
