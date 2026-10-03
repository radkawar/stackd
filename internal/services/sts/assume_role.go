package sts

import (
	"context"
	"slices"
	"strings"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

func (s *Service) assumeRole(ctx context.Context) (*stsapi.AssumeRoleOutput, *awswire.Error) {
	return withSignedSession(s, ctx, "AssumeRole", (*signedSession).assumeRole)
}

func (s *signedSession) assumeRole(ctx context.Context) (*stsapi.AssumeRoleOutput, *awswire.Error) {
	input, ok := awsapi.Input[stsapi.AssumeRoleInput](ctx)
	if !ok {
		return nil, stsValidation("Missing AssumeRole input.")
	}
	parent, ctx, apiErr := s.parent(ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if parent.SessionType == identity.SessionTypeFederation {
		return nil, stsDenied("Federated user credentials cannot assume a role.")
	}
	if s.roles == nil {
		return nil, stsDenied("IAM role source is unavailable.")
	}
	role, err := s.roles.RoleForAssumption(ctx, value(input.RoleArn))
	if err != nil {
		return nil, stsDenied("The requested role does not exist or cannot be assumed.")
	}
	duration := time.Hour
	if input.DurationSeconds != nil {
		duration = time.Duration(*input.DurationSeconds) * time.Second
	}
	if duration < 15*time.Minute || duration > role.MaxSessionDuration || duration > 12*time.Hour {
		return nil, stsValidation("DurationSeconds exceeds the role's MaxSessionDuration or is below 900 seconds.")
	}
	if parent.SessionType == identity.SessionTypeAssumeRole && duration > time.Hour {
		return nil, stsValidation("Role chaining cannot exceed a one-hour session duration.")
	}
	if len(input.ProvidedContexts) > 0 {
		// TODO: Comeback validate signed Identity Center ProvidedContexts and bind their context assertions to assumed-role sessions.
		return nil, &awswire.Error{Code: "NotImplemented", Message: "Trusted context assertions are not implemented.", StatusCode: 501}
	}
	parts := strings.SplitN(role.ARN, ":", 6)
	documents, apiErr := s.sessionPolicies(ctx, parts[4], value(input.Policy), input.PolicyArns)
	if apiErr != nil {
		return nil, apiErr
	}
	tags, apiErr := sessionTags(input.Tags)
	if apiErr != nil {
		return nil, apiErr
	}
	source := value(input.SourceIdentity)
	if strings.HasPrefix(strings.ToLower(source), "aws:") {
		return nil, stsValidation("SourceIdentity cannot begin with aws:.")
	}
	if parent.SourceIdentity != "" {
		if source != "" && source != parent.SourceIdentity {
			return nil, stsDenied("SourceIdentity cannot be changed during role chaining.")
		}
		source = parent.SourceIdentity
	}
	transitive := make([]string, 0, len(input.TransitiveTagKeys)+len(parent.TransitiveTagKeys))
	seen := make(map[string]bool)
	for _, key := range input.TransitiveTagKeys {
		name := string(key)
		canonical := strings.ToLower(name)
		if seen[canonical] {
			return nil, stsValidation("TransitiveTagKeys must be unique ignoring case.")
		}
		if _, exists := findTag(tags, name); !exists {
			return nil, stsValidation("A transitive tag key must name a supplied session tag.")
		}
		seen[canonical] = true
		transitive = append(transitive, name)
	}
	for _, key := range parent.TransitiveTagKeys {
		val, exists := findTag(parent.SessionTags, key)
		if !exists {
			continue
		}
		if _, exists := findTag(tags, key); exists {
			return nil, stsValidation("A supplied session tag cannot override an inherited transitive tag.")
		}
		tags[key] = val
		if !seen[strings.ToLower(key)] {
			transitive = append(transitive, key)
			seen[strings.ToLower(key)] = true
		}
	}
	if len(tags) > 50 {
		return nil, stsValidation("Inherited and supplied session tags exceed 50.")
	}
	slices.Sort(transitive)
	mfaTime, apiErr := s.verifyMFA(ctx, value(input.SerialNumber), value(input.TokenCode))
	if apiErr != nil {
		return nil, apiErr
	}
	m := awsctx.FromContext(ctx)
	if value(input.SerialNumber) != "" {
		m.MFAPresent = true
		m.MFAAuthenticatedAt = mfaTime
		ctx = awsctx.WithMetadata(ctx, m)
	}
	contextValues := map[string][]string{"sts:rolesessionname": {value(input.RoleSessionName)}}
	if input.ExternalId != nil {
		contextValues["sts:externalid"] = []string{value(input.ExternalId)}
	}
	if source != "" {
		contextValues["sts:sourceidentity"] = []string{source}
	}
	for key, val := range tags {
		contextValues["aws:requesttag/"+strings.ToLower(key)] = []string{val}
		contextValues["aws:tagkeys"] = append(contextValues["aws:tagkeys"], key)
	}
	if len(transitive) > 0 {
		contextValues["sts:transitivetagkeys"] = transitive
	}
	for key, val := range role.Tags {
		contextValues["aws:resourcetag/"+strings.ToLower(key)] = []string{val}
	}
	// The permission checks form one authorization decision, even if the
	// service clock advances while policy dependencies are being evaluated.
	now := s.now().UTC()
	request := authorization.Request{Action: "sts:AssumeRole", ResourceARN: role.ARN, ResourcePolicies: []authorization.BoundPolicy{{Document: role.TrustPolicy, PrincipalIDs: role.TrustPrincipalIDs, TrustPolicy: true}}, RequireResourcePolicy: true, ResourceControlExempt: role.ServiceLinkedRole, Context: contextValues, EvaluationTime: &now}
	if apiErr := s.authorizer.Authorize(ctx, request); apiErr != nil {
		return nil, apiErr
	}
	if len(tags) > 0 {
		request.Action = "sts:TagSession"
		if apiErr := s.authorizer.Authorize(ctx, request); apiErr != nil {
			return nil, apiErr
		}
	}
	if source != "" {
		request.Action = "sts:SetSourceIdentity"
		if apiErr := s.authorizer.Authorize(ctx, request); apiErr != nil {
			return nil, apiErr
		}
	}
	packed, apiErr := packedSize(value(input.Policy), input.PolicyArns, tags)
	if apiErr != nil {
		return nil, apiErr
	}
	// The authority owns current trust, policy reads and credential insertion.
	legacy, apiErr := s.defaultRegionsOnly(ctx, parts[4], s.now().UTC())
	if apiErr != nil {
		return nil, apiErr
	}
	credential, err := s.credentials.IssueRoleSession(ctx, parent, identity.RoleSessionSpec{DefaultRegionsOnly: legacy, Role: identity.Principal{AccountID: parts[4], ARN: role.ARN, ID: role.ID}, SessionName: value(input.RoleSessionName), Duration: duration, MaxSessionDuration: role.MaxSessionDuration, Policies: documents, PolicyARNs: sessionPolicyARNs(input.PolicyArns), HasSessionPolicy: input.Policy != nil || len(input.PolicyArns) > 0, Tags: tags, TransitiveTagKeys: transitive, SourceIdentity: source})
	if err != nil {
		return nil, stsCredentialError(err)
	}
	output := &stsapi.AssumeRoleOutput{Credentials: credentialOutput(credential), AssumedRoleUser: &stsapi.AssumedRoleUser{Arn: ptr(stsapi.ArnType(credential.PrincipalARN)), AssumedRoleId: ptr(stsapi.AssumedRoleIdType(credential.PrincipalID))}, PackedPolicySize: ptr(stsapi.NonNegativeIntegerType(packed))}
	if source != "" {
		output.SourceIdentity = ptr(stsapi.SourceIdentityType(source))
	}
	return output, nil
}

func findTag(tags map[string]string, key string) (string, bool) {
	for k, v := range tags {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}
