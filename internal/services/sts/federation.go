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

func (s *Service) getFederationToken(ctx context.Context) (*stsapi.GetFederationTokenOutput, *awswire.Error) {
	return withSignedSession(s, ctx, "GetFederationToken", (*signedSession).getFederationToken)
}

func (s *signedSession) getFederationToken(ctx context.Context) (*stsapi.GetFederationTokenOutput, *awswire.Error) {
	input, ok := awsapi.Input[stsapi.GetFederationTokenInput](ctx)
	if !ok {
		return nil, stsValidation("Missing GetFederationToken input.")
	}
	parent, ctx, apiErr := s.parent(ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if parent.SessionToken != "" {
		return nil, stsDenied("GetFederationToken requires long-term credentials.")
	}
	documents, apiErr := s.sessionPolicies(ctx, parent.AccountID, value(input.Policy), input.PolicyArns)
	if apiErr != nil {
		return nil, apiErr
	}
	tags, apiErr := sessionTags(input.Tags)
	if apiErr != nil {
		return nil, apiErr
	}
	m := awsctx.FromContext(ctx)
	contextValues := make(map[string][]string, len(tags)+1)
	for key, val := range tags {
		contextValues["aws:requesttag/"+strings.ToLower(key)] = []string{val}
		contextValues["aws:tagkeys"] = append(contextValues["aws:tagkeys"], key)
	}
	slices.Sort(contextValues["aws:tagkeys"])
	arn := "arn:" + m.Partition + ":sts::" + m.AccountID + ":federated-user/" + value(input.Name)
	now := s.now().UTC()
	if apiErr := s.authorizer.Authorize(ctx, authorization.Request{Action: "sts:GetFederationToken", ResourceARN: arn, Context: contextValues, EvaluationTime: &now}); apiErr != nil {
		return nil, apiErr
	}
	if len(tags) > 0 {
		if apiErr := s.authorizer.Authorize(ctx, authorization.Request{Action: "sts:TagSession", ResourceARN: "*", Context: contextValues, EvaluationTime: &now}); apiErr != nil {
			return nil, apiErr
		}
	}
	duration := 12 * time.Hour
	if input.DurationSeconds != nil {
		duration = time.Duration(*input.DurationSeconds) * time.Second
	}
	packed, apiErr := packedSize(value(input.Policy), input.PolicyArns, tags)
	if apiErr != nil {
		return nil, apiErr
	}
	legacy, apiErr := s.defaultRegionsOnly(ctx, parent.AccountID, s.now().UTC())
	if apiErr != nil {
		return nil, apiErr
	}
	credential, err := s.credentials.IssueFederation(ctx, parent, identity.FederationSpec{DefaultRegionsOnly: legacy, Name: value(input.Name), Duration: duration, Policies: documents, PolicyARNs: sessionPolicyARNs(input.PolicyArns), Tags: tags})
	if err != nil {
		return nil, stsCredentialError(err)
	}
	return &stsapi.GetFederationTokenOutput{Credentials: credentialOutput(credential), FederatedUser: &stsapi.FederatedUser{Arn: ptr(stsapi.ArnType(credential.PrincipalARN)), FederatedUserId: ptr(stsapi.FederatedIdType(credential.PrincipalID))}, PackedPolicySize: ptr(stsapi.NonNegativeIntegerType(packed))}, nil
}

func (s *Service) getAccessKeyInfo(ctx context.Context) (*stsapi.GetAccessKeyInfoOutput, *awswire.Error) {
	input, ok := awsapi.Input[stsapi.GetAccessKeyInfoInput](ctx)
	if !ok {
		return nil, stsValidation("Missing GetAccessKeyInfo input.")
	}
	m := awsctx.FromContext(ctx)
	if m.SessionType == string(identity.SessionTypeFederation) {
		return nil, stsDenied("Federated user credentials cannot call this STS operation.")
	}
	if apiErr := s.authorizer.Authorize(ctx, authorization.Request{Action: "sts:GetAccessKeyInfo", ResourceARN: "*"}); apiErr != nil {
		return nil, apiErr
	}
	account, err := s.credentials.AccessKeyAccount(ctx, value(input.AccessKeyId))
	if err != nil {
		return nil, stsCredentialError(err)
	}
	return &stsapi.GetAccessKeyInfoOutput{Account: ptr(stsapi.AccountType(account))}, nil
}
