package sts

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) getWebIdentityToken(ctx context.Context) (*stsapi.GetWebIdentityTokenOutput, *awswire.Error) {
	return withSignedSession(s, ctx, "GetWebIdentityToken", (*signedSession).getWebIdentityToken)
}

func (s *signedSession) getWebIdentityToken(ctx context.Context) (*stsapi.GetWebIdentityTokenOutput, *awswire.Error) {
	input, ok := awsapi.Input[stsapi.GetWebIdentityTokenInput](ctx)
	if !ok {
		return nil, stsValidation("Missing GetWebIdentityToken input.")
	}
	if awsctx.FromContext(ctx).Region == "aws-global" {
		return nil, &awswire.Error{Code: "InvalidAction", Message: "Unknown Operation", StatusCode: 400}
	}
	// The generated frontend validates modeled audience, duration and tag
	// constraints. Algorithm membership and tag-key collisions are semantic.
	algorithm := value(input.SigningAlgorithm)
	if algorithm != "RS256" && algorithm != "ES384" {
		return nil, stsValidation("SigningAlgorithm must be RS256 or ES384.")
	}
	tags, apiErr := outboundTokenTags(input.Tags)
	if apiErr != nil {
		return nil, apiErr
	}
	parent, ctx, apiErr := s.parent(ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	duration := 300
	if input.DurationSeconds != nil {
		duration = int(*input.DurationSeconds)
	}
	audiences := make([]string, len(input.Audience))
	for i, audience := range input.Audience {
		audiences[i] = string(audience)
	}
	values := map[string][]string{
		"sts:IdentityTokenAudience": audiences,
		"sts:DurationSeconds":       {strconv.Itoa(duration)},
		"sts:SigningAlgorithm":      {algorithm},
	}
	for key, value := range tags {
		values["aws:requesttag/"+strings.ToLower(key)] = []string{value}
		values["aws:tagkeys"] = append(values["aws:tagkeys"], key)
	}
	slices.Sort(values["aws:tagkeys"])
	now := s.now().UTC()
	m := awsctx.FromContext(ctx)
	request := authorization.Request{Action: "sts:GetWebIdentityToken", ResourceARN: "arn:" + m.Partition + ":sts::" + m.AccountID + ":self", Context: values, EvaluationTime: &now}
	if apiErr := s.authorizer.Authorize(ctx, request); apiErr != nil {
		return nil, apiErr
	}
	if len(tags) != 0 {
		request.Action = "sts:TagGetWebIdentityToken"
		if apiErr := s.authorizer.Authorize(ctx, request); apiErr != nil {
			return nil, apiErr
		}
	}
	expiration := now.Add(time.Duration(duration) * time.Second)
	if parent.SessionType != "" && expiration.After(parent.Expiration) {
		return nil, &awswire.Error{Code: "SessionDurationEscalationException", Message: "The requested token duration exceeds the original session expiration.", StatusCode: 403}
	}
	if s.outboundWebIdentity == nil {
		return nil, &awswire.Error{Code: "OutboundWebIdentityFederationDisabledException", Message: "Outbound web identity federation is not enabled for this account.", StatusCode: 403}
	}
	claims, apiErr := s.outboundTokenClaims(ctx, parent, audiences, tags, now, expiration)
	if apiErr != nil {
		return nil, apiErr
	}
	token, err := s.outboundWebIdentity.SignWebIdentityToken(ctx, algorithm, claims)
	if err != nil {
		var apiErr *awswire.Error
		if errors.As(err, &apiErr) {
			return nil, apiErr
		}
		return nil, outboundTokenFailure("Unable to sign the web identity token.")
	}
	return &stsapi.GetWebIdentityTokenOutput{WebIdentityToken: ptr(stsapi.WebIdentityTokenType(token)), Expiration: &expiration}, nil
}

func outboundTokenTags(tags stsapi.TagListType) (map[string]string, *awswire.Error) {
	result := make(map[string]string, len(tags))
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		key := value(tag.Key)
		canonical := strings.ToLower(key)
		if seen[canonical] {
			return nil, &awswire.Error{Code: "InvalidParameterValue", Message: "Tag keys must be unique ignoring case.", StatusCode: 400}
		}
		seen[canonical] = true
		result[key] = value(tag.Value)
	}
	return result, nil
}

func outboundTokenFailure(message string) *awswire.Error {
	return &awswire.Error{Code: "InternalFailure", Message: message, StatusCode: 500}
}
