package sqs

import (
	"context"
	"maps"

	"stackd/internal/authorization"
	"stackd/internal/awswire"
)

func (s *Service) bindPolicy(ctx context.Context, document string) (map[string]string, *awswire.Error) {
	if document == "" {
		return nil, nil
	}
	binder, ok := s.authorizer.(authorization.PolicyBinder)
	if !ok {
		return nil, failure("InvalidAttributeValue", "The configured authorizer does not support resource policy principal binding.")
	}
	bound, err := binder.BindResourcePolicy(ctx, document, authorization.ResourcePolicyOptions{})
	if err != nil {
		return nil, failure("InvalidAttributeValue", err.Error())
	}
	return maps.Clone(bound.PrincipalIDs), nil
}
func (s *Service) renderPolicy(ctx context.Context, q *queue) (string, *awswire.Error) {
	if q.config.policy == "" {
		return "", nil
	}
	binder, ok := s.authorizer.(authorization.PolicyBinder)
	if !ok {
		return q.config.policy, nil
	}
	rendered, err := binder.RenderResourcePolicy(ctx, authorization.BoundPolicy{Document: q.config.policy, PrincipalIDs: q.config.policyPrincipals})
	if err != nil {
		return "", &awswire.Error{Code: "InternalError", Message: "Unable to render policy principals.", StatusCode: 500}
	}
	return rendered, nil
}
