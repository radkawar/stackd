package kinesis

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/kinesis"
)

const policyPropagationDelay = 5 * time.Second

func (s *Service) getResourcePolicy(ctx context.Context, tx Transaction, in *api.GetResourcePolicyInput) (*api.GetResourcePolicyOutput, error) {
	key, err := s.resourceTarget(ctx, tx, value(in.ResourceARN), "GetResourcePolicy", nil)
	if err != nil {
		return nil, err
	}
	record, err := tx.Policy(key)
	if errors.Is(err, ErrNotFound) || err == nil && record.Policy.Document == "" {
		return &api.GetResourcePolicyOutput{Policy: new(api.Policy("{}"))}, nil
	}
	if err != nil {
		return nil, err
	}
	if s.binder == nil {
		return nil, failure("InternalFailureException", "Kinesis resource policy principal binding is not configured", 500)
	}
	document, err := s.binder.RenderResourcePolicy(ctx, record.Policy)
	if err != nil {
		return nil, err
	}
	return &api.GetResourcePolicyOutput{Policy: new(api.Policy(document))}, nil
}

// normalizePolicy preserves IAM language for the shared validator, while using
// the service's scalar representation for singleton action/resource/principal lists.
func normalizePolicy(document string) (string, error) {
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(document), &parsed); err != nil || parsed == nil {
		return "", failure("InvalidArgumentException", "Policy validation error: This policy contains invalid Json")
	}
	var statements []map[string]json.RawMessage
	raw := parsed["Statement"]
	if err := json.Unmarshal(raw, &statements); err != nil {
		var statement map[string]json.RawMessage
		if err := json.Unmarshal(raw, &statement); err != nil || statement == nil {
			return "", failure("InvalidArgumentException", "Policy validation error: Invalid Statement")
		}
		statements = []map[string]json.RawMessage{statement}
	}
	for _, statement := range statements {
		for _, field := range []string{"Action", "NotAction", "Resource", "NotResource"} {
			statement[field] = scalarPolicyList(statement[field])
			if statement[field] == nil {
				delete(statement, field)
			}
		}
		for _, field := range []string{"Principal", "NotPrincipal"} {
			var principals map[string]json.RawMessage
			if json.Unmarshal(statement[field], &principals) == nil && principals != nil {
				for kind, values := range principals {
					principals[kind] = scalarPolicyList(values)
				}
				statement[field], _ = json.Marshal(principals)
			}
		}
	}
	parsed["Statement"], _ = json.Marshal(statements)
	encoded, err := json.Marshal(parsed)
	if err != nil {
		return "", err
	}
	if len(encoded) > 20*1024 {
		return "", failure("InvalidArgumentException", "Resource policy exceeds the maximum size of 20 KB")
	}
	return string(encoded), nil
}

func scalarPolicyList(raw json.RawMessage) json.RawMessage {
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) == nil && len(values) == 1 {
		return values[0]
	}
	return raw
}

func (s *Service) putResourcePolicy(ctx context.Context, tx Transaction, in *api.PutResourcePolicyInput) (*api.PutResourcePolicyOutput, error) {
	key, err := s.resourceTarget(ctx, tx, value(in.ResourceARN), "PutResourcePolicy", nil)
	if err != nil {
		return nil, err
	}
	if key.AccountID != scopeFor(ctx).AccountID {
		return nil, failure("AccessDeniedException", "Only the resource owner's account may put a resource policy")
	}
	if s.binder == nil {
		return nil, failure("InternalFailureException", "Kinesis resource policy principal binding is not configured", 500)
	}
	// Bind the original document before normalization so unsupported or malformed
	// fields cannot disappear during canonicalization.
	bound, err := s.binder.BindResourcePolicy(ctx, value(in.Policy), authorization.ResourcePolicyOptions{})
	if err != nil {
		return nil, failure("InvalidArgumentException", "Policy validation error: "+err.Error())
	}
	document, err := normalizePolicy(bound.Document)
	if err != nil {
		return nil, err
	}
	bound.Document = document
	current, err := tx.Policy(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if current.Policy.Document == bound.Document && maps.Equal(current.Policy.PrincipalIDs, bound.PrincipalIDs) {
		return &api.PutResourcePolicyOutput{}, nil
	}
	now := s.clock.Now()
	effective := current.Policy
	if now.Before(current.PublishAt) {
		effective = current.Effective
	}
	if err = tx.PutPolicy(PolicyRecord{Key: key, Policy: bound, Effective: effective, PublishAt: now.Add(policyPropagationDelay)}); err != nil {
		return nil, err
	}
	return &api.PutResourcePolicyOutput{}, nil
}

func (s *Service) deleteResourcePolicy(ctx context.Context, tx Transaction, in *api.DeleteResourcePolicyInput) (*api.DeleteResourcePolicyOutput, error) {
	key, err := s.resourceTarget(ctx, tx, value(in.ResourceARN), "DeleteResourcePolicy", nil)
	if err != nil {
		return nil, err
	}
	current, err := tx.Policy(key)
	if errors.Is(err, ErrNotFound) || err == nil && current.Policy.Document == "" {
		return nil, failure("ResourceNotFoundException", "No resource policy found for resource ARN "+key.ARN+".")
	}
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	effective := current.Policy
	if now.Before(current.PublishAt) {
		effective = current.Effective
	}
	if err = tx.PutPolicy(PolicyRecord{Key: key, Policy: authorization.BoundPolicy{}, Effective: effective, PublishAt: now.Add(policyPropagationDelay)}); err != nil {
		return nil, err
	}
	return &api.DeleteResourcePolicyOutput{}, nil
}
