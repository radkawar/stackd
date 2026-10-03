package dynamodb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"

	"github.com/google/uuid"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awsctx"
)

func (s *Service) policyTarget(ctx context.Context, tx Transaction, resource, action string) (TableKey, PolicyKey, error) {
	if !strings.HasPrefix(resource, "arn:") {
		return TableKey{}, PolicyKey{}, failure("ValidationException", "ResourceArn must be a DynamoDB table or stream ARN")
	}
	tableARN, stream, isStream := strings.Cut(resource, "/stream/")
	key, err := parseTableKey(ctx, tableARN)
	if err != nil {
		return TableKey{}, PolicyKey{}, err
	}
	policyKey := PolicyKey{Scope: key.Scope, ResourceARN: resource}
	if isStream && (stream == "" || strings.Contains(stream, "/")) {
		return key, policyKey, failure("ValidationException", "Invalid stream ARN")
	}
	bound, err := tx.Policy(policyKey)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return key, policyKey, err
	}
	if err = s.authorizePolicy(ctx, tx, key, resource, action, bound.Policy); err != nil {
		return key, policyKey, err
	}
	if isStream {
		generation, err := tx.Stream(policyKey)
		if errors.Is(err, ErrNotFound) || err == nil && streamExpired(generation, s.clock.Now()) {
			return key, policyKey, failure("ResourceNotFoundException", "Requested resource not found: ResourceArn: "+resource+" not found")
		}
		if err != nil {
			return key, policyKey, err
		}
		return generation.Table, policyKey, nil
	}
	_, err = tx.Table(key)
	if errors.Is(err, ErrNotFound) {
		return key, policyKey, failure("ResourceNotFoundException", "Requested resource not found: ResourceArn: "+resource+" not found")
	}
	if err != nil {
		return key, policyKey, err
	}
	return key, policyKey, nil
}

func (s *Service) authorizePolicy(ctx context.Context, r Reader, key TableKey, resource, action string, bound authorization.BoundPolicy) error {
	conditions := map[string][]string{}
	tags, err := readTags(r, key)
	if err != nil {
		return err
	}
	for _, tag := range tags.Tags {
		conditions["aws:ResourceTag/"+value(tag.Key)] = []string{value(tag.Value)}
	}
	now := s.clock.Now()
	request := authorization.Request{Action: "dynamodb:" + action, ResourceARN: resource, Context: conditions, EvaluationTime: &now}
	// DynamoDB permits the owning root to recover a policy that denies itself.
	// Only the resource policy is bypassed: organization and session controls remain.
	identity := awsctx.FromContext(ctx)
	if action == "DeleteResourcePolicy" && identity.PrincipalARN == "arn:"+key.Partition+":iam::"+key.AccountID+":root" && identity.PrincipalID == key.AccountID {
		bound = authorization.BoundPolicy{}
	}
	if bound.Document != "" {
		request.ResourcePolicies = []authorization.BoundPolicy{bound}
	}
	if rejected := s.authorizer.Authorize(ctx, request); rejected != nil {
		return rejected
	}
	return nil
}

func (s *Service) bindPolicy(ctx context.Context, r Reader, key TableKey, resource, document string, confirm bool) (authorization.BoundPolicy, error) {
	if s.binder == nil {
		return authorization.BoundPolicy{}, unsupported("DynamoDB resource policy principal binding is not configured.")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(document)); err != nil {
		return authorization.BoundPolicy{}, failure("ValidationException", "Invalid resource policy document: "+err.Error())
	}
	if compact.Len() > 20*1024 {
		return authorization.BoundPolicy{}, failure("LimitExceededException", "Resource policy exceeds the maximum size of 20 KB")
	}
	bound, err := s.binder.BindResourcePolicy(ctx, compact.String(), authorization.ResourcePolicyOptions{})
	if err != nil {
		return authorization.BoundPolicy{}, failure("ValidationException", "Invalid resource policy document: "+err.Error())
	}
	if !confirm {
		if err = s.authorizePolicy(ctx, r, key, resource, "PutResourcePolicy", bound); err != nil {
			return authorization.BoundPolicy{}, failure("AccessDeniedException", "The new resource policy will not allow you to update the resource policy in the future.")
		}
	}
	return bound, nil
}

func (s *Service) getResourcePolicy(ctx context.Context, tx Transaction, in *api.GetResourcePolicyInput) (*api.GetResourcePolicyOutput, error) {
	_, key, err := s.policyTarget(ctx, tx, value(in.ResourceArn), "GetResourcePolicy")
	if err != nil {
		return nil, err
	}
	record, err := tx.Policy(key)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("PolicyNotFoundException", "No resource-based policy found for resource: "+key.ResourceARN)
	}
	if err != nil {
		return nil, err
	}
	if s.binder == nil {
		return nil, unsupported("DynamoDB resource policy principal binding is not configured.")
	}
	document, err := s.binder.RenderResourcePolicy(ctx, record.Policy)
	if err != nil {
		return nil, err
	}
	return &api.GetResourcePolicyOutput{Policy: new(api.ResourcePolicy(document)), RevisionId: new(api.PolicyRevisionId(record.Revision))}, nil
}

func policyRevisionMatches(expected *api.PolicyRevisionId, record PolicyRecord, exists bool) error {
	if expected == nil {
		return nil
	}
	revision := value(expected)
	if revision == "NO_POLICY" && !exists {
		return nil
	}
	if exists && revision == record.Revision {
		return nil
	}
	return failure("PolicyNotFoundException", "The resource policy revision does not match the expected revision")
}

func (s *Service) putResourcePolicy(ctx context.Context, tx Transaction, in *api.PutResourcePolicyInput) (*api.PutResourcePolicyOutput, error) {
	tableKey, key, err := s.policyTarget(ctx, tx, value(in.ResourceArn), "PutResourcePolicy")
	if err != nil {
		return nil, err
	}
	current, err := tx.Policy(key)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err = policyRevisionMatches(in.ExpectedRevisionId, current, exists); err != nil {
		return nil, err
	}
	confirm := in.ConfirmRemoveSelfResourceAccess != nil && bool(*in.ConfirmRemoveSelfResourceAccess)
	bound, err := s.bindPolicy(ctx, tx, tableKey, key.ResourceARN, value(in.Policy), confirm)
	if err != nil {
		return nil, err
	}
	revision := current.Revision
	if !exists || current.Policy.Document != bound.Document || !maps.Equal(current.Policy.PrincipalIDs, bound.PrincipalIDs) {
		// Revisions are opaque and must not repeat after delete/recreate, even when
		// the service clock is frozen or moves backwards.
		revision = uuid.NewString()
		if err = tx.PutPolicy(PolicyRecord{Key: key, Policy: bound, Revision: revision}); err != nil {
			return nil, err
		}
	}
	return &api.PutResourcePolicyOutput{RevisionId: new(api.PolicyRevisionId(revision))}, nil
}

func (s *Service) deleteResourcePolicy(ctx context.Context, tx Transaction, in *api.DeleteResourcePolicyInput) (*api.DeleteResourcePolicyOutput, error) {
	_, key, err := s.policyTarget(ctx, tx, value(in.ResourceArn), "DeleteResourcePolicy")
	if err != nil {
		return nil, err
	}
	current, err := tx.Policy(key)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if !exists && in.ExpectedRevisionId != nil {
		return nil, failure("PolicyNotFoundException", "No resource-based policy found for resource: "+key.ResourceARN)
	}
	if err = policyRevisionMatches(in.ExpectedRevisionId, current, exists); err != nil {
		return nil, err
	}
	if !exists {
		return &api.DeleteResourcePolicyOutput{}, nil
	}
	if err = tx.DeletePolicy(key); err != nil {
		return nil, err
	}
	return &api.DeleteResourcePolicyOutput{RevisionId: new(api.PolicyRevisionId(current.Revision))}, nil
}
