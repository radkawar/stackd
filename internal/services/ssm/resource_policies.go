package ssm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ssm"
)

func (s *Service) resourcePolicyParameter(tx Transaction, action, arn string) (ParameterRecord, error) {
	if !strings.HasPrefix(arn, "arn:") {
		return ParameterRecord{}, failure("ResourcePolicyInvalidParameterException", "ResourceArn must be a parameter ARN.")
	}
	key, err := parameterKey(tx.Context(), arn, true)
	if err != nil {
		return ParameterRecord{}, failure("ResourcePolicyInvalidParameterException", "ResourceArn must be a parameter ARN in this Region.")
	}
	if key.Scope != scopeFor(tx.Context()) {
		return ParameterRecord{}, failure("AccessDeniedException", "Resource policies can only be managed by the parameter owner.")
	}
	p, err := resolveParameter(tx, key)
	if errors.Is(err, ErrNotFound) {
		return ParameterRecord{}, failure("ResourceNotFoundException", "The specified parameter could not be found.")
	}
	if err != nil {
		return ParameterRecord{}, err
	}
	if err := s.authorize(tx, action, p, nil); err != nil {
		return ParameterRecord{}, err
	}
	return p, nil
}

func (s *Service) putResourcePolicy(tx Transaction, in *api.PutResourcePolicyRequest) (*api.PutResourcePolicyResponse, error) {
	p, err := s.resourcePolicyParameter(tx, "PutResourcePolicy", value(in.ResourceArn))
	if err != nil {
		return nil, err
	}
	if err := s.shareableParameter(tx, p); err != nil {
		return nil, err
	}
	id, hash := value(in.PolicyId), value(in.PolicyHash)
	index := slices.IndexFunc(p.ResourcePolicies, func(policy ResourcePolicy) bool { return policy.ID == id })
	if id == "" && hash != "" {
		return nil, failure("ResourcePolicyInvalidParameterException", "PolicyId and PolicyHash must be supplied together.")
	}
	if id != "" {
		if index < 0 {
			return nil, failure("ResourcePolicyNotFoundException", "The specified resource policy could not be found.")
		}
		if hash == "" || p.ResourcePolicies[index].Hash != hash {
			return nil, failure("ResourcePolicyConflictException", "The policy hash does not match the current policy version.")
		}
	}
	claim, claimed := cloudFormationPolicyOwner(tx.Context())
	if claimed {
		if id == "" {
			// A retried incarnation recovers only the policy it committed.
			if owned := slices.IndexFunc(p.ResourcePolicies, func(policy ResourcePolicy) bool { return policy.CloudFormationOwner == claim }); owned >= 0 {
				existing := p.ResourcePolicies[owned]
				return &api.PutResourcePolicyResponse{PolicyId: new(api.PolicyId(existing.ID)), PolicyHash: new(api.PolicyHash(existing.Hash))}, nil
			}
		} else if p.ResourcePolicies[index].CloudFormationOwner != claim {
			return nil, cloudFormationPolicyConflict()
		}
	}
	document := value(in.Policy)
	if len(document) > 1024 {
		return nil, failure("ResourcePolicyLimitExceededException", "A resource policy cannot exceed 1024 bytes.")
	}
	if s.binder == nil {
		return nil, failure("InternalServerError", "Resource policy principal binding is not configured.")
	}
	bound, err := s.binder.BindResourcePolicy(tx.Context(), document, authorization.ResourcePolicyOptions{})
	if err != nil {
		return nil, failure("MalformedResourcePolicyDocumentException", err.Error())
	}
	if id == "" {
		id = identifier()
	}
	digest := sha256.Sum256([]byte(document))
	policy := ResourcePolicy{ID: id, Hash: hex.EncodeToString(digest[:]), Policy: bound}
	if index < 0 {
		if claimed {
			policy.CloudFormationOwner = claim
		}
		p.ResourcePolicies = append(p.ResourcePolicies, policy)
	} else {
		// Public updates keep the incarnation that created the policy.
		policy.CloudFormationOwner = p.ResourcePolicies[index].CloudFormationOwner
		p.ResourcePolicies[index] = policy
	}
	if err := tx.PutParameter(p); err != nil {
		return nil, err
	}
	if err := s.syncSharedPolicy(tx.Context(), p, policy.ID, bound); err != nil {
		return nil, err
	}
	// Direct resource-policy sharing is effective for ARN reads. RAM promotion
	// is a separate prerequisite for DescribeParameters(Shared=true).
	return &api.PutResourcePolicyResponse{PolicyId: new(api.PolicyId(policy.ID)), PolicyHash: new(api.PolicyHash(policy.Hash))}, nil
}

func (s *Service) getResourcePolicies(tx Transaction, in *api.GetResourcePoliciesRequest) (*api.GetResourcePoliciesResponse, error) {
	p, err := s.resourcePolicyParameter(tx, "GetResourcePolicies", value(in.ResourceArn))
	if err != nil {
		return nil, err
	}
	if claim, claimed := cloudFormationPolicyOwner(tx.Context()); claimed {
		p.ResourcePolicies = slices.DeleteFunc(slices.Clone(p.ResourcePolicies), func(policy ResourcePolicy) bool { return policy.CloudFormationOwner != claim })
	} else if sharing, ok := s.sharing.(ManagedParameterPolicies); ok {
		managed, err := sharing.ManagedPolicies(tx.Context(), SharedParameter{ARN: p.ARN})
		if err != nil {
			return nil, err
		}
		p.ResourcePolicies = append(p.ResourcePolicies, managed...)
	}
	size := 50
	if in.MaxResults != nil {
		size = int(*in.MaxResults)
	}
	var token *api.NextToken
	if in.NextToken != nil {
		token = new(api.NextToken(*in.NextToken))
	}
	policies, next, err := parameterPage(s, tx, "GetResourcePolicies", p.ARN, p.ResourcePolicies, func(policy ResourcePolicy) string { return policy.ID }, size, 50, token)
	if err != nil {
		return nil, err
	}
	out := &api.GetResourcePoliciesResponse{Policies: make(api.GetResourcePoliciesResponseEntries, 0, len(policies))}
	if next != nil {
		out.NextToken = new(api.String(*next))
	}
	if len(policies) > 0 && s.binder == nil {
		return nil, failure("InternalServerError", "Resource policy principal binding is not configured.")
	}
	for _, policy := range policies {
		document, err := s.binder.RenderResourcePolicy(tx.Context(), policy.Policy)
		if err != nil {
			return nil, err
		}
		out.Policies = append(out.Policies, api.GetResourcePoliciesResponseEntry{Policy: new(api.Policy(document)), PolicyId: new(api.PolicyId(policy.ID)), PolicyHash: new(api.PolicyHash(policy.Hash))})
	}
	return out, nil
}

func (s *Service) deleteResourcePolicy(tx Transaction, in *api.DeleteResourcePolicyRequest) (*api.DeleteResourcePolicyResponse, error) {
	p, err := s.resourcePolicyParameter(tx, "DeleteResourcePolicy", value(in.ResourceArn))
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(p.ResourcePolicies, func(policy ResourcePolicy) bool { return policy.ID == value(in.PolicyId) })
	if index < 0 {
		return nil, failure("ResourcePolicyNotFoundException", "The specified resource policy could not be found.")
	}
	if value(in.PolicyHash) != p.ResourcePolicies[index].Hash {
		return nil, failure("ResourcePolicyConflictException", "The policy hash does not match the current policy version.")
	}
	if claim, claimed := cloudFormationPolicyOwner(tx.Context()); claimed && p.ResourcePolicies[index].CloudFormationOwner != claim {
		return nil, cloudFormationPolicyConflict()
	}
	p.ResourcePolicies = slices.Delete(p.ResourcePolicies, index, index+1)
	if err := tx.PutParameter(p); err != nil {
		return nil, err
	}
	return &api.DeleteResourcePolicyResponse{}, s.syncSharedPolicy(tx.Context(), p, value(in.PolicyId), authorization.BoundPolicy{})
}

// RemoveParameterResourcePolicy transfers a policy-created RAM share to managed
// permission authority within the same transaction. The ordinary SSM mutation
// permission remains required. RAM owns the matching share transition, so this
// callback intentionally does not call the synchronization hook recursively.
func (s *Service) RemoveParameterResourcePolicy(ctx context.Context, arn, id, principal string) error {
	if principal != "" {
		return failure("OperationNotPermittedException", "A policy-created share must be promoted before changing its principals through RAM.")
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		p, err := s.resourcePolicyParameter(tx, "PutResourcePolicy", arn)
		if err != nil {
			return err
		}
		index := slices.IndexFunc(p.ResourcePolicies, func(policy ResourcePolicy) bool { return policy.ID == id })
		if index < 0 {
			return failure("ResourcePolicyNotFoundException", "The source resource policy no longer exists.")
		}
		p.ResourcePolicies = slices.Delete(p.ResourcePolicies, index, index+1)
		return tx.PutParameter(p)
	})
}
