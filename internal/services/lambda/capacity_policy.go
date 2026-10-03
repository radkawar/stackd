package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

// Despite sharing the managed-instance release, ResourcePolicy operations are
// function policies, not capacity-provider policies (PolicyResourceArn model).
func capacityPolicyReference(ctx context.Context, resource string) (FunctionReference, *awswire.Error) {
	if !strings.HasPrefix(resource, "arn:") {
		return FunctionReference{}, capacityParameter("ResourceArn must be a complete function ARN.")
	}
	return parseFunctionReference(ctx, resource, "")
}
func resourcePolicyRevision(expected *api.RevisionId, actual string) error {
	if expected != nil && string(*expected) != actual {
		return failure("PreconditionFailedException", "The RevisionId does not match the current policy revision.", 412)
	}
	return nil
}
func (s *Service) getCapacityPolicy(ctx context.Context, in *api.GetResourcePolicyRequest) (*api.GetResourcePolicyResponse, *awswire.Error) {
	ref, rejected := capacityPolicyReference(ctx, value(in.ResourceArn))
	if rejected != nil {
		return nil, rejected
	}
	var out *api.GetResourcePolicyResponse
	err := s.repository.View(ctx, func(r Reader) error {
		f, err := loadFunction(r, ref)
		if err != nil {
			return err
		}
		if rejected := s.authorizeFunction(r, "GetResourcePolicy", ref, f, nil); rejected != nil {
			return rejected
		}
		current, err := r.FunctionPolicy(ref)
		if err != nil {
			return err
		}
		if s.binder == nil {
			return unsupported("Resource policy principal binding is not configured.")
		}
		rendered, err := s.binder.RenderResourcePolicy(r.Context(), authorization.BoundPolicy{Document: current.Document, PrincipalIDs: current.PrincipalIDs})
		if err != nil {
			return err
		}
		out = &api.GetResourcePolicyResponse{Policy: new(api.ResourcePolicy(rendered)), RevisionId: new(api.RevisionId(current.Revision))}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) putCapacityPolicy(ctx context.Context, in *api.PutResourcePolicyRequest) (*api.PutResourcePolicyResponse, *awswire.Error) {
	ref, rejected := capacityPolicyReference(ctx, value(in.ResourceArn))
	if rejected != nil {
		return nil, rejected
	}
	document := value(in.Policy)
	if len(document) > functionPolicyLimit {
		return nil, failure("PolicyLengthExceededException", "The policy exceeds 20480 bytes.", 400)
	}
	document, err := normalizeFunctionResourcePolicy(document, ref.ARN())
	if err != nil {
		if errors.Is(err, errFunctionResourcePolicySyntax) {
			return nil, capacityParameter("Policy has syntax errors.")
		}
		return nil, capacityParameter(err.Error())
	}
	var out *api.PutResourcePolicyResponse
	err = s.repository.Update(ctx, func(tx Transaction) error {
		f, err := loadFunction(tx, ref)
		if err != nil {
			return err
		}
		if rejected := s.authorizeFunction(tx, "PutResourcePolicy", ref, f, nil); rejected != nil {
			return rejected
		}
		deployment, rejected := functionPolicyDeploymentFor(tx.Context())
		if rejected != nil {
			return rejected
		}
		current, err := tx.FunctionPolicy(ref)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if deployment.CreateOnly && err == nil {
			if deployment.Owner == (FunctionPolicyOwner{}) || current.Owner != deployment.Owner {
				return failure("ResourceConflictException", "The function resource policy already exists.", 409)
			}
			if s.binder == nil {
				return unsupported("Resource policy principal binding is not configured.")
			}
			rendered, err := s.binder.RenderResourcePolicy(tx.Context(), authorization.BoundPolicy{Document: current.Document, PrincipalIDs: current.PrincipalIDs})
			if err != nil {
				return err
			}
			out = &api.PutResourcePolicyResponse{Policy: new(api.ResourcePolicy(rendered)), RevisionId: new(api.RevisionId(current.Revision))}
			return s.recordCall(tx.Context(), "PutResourcePolicy", in, out, nil)
		}
		if err = resourcePolicyRevision(in.RevisionId, current.Revision); err != nil {
			return err
		}
		if s.binder == nil {
			return unsupported("Resource policy principal binding is not configured.")
		}
		bound, err := s.binder.BindResourcePolicy(tx.Context(), document, authorization.ResourcePolicyOptions{AllowFederatedPrincipals: true})
		if err != nil {
			return capacityParameter(err.Error())
		}
		current = FunctionPolicy{Key: ref, Document: bound.Document, PrincipalIDs: bound.PrincipalIDs, Revision: uuid.NewString(), Owner: deployment.Owner}
		if err = tx.PutFunctionPolicy(current); err != nil {
			return err
		}
		rendered, err := s.binder.RenderResourcePolicy(tx.Context(), bound)
		if err != nil {
			return err
		}
		out = &api.PutResourcePolicyResponse{Policy: new(api.ResourcePolicy(rendered)), RevisionId: new(api.RevisionId(current.Revision))}
		return s.recordCall(tx.Context(), "PutResourcePolicy", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) deleteCapacityPolicy(ctx context.Context, in *api.DeleteResourcePolicyRequest) (*api.Unit, *awswire.Error) {
	ref, rejected := capacityPolicyReference(ctx, value(in.ResourceArn))
	if rejected != nil {
		return nil, rejected
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		f, err := loadFunction(tx, ref)
		if errors.Is(err, ErrNotFound) {
			// Native deletion is idempotent even when the function is absent,
			// but still requires identity authorization and revision matching.
			if rejected := s.authorize(tx.Context(), "DeleteResourcePolicy", ref.ARN(), nil, nil, nil); rejected != nil {
				return rejected
			}
			if err := resourcePolicyRevision(in.RevisionId, ""); err != nil {
				return err
			}
			return s.recordCall(tx.Context(), "DeleteResourcePolicy", in, &api.Unit{}, nil)
		}
		if err != nil {
			return err
		}
		if rejected := s.authorizeFunction(tx, "DeleteResourcePolicy", ref, f, nil); rejected != nil {
			return rejected
		}
		current, err := tx.FunctionPolicy(ref)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err = resourcePolicyRevision(in.RevisionId, current.Revision); err != nil {
			return err
		}
		if err = tx.DeleteFunctionPolicy(ref); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "DeleteResourcePolicy", in, &api.Unit{}, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &api.Unit{}, nil
}

var errFunctionResourcePolicySyntax = errors.New("policy has syntax errors")

// AWS admits public principals here; PublicPolicyException in the API model
// does not establish an unconditional public-access block. Admission validates
// Lambda's policy syntax; principal/condition evaluation remains IAM-owned.
func normalizeFunctionResourcePolicy(document, resourceARN string) (string, error) {
	parsed, err := policy.ParseResource([]byte(document))
	if err != nil {
		return "", err
	}
	for _, resource := range parsed.ResourcePatterns() {
		if resource != resourceARN {
			return "", errFunctionResourcePolicySyntax
		}
	}
	for _, key := range parsed.ConditionKeys() {
		key = strings.ToLower(key)
		if !strings.HasPrefix(key, "aws:") && !strings.HasPrefix(key, "lambda:") {
			return "", errFunctionResourcePolicySyntax
		}
	}
	var decoded permissionDocument
	if err := json.Unmarshal([]byte(document), &decoded); err != nil {
		return "", err
	}
	if len(decoded.Statements) == 0 {
		return "", errFunctionResourcePolicySyntax
	}
	for _, statement := range decoded.Statements {
		var selectors struct {
			Action    json.RawMessage
			NotAction json.RawMessage
		}
		if err := json.Unmarshal(statement.raw, &selectors); err != nil {
			return "", err
		}
		for _, raw := range [...]json.RawMessage{selectors.Action, selectors.NotAction} {
			if len(raw) == 0 {
				continue
			}
			var actions []string
			if raw[0] == '"' {
				var action string
				if err := json.Unmarshal(raw, &action); err != nil {
					return "", err
				}
				actions = []string{action}
			} else if err := json.Unmarshal(raw, &actions); err != nil {
				return "", err
			}
			for _, action := range actions {
				if action != "*" && !strings.HasPrefix(strings.ToLower(action), "lambda:") {
					return "", errFunctionResourcePolicySyntax
				}
			}
		}
	}
	if decoded.Version == "" {
		decoded.Version = "2008-10-17"
	}
	encoded, err := json.Marshal(decoded)
	return string(encoded), err
}
