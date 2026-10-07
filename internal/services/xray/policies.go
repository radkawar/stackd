package xray

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/xray"
	"stackd/internal/awsctx"
)

func (s *Service) authorizedPolicies(r Reader, action string) ([]PolicyRecord, error) {
	rows, err := r.ResourcePolicies(scopeFor(r.Context()))
	if err != nil {
		return nil, err
	}
	if err := s.authorizePolicies(r.Context(), authorization.Request{Action: "xray:" + action, ResourceARN: "*"}, rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *Service) authorizePolicies(ctx context.Context, request authorization.Request, rows []PolicyRecord) error {
	policies := make([]authorization.BoundPolicy, 0, len(rows))
	for _, row := range rows {
		policies = append(policies, row.Policy)
	}
	service := awsctx.FromContext(ctx).ServicePrincipal.Name != ""
	// Resource grants enable service integration; an accepted role grant did
	// not replace identity permission in the native ingestion control.
	request.ResourceAccountID = scopeFor(ctx).AccountID
	request.ResourcePolicies = policies
	request.RequireResourcePolicy = service
	request.ResourcePolicyDenyOnly = !service
	if rejected := s.authorizer.Authorize(ctx, request); rejected != nil {
		return rejected
	}
	return nil
}

func (s *Service) authorizeResource(r Reader, request authorization.Request) error {
	rows, err := r.ResourcePolicies(scopeFor(r.Context()))
	if err != nil {
		return err
	}
	return s.authorizePolicies(r.Context(), request, rows)
}

func policyOutput(p PolicyRecord) api.ResourcePolicy {
	return api.ResourcePolicy{PolicyName: new(api.PolicyName(p.Key.Name)), PolicyDocument: new(api.PolicyDocument(p.Policy.Document)), PolicyRevisionId: new(api.PolicyRevisionId(strconv.FormatInt(p.Revision, 10))), LastUpdatedTime: new(p.Updated)}
}

func (s *Service) putResourcePolicy(tx Transaction, in *api.PutResourcePolicyRequest) (*api.PutResourcePolicyResult, error) {
	rows, err := s.authorizedPolicies(tx, "PutResourcePolicy")
	if err != nil {
		return nil, err
	}
	name := value(in.PolicyName)
	var old PolicyRecord
	for _, row := range rows {
		if row.Key.Name == name {
			old = row
			break
		}
	}
	owner, err := cloudFormationClaim(tx.Context(), old.CFNOwner, old.Revision != 0)
	if err != nil {
		return nil, err
	}
	if in.PolicyRevisionId != nil && value(in.PolicyRevisionId) != strconv.FormatInt(old.Revision, 10) {
		return nil, revisionConflict(name)
	}
	if old.Revision == 0 && len(rows) >= 5 {
		return nil, failure("PolicyCountLimitExceededException", "The maximum number of X-Ray resource policies has been reached.")
	}
	document := value(in.PolicyDocument)
	if len(document) > 5*1024 {
		return nil, failure("PolicySizeLimitExceededException", "The resource policy exceeds the maximum size of 5 KB.")
	}
	if s.binder == nil {
		return nil, failure("InternalFailure", "X-Ray policy principal binding is not configured.", 500)
	}
	bound, err := s.binder.BindResourcePolicy(tx.Context(), document, authorization.ResourcePolicyOptions{})
	if err != nil {
		if errors.Is(err, policy.ErrInvalidPolicy) || errors.Is(err, authorization.ErrInvalidPrincipal) {
			return nil, failure("MalformedPolicyDocumentException", "Invalid resource policy: "+err.Error())
		}
		return nil, err
	}
	bound.Document, err = canonicalPolicy(bound.Document)
	if err != nil {
		return nil, err
	}
	p := PolicyRecord{CFNOwner: owner, Key: PolicyKey{Scope: scopeFor(tx.Context()), Name: name}, Policy: bound, Revision: old.Revision + 1, Updated: s.clock.Now().UTC().Truncate(time.Second)}
	if in.BypassPolicyLockoutCheck == nil || !bool(*in.BypassPolicyLockoutCheck) {
		candidate := make([]PolicyRecord, 0, len(rows)+1)
		for _, row := range rows {
			if row.Key.Name != name {
				candidate = append(candidate, row)
			}
		}
		candidate = append(candidate, p)
		if err := s.authorizePolicies(tx.Context(), authorization.Request{Action: "xray:PutResourcePolicy", ResourceARN: "*"}, candidate); err != nil {
			return nil, failure("LockoutPreventionException", "The resource policy would prevent the caller from making a subsequent PutResourcePolicy request.")
		}
	}
	if err := tx.PutResourcePolicy(p); err != nil {
		return nil, err
	}
	out := policyOutput(p)
	return &api.PutResourcePolicyResult{ResourcePolicy: &out}, nil
}

func (s *Service) listResourcePolicies(tx Transaction, in *api.ListResourcePoliciesRequest) (*api.ListResourcePoliciesResult, error) {
	rows, err := s.authorizedPolicies(tx, "ListResourcePolicies")
	if err != nil {
		return nil, err
	}
	if in.NextToken != nil {
		return nil, failure("InvalidRequestException", "NextToken is currently not supported.")
	}
	out := &api.ListResourcePoliciesResult{ResourcePolicies: api.ResourcePolicyList{}}
	for _, row := range rows {
		if len(row.Policy.PrincipalIDs) != 0 {
			if s.binder == nil {
				return nil, failure("InternalFailure", "X-Ray policy principal binding is not configured.", 500)
			}
			document, err := s.binder.RenderResourcePolicy(tx.Context(), row.Policy)
			if err != nil {
				return nil, err
			}
			row.Policy.Document = document
		}
		out.ResourcePolicies = append(out.ResourcePolicies, policyOutput(row))
	}
	return out, nil
}

func (s *Service) deleteResourcePolicy(tx Transaction, in *api.DeleteResourcePolicyRequest) (*api.DeleteResourcePolicyResult, error) {
	rows, err := s.authorizedPolicies(tx, "DeleteResourcePolicy")
	if err != nil {
		return nil, err
	}
	name := value(in.PolicyName)
	for _, row := range rows {
		if row.Key.Name != name {
			continue
		}
		if _, err := cloudFormationClaim(tx.Context(), row.CFNOwner, true); err != nil {
			return nil, err
		}
		if in.PolicyRevisionId != nil && value(in.PolicyRevisionId) != strconv.FormatInt(row.Revision, 10) {
			return nil, revisionConflict(name)
		}
		if err := tx.DeleteResourcePolicy(row.Key); err != nil {
			return nil, err
		}
		return &api.DeleteResourcePolicyResult{}, nil
	}
	if in.PolicyRevisionId != nil {
		return nil, revisionConflict(name)
	}
	return nil, failure("InvalidRequestException", "Resource policy does not exist: "+name)
}

func revisionConflict(name string) error {
	return failure("InvalidPolicyRevisionIdException", "Another concurrent request has modified the resource policy "+name)
}

// Native policy retrieval collapses singleton action arrays. Keep the rest of
// the submitted policy document intact, including multivalued conditions.
func canonicalPolicy(document string) (string, error) {
	var object map[string]any
	if err := json.Unmarshal([]byte(document), &object); err != nil {
		return "", err
	}
	statements, ok := object["Statement"].([]any)
	if !ok {
		statements = []any{object["Statement"]}
	}
	for _, raw := range statements {
		statement, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for _, field := range []string{"Action", "NotAction"} {
			if list, ok := statement[field].([]any); ok && len(list) == 1 {
				statement[field] = list[0]
			}
		}
	}
	encoded, err := json.Marshal(object)
	return string(encoded), err
}
