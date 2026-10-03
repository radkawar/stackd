package logs

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awswire"
)

const maxAccountResourcePolicies = 10

func policyKey(ctx context.Context, name *api.PolicyName, arn *api.Arn) (PolicyKey, *awswire.Error) {
	k := PolicyKey{Scope: scopeFor(ctx), PolicyScope: PolicyScopeAccount, Name: value(name)}
	if name != nil && arn != nil {
		return k, invalid("Both policy name and resource arn cannot be specified at the same time.")
	}
	if arn != nil {
		if _, w := policyGroupKey(ctx, value(arn)); w != nil {
			return k, w
		}
		k.PolicyScope, k.Name = PolicyScopeResource, value(arn)
	} else if k.Name == "" {
		return k, invalid("A policy name or resource arn must be specified.")
	}
	return k, nil
}

func policyGroupKey(ctx context.Context, arn string) (GroupKey, *awswire.Error) {
	parts := strings.SplitN(arn, ":", 7)
	if len(parts) != 7 || parts[0] != "arn" || parts[2] != "logs" || parts[5] != "log-group" || !groupNamePattern.MatchString(parts[6]) {
		return GroupKey{}, failure("ValidationException", "Invalid resourceArn")
	}
	k := GroupKey{Scope: Scope{Partition: parts[1], AccountID: parts[4], Region: parts[3]}, Name: parts[6]}
	if k.Scope != scopeFor(ctx) {
		return k, failure("ResourceNotFoundException", "The specified log group does not exist.")
	}
	return k, nil
}

func policyConflict() *awswire.Error {
	return failure("OperationAbortedException", "A conflicting operation is currently in progress against this resource. Please try again.")
}

func expectedRevision(p *api.ExpectedRevisionId) (int64, *awswire.Error) {
	if p == nil {
		return 0, nil
	}
	n, err := strconv.ParseInt(value(p), 10, 64)
	if err != nil || n < 1 {
		return 0, invalid("Invalid ExpectedRevisionId")
	}
	return n, nil
}

func resourcePolicyOutput(p PolicyRecord, describe bool) api.ResourcePolicy {
	out := api.ResourcePolicy{PolicyDocument: new(api.PolicyDocument(p.Document)), LastUpdatedTime: new(api.Timestamp(p.Updated)), PolicyScope: new(api.PolicyScope(p.Key.PolicyScope))}
	if p.Key.PolicyScope == PolicyScopeAccount {
		out.PolicyName = new(api.PolicyName(p.Key.Name))
	} else {
		out.ResourceArn = new(api.Arn(p.Key.Name))
		if describe {
			out.RevisionId = new(api.ExpectedRevisionId(strconv.FormatInt(p.Revision, 10)))
		}
	}
	return out
}

func (s *Service) authorizePolicy(r Reader, action string, k PolicyKey) *awswire.Error {
	g := GroupRecord{Key: GroupKey{Scope: k.Scope}}
	if k.PolicyScope == PolicyScopeResource {
		key, w := policyGroupKey(r.Context(), k.Name)
		if w != nil {
			return w
		}
		g.Key = key
	}
	return s.authorize(r, action, g, "", nil, nil)
}

func (s *Service) putResourcePolicy(tx Transaction, in *api.PutResourcePolicyRequest) (*api.PutResourcePolicyResponse, *awswire.Error) {
	k, w := policyKey(tx.Context(), in.PolicyName, in.ResourceArn)
	if w != nil {
		return nil, w
	}
	if w := s.authorizePolicy(tx, "PutResourcePolicy", k); w != nil {
		return nil, w
	}
	if err := authorization.ValidateResourcePolicy([]byte(value(in.PolicyDocument))); err != nil {
		return nil, invalid("Error occurred while parsing accessPolicy. Please check if the accessPolicy has been constructed correctly using IAM grammar.")
	}
	var revision int64
	if k.PolicyScope == PolicyScopeResource {
		revision, w = expectedRevision(in.ExpectedRevisionId)
		if w != nil {
			return nil, w
		}
	}
	old, err := tx.ResourcePolicy(k)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, wireError(err)
	}
	p := PolicyRecord{Key: k, Document: value(in.PolicyDocument), Updated: s.clock.Now().UnixMilli()}
	if k.PolicyScope == PolicyScopeResource {
		gk, w := policyGroupKey(tx.Context(), k.Name)
		if w != nil {
			return nil, w
		}
		g, err := tx.Group(gk)
		if err != nil {
			return nil, wireError(err)
		}
		if revision != old.Revision {
			return nil, policyConflict()
		}
		p.GroupID, p.Revision = g.ID, old.Revision+1
	} else if errors.Is(err, ErrNotFound) {
		rows, err := tx.ResourcePolicies(PolicyQuery{Scope: k.Scope, PolicyScope: PolicyScopeAccount, Limit: maxAccountResourcePolicies})
		if err != nil {
			return nil, wireError(err)
		}
		if len(rows) >= maxAccountResourcePolicies {
			return nil, failure("LimitExceededException", "The maximum number of account resource policies has been reached.")
		}
	}
	if err := tx.PutResourcePolicy(p); err != nil {
		return nil, wireError(err)
	}
	out := &api.PutResourcePolicyResponse{ResourcePolicy: new(resourcePolicyOutput(p, false))}
	if k.PolicyScope == PolicyScopeResource {
		out.RevisionId = new(api.ExpectedRevisionId(strconv.FormatInt(p.Revision, 10)))
	}
	return out, nil
}

func (s *Service) describeResourcePolicies(tx Transaction, in *api.DescribeResourcePoliciesRequest) (*api.DescribeResourcePoliciesResponse, *awswire.Error) {
	kind := PolicyScopeAccount
	if in.PolicyScope != nil {
		kind = PolicyScope(*in.PolicyScope)
	}
	if kind != PolicyScopeAccount && kind != PolicyScopeResource {
		return nil, invalid("Invalid policyScope")
	}
	if kind == PolicyScopeAccount && in.ResourceArn != nil {
		return nil, invalid("Cannot provide ResourceArn for PolicyScope ACCOUNT")
	}
	if in.ResourceArn != nil {
		if _, w := policyGroupKey(tx.Context(), value(in.ResourceArn)); w != nil {
			return nil, w
		}
	}
	scope := scopeFor(tx.Context())
	if w := s.authorizePolicy(tx, "DescribeResourcePolicies", PolicyKey{Scope: scope}); w != nil {
		return nil, w
	}
	n, w := pageLimit(in.Limit, 50, 50)
	if w != nil {
		return nil, w
	}
	token, w := s.decodeToken(value(in.NextToken), queryIdentity("DescribeResourcePolicies", scope, kind, value(in.ResourceArn)))
	if w != nil {
		return nil, w
	}
	rows, err := tx.ResourcePolicies(PolicyQuery{Scope: scope, PolicyScope: kind, ResourceARN: value(in.ResourceArn), After: token.Name, Limit: n + 1})
	if err != nil {
		return nil, wireError(err)
	}
	out := &api.DescribeResourcePoliciesResponse{ResourcePolicies: api.ResourcePolicies{}}
	for _, p := range rows {
		if len(out.ResourcePolicies) == n {
			out.NextToken = encodeToken(token)
			break
		}
		out.ResourcePolicies = append(out.ResourcePolicies, resourcePolicyOutput(p, true))
		token.Name = p.Key.Name
	}
	return out, nil
}

func (s *Service) deleteResourcePolicy(tx Transaction, in *api.DeleteResourcePolicyRequest) (*api.DeleteResourcePolicyOutput, *awswire.Error) {
	k, w := policyKey(tx.Context(), in.PolicyName, in.ResourceArn)
	if w != nil {
		return nil, w
	}
	if w := s.authorizePolicy(tx, "DeleteResourcePolicy", k); w != nil {
		return nil, w
	}
	var revision int64
	if k.PolicyScope == PolicyScopeResource {
		revision, w = expectedRevision(in.ExpectedRevisionId)
		if w != nil {
			return nil, w
		}
		if in.ExpectedRevisionId == nil {
			return nil, invalid("Invalid ExpectedRevisionId")
		}
	}
	old, err := tx.ResourcePolicy(k)
	if errors.Is(err, ErrNotFound) {
		if k.PolicyScope == PolicyScopeResource {
			return nil, failure("ResourceNotFoundException", "No policy found for ResourceArn")
		}
		return nil, failure("ResourceNotFoundException", "Policy with name ["+k.Name+"] does not exist.")
	}
	if err != nil {
		return nil, wireError(err)
	}
	if k.PolicyScope == PolicyScopeResource && revision != old.Revision {
		return nil, policyConflict()
	}
	if err := tx.DeleteResourcePolicy(k); err != nil {
		return nil, wireError(err)
	}
	return &api.DeleteResourcePolicyOutput{}, nil
}
