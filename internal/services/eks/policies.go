package eks

import (
	"context"

	api "stackd/internal/awsapi/eks"
)

var accessPolicyRoles = map[string]string{"AmazonEKSClusterAdminPolicy": "cluster-admin", "AmazonEKSAdminPolicy": "admin", "AmazonEKSEditPolicy": "edit", "AmazonEKSViewPolicy": "view"}

func policyARN(partition, name string) string {
	return "arn:" + partition + ":eks::aws:cluster-access-policy/" + name
}
func policyRole(partition, arn string) (string, bool) {
	for name, role := range accessPolicyRoles {
		if arn == policyARN(partition, name) {
			return role, true
		}
	}
	return "", false
}
func (s *Service) associateAccessPolicy(ctx context.Context, tx Transaction, in *api.AssociateAccessPolicyRequest) (*api.AssociateAccessPolicyResponse, error) {
	principal := value(in.PrincipalArn)
	if in.AccessScope == nil {
		return nil, invalid("accessScope is required.")
	}
	scope := value(in.AccessScope.Type)
	namespaces := stringsFromAPI(in.AccessScope.Namespaces)
	arn := value(in.PolicyArn)
	conditions := map[string][]string{"eks:policyArn": {arn}, "eks:accessScope": {scope}}
	if len(namespaces) > 0 {
		conditions["eks:namespaces"] = namespaces
	}
	c, _, e := s.accessForAction(ctx, tx, value(in.ClusterName), principal, "AssociateAccessPolicy", true, conditions)
	if e != nil {
		return nil, e
	}
	if _, ok := policyRole(c.Key.Partition, arn); !ok {
		return nil, unsupported("This EKS access policy is not implemented.")
	}
	switch scope {
	case "cluster":
		if len(namespaces) > 0 {
			return nil, invalid("Cluster scope cannot specify namespaces.")
		}
	case "namespace":
		if len(namespaces) == 0 {
			return nil, invalid("Namespace scope requires at least one namespace.")
		}
	default:
		return nil, invalid("accessScope.type must be cluster or namespace.")
	}
	now := s.clock.Now()
	p := AccessPolicy{Key: c.Key, PrincipalARN: principal, PolicyARN: arn, ScopeType: scope, Namespaces: namespaces, Associated: now, Modified: now}
	all, e := tx.AccessPolicies(c.Key, principal)
	if e != nil {
		return nil, e
	}
	for _, old := range all {
		if old.PolicyARN == arn {
			p.Associated = old.Associated
			break
		}
	}
	if e = tx.PutAccessPolicy(p); e != nil {
		return nil, e
	}
	return &api.AssociateAccessPolicyResponse{ClusterName: new(api.String(c.Key.Name)), PrincipalArn: new(api.String(principal)), AssociatedAccessPolicy: associatedPolicyAPI(p)}, nil
}
func (s *Service) disassociateAccessPolicy(ctx context.Context, tx Transaction, in *api.DisassociateAccessPolicyRequest) (*api.DisassociateAccessPolicyResponse, error) {
	principal := value(in.PrincipalArn)
	c, _, e := s.accessForAction(ctx, tx, value(in.ClusterName), principal, "DisassociateAccessPolicy", true, map[string][]string{"eks:policyArn": {value(in.PolicyArn)}})
	if e != nil {
		return nil, e
	}
	all, e := tx.AccessPolicies(c.Key, principal)
	if e != nil {
		return nil, e
	}
	found := false
	for _, p := range all {
		if p.PolicyARN == value(in.PolicyArn) {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrNotFound
	}
	if e = tx.DeleteAccessPolicy(c.Key, principal, value(in.PolicyArn)); e != nil {
		return nil, e
	}
	return &api.DisassociateAccessPolicyResponse{}, nil
}
func (s *Service) listAssociatedAccessPolicies(ctx context.Context, tx Transaction, in *api.ListAssociatedAccessPoliciesRequest) (*api.ListAssociatedAccessPoliciesResponse, error) {
	principal := value(in.PrincipalArn)
	c, _, e := s.accessForAction(ctx, tx, value(in.ClusterName), principal, "ListAssociatedAccessPolicies", false, nil)
	if e != nil {
		return nil, e
	}
	all, e := tx.AccessPolicies(c.Key, principal)
	if e != nil {
		return nil, e
	}
	names := []string{}
	byARN := map[string]AccessPolicy{}
	for _, p := range all {
		names = append(names, p.PolicyARN)
		byARN[p.PolicyARN] = p
	}
	page, next, e := pageStrings(names, value(in.NextToken), pageLimit(in.MaxResults), c.Key.ARN()+"/policies/"+principal)
	if e != nil {
		return nil, e
	}
	out := &api.ListAssociatedAccessPoliciesResponse{ClusterName: new(api.String(c.Key.Name)), PrincipalArn: new(api.String(principal)), NextToken: next, AssociatedAccessPolicies: api.AssociatedAccessPoliciesList{}}
	for _, arn := range page {
		out.AssociatedAccessPolicies = append(out.AssociatedAccessPolicies, *associatedPolicyAPI(byARN[arn]))
	}
	return out, nil
}
func (s *Service) listAccessPolicies(ctx context.Context, _ Transaction, in *api.ListAccessPoliciesRequest) (*api.ListAccessPoliciesResponse, error) {
	sc := scopeFor(ctx)
	if e := s.authorize(ctx, Cluster{Key: Key{Scope: sc}}, "ListAccessPolicies", nil); e != nil {
		return nil, e
	}
	names := []string{}
	for name := range accessPolicyRoles {
		names = append(names, name)
	}
	page, next, e := pageStrings(names, value(in.NextToken), pageLimit(in.MaxResults), scKey(sc)+"/access-policies")
	if e != nil {
		return nil, e
	}
	out := &api.ListAccessPoliciesResponse{NextToken: next, AccessPolicies: api.AccessPoliciesList{}}
	for _, name := range page {
		out.AccessPolicies = append(out.AccessPolicies, api.AccessPolicy{Name: new(api.String(name)), Arn: new(api.String(policyARN(sc.Partition, name)))})
	}
	return out, nil
}
func associatedPolicyAPI(p AccessPolicy) *api.AssociatedAccessPolicy {
	return &api.AssociatedAccessPolicy{PolicyArn: new(api.String(p.PolicyARN)), AccessScope: &api.AccessScope{Type: new(api.AccessScopeType(p.ScopeType)), Namespaces: stringsToAPI(p.Namespaces)}, AssociatedAt: new(p.Associated), ModifiedAt: new(p.Modified)}
}
