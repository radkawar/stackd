package ram

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

type ManagedResourcePolicy struct {
	ID     string
	Policy authorization.BoundPolicy
}

func (s *Service) sharePermission(r Reader, sh Share, a PermissionAssociation) (Permission, error) {
	for _, p := range s.managed {
		arn := strings.Replace(p.ARN, "arn:aws:", "arn:"+sh.Partition+":", 1)
		if arn == a.ARN {
			p.ARN = arn
			return p, nil
		}
	}
	p, e := r.Permission(a.ARN)
	if e != nil {
		return p, e
	}
	if p.Scope != sh.Scope || p.Status == "DELETED" {
		return Permission{}, ErrNotFound
	}
	return p, nil
}
func (s *Service) invitationStatus(i Invitation) string {
	if i.Status == "PENDING" && !s.clock.Now().Before(i.Created.Add(12*time.Hour)) {
		return "EXPIRED"
	}
	return i.Status
}
func (s *Service) principalAssociationStatus(r Reader, p PrincipalAssociation) (string, error) {
	if p.Status == "ASSOCIATING" && p.InvitationARN != "" {
		i, e := r.Invitation(p.InvitationARN)
		if e != nil {
			return "", e
		}
		if s.invitationStatus(i) == "EXPIRED" {
			return "DISASSOCIATED", nil
		}
	}
	return p.Status, nil
}
func (s *Service) principalActive(r Reader, sh Share, p PrincipalAssociation, recipient string) (bool, error) {
	if p.Status != "ASSOCIATED" {
		return false, nil
	}
	if p.InvitationARN != "" {
		i, e := r.Invitation(p.InvitationARN)
		if errors.Is(e, ErrNotFound) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		return s.invitationStatus(i) == "ACCEPTED" && i.Receiver == recipient, nil
	}
	if !p.Organization {
		return principalAccount(p.Principal) == recipient, nil
	}
	account := principalAccount(p.Principal)
	if account != "" {
		if account != recipient {
			return false, nil
		}
		if account == sh.AccountID {
			return true, nil
		}
		if s.organization == nil {
			return false, nil
		}
		return s.organization.Eligible(r.Context(), sh.AccountID, account, recipient)
	}
	if s.organization == nil {
		return false, nil
	}
	return s.organization.Eligible(r.Context(), sh.AccountID, p.Principal, recipient)
}
func principalVisible(ctx context.Context, p PrincipalAssociation) bool {
	if p.PrincipalID == "" {
		return true
	}
	m := awsctx.FromContext(ctx)
	id, _, _ := strings.Cut(m.PrincipalID, ":")
	return id == p.PrincipalID || m.IssuerID == p.PrincipalID
}
func (s *Service) visibleShare(r Reader, sh Share, owner string) (bool, error) {
	sc := scopeFor(r.Context())
	if sh.Partition != sc.Partition || sh.Region != sc.Region {
		return false, nil
	}
	if owner == "SELF" {
		return sh.AccountID == sc.AccountID, nil
	}
	if owner != "OTHER-ACCOUNTS" {
		return false, failure("InvalidParameterException", "ResourceOwner must be SELF or OTHER-ACCOUNTS.")
	}
	if sh.AccountID == sc.AccountID || sh.Status != "ACTIVE" || sh.FeatureSet != "STANDARD" {
		return false, nil
	}
	for _, p := range sh.Principals {
		if !principalVisible(r.Context(), p) {
			continue
		}
		ok, e := s.principalActive(r, sh, p, sc.AccountID)
		if e != nil {
			return false, e
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
func (s *Service) currentResource(r Reader, a ResourceAssociation) (ResourceIdentity, bool, error) {
	if a.Status != "ASSOCIATED" {
		return ResourceIdentity{}, false, nil
	}
	v, e := s.resolve(r, a.ARN)
	if errors.Is(e, ErrNotFound) || errors.Is(e, ErrUnsupportedResource) {
		return ResourceIdentity{}, false, nil
	}
	if e != nil {
		return ResourceIdentity{}, false, e
	}
	return v, v.AccountID == a.AccountID && v.Partition == a.Partition && v.Region == a.Region, nil
}

// ResourcePolicies returns only live, accepted grants. The resource owner must add
// these policies to its ordinary evaluator so identity ceilings, RCPs and trusted
// resource context remain authoritative. This method never evaluates IAM itself.
func (s *Service) ResourcePolicies(ctx context.Context, arn string) ([]authorization.BoundPolicy, error) {
	var out []authorization.BoundPolicy
	e := s.repository.View(ctx, func(r Reader) error {
		policies, e := s.resourcePolicies(r, arn, awsctx.FromContext(ctx).AccountID, false)
		if e != nil {
			return e
		}
		for _, p := range policies {
			out = append(out, p.Policy)
		}
		return nil
	})
	return out, e
}

// ManagedResourcePolicies projects owner-visible current policies without a second
// stored resource policy. Pending invitations contribute no effective statements.
func (s *Service) ManagedResourcePolicies(ctx context.Context, arn string) ([]ManagedResourcePolicy, error) {
	var out []ManagedResourcePolicy
	e := s.repository.View(ctx, func(r Reader) error { var e error; out, e = s.resourcePolicies(r, arn, "", true); return e })
	return out, e
}
func (s *Service) resourcePolicies(r Reader, arn, recipient string, inspection bool) ([]ManagedResourcePolicy, error) {
	current, e := s.resolve(r, arn)
	if errors.Is(e, ErrNotFound) || errors.Is(e, ErrUnsupportedResource) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	shares, e := r.Shares()
	if e != nil {
		return nil, e
	}
	out := []ManagedResourcePolicy{}
	for _, sh := range shares {
		if sh.Status != "ACTIVE" || sh.FeatureSet != "STANDARD" || sh.PolicyID != "" || sh.Partition != current.Partition || sh.Region != current.Region || sh.AccountID != current.AccountID {
			continue
		}
		found := false
		for _, a := range sh.Resources {
			if a.ARN == arn && a.Status == "ASSOCIATED" {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		var permission PermissionVersion
		for _, a := range sh.Permissions {
			if a.ResourceType != current.ResourceType {
				continue
			}
			p, err := s.sharePermission(r, sh, a)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			permission, err = versionOf(p, a.Version)
			if err != nil {
				return nil, err
			}
		}
		if permission.Deleted || permission.Document == "" {
			continue
		}
		statements := []map[string]json.RawMessage{}
		ids := map[string]string{}
		for _, p := range sh.Principals {
			target := recipient
			if inspection {
				target = principalAccount(p.Principal)
				if target == "" {
					if s.organization == nil {
						continue
					}
					ok, err := s.organization.Eligible(r.Context(), sh.AccountID, p.Principal, "")
					if err != nil {
						return nil, err
					}
					if !ok {
						continue
					}
					target = sh.AccountID
				}
			}
			if !inspection || principalAccount(p.Principal) != "" {
				active, err := s.principalActive(r, sh, p, target)
				if err != nil {
					return nil, err
				}
				if !active {
					continue
				}
			} else if p.Status != "ASSOCIATED" {
				continue
			}
			rows, err := templateStatements(permission.Document)
			if err != nil {
				return nil, err
			}
			principal := p.Principal
			org := principalAccount(principal) == ""
			if accountPattern.MatchString(principal) {
				principal = "arn:" + sh.Partition + ":iam::" + principal + ":root"
			}
			for _, row := range rows {
				row["Resource"], _ = json.Marshal(arn)
				if org {
					row["Principal"] = json.RawMessage(`"*"`)
					if inspection {
						if err = addOrganizationCondition(row, p.Principal); err != nil {
							return nil, err
						}
					}
				} else {
					row["Principal"], _ = json.Marshal(map[string]string{"AWS": principal})
				}
				statements = append(statements, row)
			}
			if p.PrincipalID != "" {
				ids[p.Principal] = p.PrincipalID
			}
		}
		if len(statements) == 0 {
			continue
		}
		doc, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
		if err != nil {
			return nil, err
		}
		out = append(out, ManagedResourcePolicy{ID: sh.ARN, Policy: authorization.BoundPolicy{Document: string(doc), PrincipalIDs: ids}})
	}
	return out, nil
}
func addOrganizationCondition(row map[string]json.RawMessage, principal string) error {
	parts := strings.SplitN(principal, ":", 6)
	if len(parts) != 6 {
		return ErrNotFound
	}
	ids := strings.Split(parts[5], "/")
	if len(ids) < 2 {
		return ErrNotFound
	}
	var conditions map[string]map[string]json.RawMessage
	if raw := row["Condition"]; len(raw) > 0 {
		if e := json.Unmarshal(raw, &conditions); e != nil {
			return e
		}
	}
	if conditions == nil {
		conditions = map[string]map[string]json.RawMessage{}
	}
	operator, key, expected := "StringEquals", "aws:PrincipalOrgID", ids[1]
	if len(ids) == 3 {
		operator, key, expected = "ForAnyValue:StringLike", "aws:PrincipalOrgPaths", ids[1]+"/*/"+ids[2]+"/*"
	}
	if conditions[operator] == nil {
		conditions[operator] = map[string]json.RawMessage{}
	}
	if _, present := conditions[operator][key]; !present {
		conditions[operator][key], _ = json.Marshal(expected)
	}
	row["Condition"], _ = json.Marshal(conditions)
	return nil
}

// ResourcePermission is a convenience check using the ordinary configured IAM
// evaluator; owners with resource-specific condition context use ResourcePolicies.
func (s *Service) ResourcePermission(ctx context.Context, q PermissionQuery) (bool, error) {
	if q.AccountID != "" && q.AccountID != awsctx.FromContext(ctx).AccountID {
		return false, nil
	}
	policies, e := s.ResourcePolicies(ctx, q.ResourceARN)
	if e != nil || len(policies) == 0 {
		return false, e
	}
	now := s.clock.Now()
	return s.authorizer.Authorize(ctx, authorization.Request{Action: q.Action, ResourceARN: q.ResourceARN, ResourcePolicies: policies, RequireResourcePolicy: true, EvaluationTime: &now}) == nil, nil
}

// SharedResources enumerates potential current grants, not an IAM authorization
// result. Consumers must perform ordinary owner authorization for every result.
func (s *Service) SharedResources(ctx context.Context, q SharedResourcesQuery) ([]ResourceIdentity, error) {
	out := []ResourceIdentity{}
	e := s.repository.View(ctx, func(r Reader) error {
		shares, e := r.Shares()
		if e != nil {
			return e
		}
		seen := map[string]bool{}
		for _, sh := range shares {
			if sh.Status != "ACTIVE" || sh.FeatureSet != "STANDARD" || sh.PolicyID != "" || sh.Partition != q.Partition || sh.Region != q.Region {
				continue
			}
			eligible := false
			for _, p := range sh.Principals {
				if !principalVisible(ctx, p) {
					continue
				}
				ok, e := s.principalActive(r, sh, p, q.AccountID)
				if e != nil {
					return e
				}
				eligible = eligible || ok
			}
			if !eligible {
				continue
			}
			for _, a := range sh.Resources {
				if seen[a.ARN] || q.ResourceType != "" && q.ResourceType != a.ResourceType {
					continue
				}
				resource, ok, e := s.currentResource(r, a)
				if e != nil {
					return e
				}
				if !ok {
					continue
				}
				if q.Action != "" {
					allowed := false
					for _, pa := range sh.Permissions {
						if pa.ResourceType != a.ResourceType {
							continue
						}
						p, e := s.sharePermission(r, sh, pa)
						if e != nil {
							return e
						}
						v, e := versionOf(p, pa.Version)
						if e != nil {
							return e
						}
						allowed = !v.Deleted && actionAllowed(v.Actions, q.Action)
					}
					if !allowed {
						continue
					}
				}
				seen[a.ARN] = true
				out = append(out, resource)
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b ResourceIdentity) int { return strings.Compare(a.ARN, b.ARN) })
	return out, e
}

// HasResourceShares is an owner-side deletion dependency check.
func (s *Service) HasResourceShares(ctx context.Context, arn string) (bool, error) {
	found := false
	e := s.repository.View(ctx, func(r Reader) error {
		shares, e := r.Shares()
		if e != nil {
			return e
		}
		for _, sh := range shares {
			if sh.Status != "ACTIVE" {
				continue
			}
			for _, a := range sh.Resources {
				if a.ARN == arn && a.Status == "ASSOCIATED" {
					found = true
					return nil
				}
			}
		}
		return nil
	})
	return found, e
}

// ResourceDeleted is called by the owner inside its deletion transaction. It
// revokes associations before another resource can be created at the same ARN.
func (s *Service) ResourceDeleted(ctx context.Context, arn string) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		shares, e := tx.Shares()
		if e != nil {
			return e
		}
		for _, sh := range shares {
			changed := false
			for i := range sh.Resources {
				a := &sh.Resources[i]
				if a.ARN == arn && a.Status != "DISASSOCIATED" {
					a.Status = "DISASSOCIATED"
					a.StatusMessage = "The resource was deleted."
					a.Updated = s.clock.Now()
					changed = true
				}
			}
			if changed {
				sh.Updated = s.clock.Now()
				if sh.FeatureSet == "CREATED_FROM_POLICY" {
					sh.Status = "DELETED"
				}
				if e = tx.PutShare(sh); e != nil {
					return e
				}
			}
		}
		return nil
	})
}
