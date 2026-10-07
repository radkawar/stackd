package wafv2

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/wafv2"
)

func registerIPSets(s *Service) {
	register(s, "CreateIPSet", s.createIPSet)
	register(s, "GetIPSet", s.getIPSet)
	register(s, "ListIPSets", s.listIPSets)
	register(s, "UpdateIPSet", s.updateIPSet)
	register(s, "DeleteIPSet", s.deleteIPSet)
}

func ipSetARN(sc Scope, name, id string) string {
	return "arn:" + sc.Partition + ":wafv2:" + sc.Region + ":" + sc.AccountID + ":regional/ipset/" + name + "/" + id
}

func (v IPSet) model() *api.IPSet {
	out := &api.IPSet{ARN: new(api.ResourceArn(v.ARN)), Name: new(api.EntityName(v.Name)), Id: new(api.EntityId(v.ID)), IPAddressVersion: new(api.IPAddressVersion(v.IPAddressVersion)), Addresses: api.IPAddresses{}}
	for _, a := range v.Addresses {
		out.Addresses = append(out.Addresses, api.IPAddress(a))
	}
	if v.Description != "" {
		out.Description = new(api.EntityDescription(v.Description))
	}
	return out
}

func (v IPSet) summary() api.IPSetSummary {
	out := api.IPSetSummary{ARN: new(api.ResourceArn(v.ARN)), Name: new(api.EntityName(v.Name)), Id: new(api.EntityId(v.ID)), LockToken: new(api.LockToken(v.LockToken))}
	if v.Description != "" {
		out.Description = new(api.EntityDescription(v.Description))
	}
	return out
}

func (s *Service) loadIPSet(ctx context.Context, r Reader, name, id, action string) (IPSet, error) {
	sc := scopeFor(ctx)
	v, err := r.IPSet(sc, ipSetARN(sc, name, id))
	if errors.Is(err, ErrNotFound) {
		return v, nonexistent("AWS WAF couldn’t find the IP set " + name + " with ID " + id)
	}
	if err != nil {
		return v, err
	}
	if err := s.authorize(ctx, "wafv2:"+action, v.ARN, v.Tags, nil); err != nil {
		return v, err
	}
	return v, checkResourceOwner(ctx, v.Owner)
}

func (s *Service) createIPSet(ctx context.Context, t Transaction, in *api.CreateIPSetInput) (*api.CreateIPSetOutput, error) {
	if err := requireRegional(in.Scope); err != nil {
		return nil, err
	}
	name := value(in.Name)
	if !entityName.MatchString(name) {
		return nil, invalidParameter("NAME", name, "Name must match ^[\\w\\-]+$ and contain 1-128 characters")
	}
	if err := validDescription(in.Description); err != nil {
		return nil, err
	}
	addresses, err := validateAddresses(value(in.IPAddressVersion), in.Addresses)
	if err != nil {
		return nil, err
	}
	tags, conditions, err := requestTags(in.Tags)
	if err != nil {
		return nil, err
	}
	sc := scopeFor(ctx)
	owner, err := resourceOwnerFor(ctx)
	if err != nil {
		return nil, err
	}
	existing, err := t.IPSets(sc)
	if err != nil {
		return nil, err
	}
	for _, other := range existing {
		if other.Name == name {
			if err := s.authorize(ctx, "wafv2:CreateIPSet", other.ARN, other.Tags, conditions); err != nil {
				return nil, err
			}
			if owner != (ResourceOwner{}) && other.Owner == owner {
				summary := other.summary()
				return &api.CreateIPSetOutput{Summary: &summary}, nil
			}
			return nil, failure("WAFDuplicateItemException", "AWS WAF couldn’t perform the operation because some resource in your request is a duplicate of an existing one.", 400)
		}
	}
	id := uuid.NewString()
	v := IPSet{Scope: sc, Name: name, ID: id, ARN: ipSetARN(sc, name, id), Description: value(in.Description), LockToken: uuid.NewString(), IPAddressVersion: value(in.IPAddressVersion), Addresses: addresses, Tags: tags, Owner: owner}
	if err := s.authorize(ctx, "wafv2:CreateIPSet", v.ARN, nil, conditions); err != nil {
		return nil, err
	}
	if len(existing) >= 100 {
		return nil, failure("WAFLimitsExceededException", "The account already has the maximum of 100 regional IP sets", 400)
	}
	v.Created = s.clock.Now().UTC()
	v.Updated = v.Created
	if err := t.PutIPSet(v); err != nil {
		return nil, err
	}
	summary := v.summary()
	return &api.CreateIPSetOutput{Summary: &summary}, nil
}

func (s *Service) getIPSet(ctx context.Context, t Transaction, in *api.GetIPSetInput) (*api.GetIPSetOutput, error) {
	if err := requireRegional(in.Scope); err != nil {
		return nil, err
	}
	v, err := s.loadIPSet(ctx, t, value(in.Name), value(in.Id), "GetIPSet")
	if err != nil {
		return nil, err
	}
	return &api.GetIPSetOutput{IPSet: v.model(), LockToken: new(api.LockToken(v.LockToken))}, nil
}

func (s *Service) listIPSets(ctx context.Context, t Transaction, in *api.ListIPSetsInput) (*api.ListIPSetsOutput, error) {
	if err := requireRegional(in.Scope); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "wafv2:ListIPSets", "", nil, nil); err != nil {
		return nil, err
	}
	rows, err := t.IPSets(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	owner, err := resourceOwnerFor(ctx)
	if err != nil {
		return nil, err
	}
	if owner != (ResourceOwner{}) {
		owned := rows[:0]
		for _, v := range rows {
			if v.Owner == owner {
				if err := s.authorize(ctx, "wafv2:GetIPSet", v.ARN, v.Tags, nil); err != nil {
					return nil, err
				}
				owned = append(owned, v)
			}
		}
		rows = owned
	}
	start, end, next, err := page(in.Limit, in.NextMarker, len(rows))
	if err != nil {
		return nil, err
	}
	out := &api.ListIPSetsOutput{IPSets: api.IPSetSummaries{}, NextMarker: next}
	for _, v := range rows[start:end] {
		out.IPSets = append(out.IPSets, v.summary())
	}
	return out, nil
}

func (s *Service) updateIPSet(ctx context.Context, t Transaction, in *api.UpdateIPSetInput) (*api.UpdateIPSetOutput, error) {
	if err := requireRegional(in.Scope); err != nil {
		return nil, err
	}
	v, err := s.loadIPSet(ctx, t, value(in.Name), value(in.Id), "UpdateIPSet")
	if err != nil {
		return nil, err
	}
	if err := validDescription(in.Description); err != nil {
		return nil, err
	}
	addresses, err := validateAddresses(v.IPAddressVersion, in.Addresses)
	if err != nil {
		return nil, err
	}
	if err := checkLock(v.LockToken, in.LockToken); err != nil {
		return nil, err
	}
	v.Addresses, v.Description = addresses, value(in.Description)
	v.LockToken, v.Updated = uuid.NewString(), s.clock.Now().UTC()
	if err := t.PutIPSet(v); err != nil {
		return nil, err
	}
	return &api.UpdateIPSetOutput{NextLockToken: new(api.LockToken(v.LockToken))}, nil
}

func (s *Service) deleteIPSet(ctx context.Context, t Transaction, in *api.DeleteIPSetInput) (*api.DeleteIPSetOutput, error) {
	if err := requireRegional(in.Scope); err != nil {
		return nil, err
	}
	v, err := s.loadIPSet(ctx, t, value(in.Name), value(in.Id), "DeleteIPSet")
	if err != nil {
		return nil, err
	}
	if err := checkLock(v.LockToken, in.LockToken); err != nil {
		return nil, err
	}
	acls, err := t.WebACLs(v.Scope)
	if err != nil {
		return nil, err
	}
	for _, acl := range acls {
		if slices.Contains(definitionIPSets(acl.Definition), v.ARN) {
			return nil, failure("WAFAssociatedItemException", "AWS WAF couldn’t perform the operation because your resource is being used by another resource or it’s associated with another resource.", 400)
		}
	}
	if err := t.DeleteIPSet(v.Scope, v.ARN); err != nil {
		return nil, err
	}
	return &api.DeleteIPSetOutput{}, nil
}

// definitionIPSets lists the IP set ARNs referenced by a stored definition.
func definitionIPSets(d Definition) []string {
	var out []string
	var walk func(*api.Statement)
	walk = func(s *api.Statement) {
		if s == nil {
			return
		}
		switch {
		case s.IPSetReferenceStatement != nil:
			out = append(out, value(s.IPSetReferenceStatement.ARN))
		case s.AndStatement != nil:
			for i := range s.AndStatement.Statements {
				walk(&s.AndStatement.Statements[i])
			}
		case s.OrStatement != nil:
			for i := range s.OrStatement.Statements {
				walk(&s.OrStatement.Statements[i])
			}
		case s.NotStatement != nil:
			walk(s.NotStatement.Statement)
		case s.RateBasedStatement != nil:
			walk(s.RateBasedStatement.ScopeDownStatement)
		}
	}
	for i := range d.Rules {
		walk(d.Rules[i].Statement)
	}
	return out
}
