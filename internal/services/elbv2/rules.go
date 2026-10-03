package elbv2

import (
	"context"
	"fmt"
	"slices"
	api "stackd/internal/awsapi/elbv2"
	"strconv"
	"strings"
)

func registerRules(s *Service) {
	register(s, "CreateRule", s.createRule)
	register(s, "DeleteRule", s.deleteRule)
	register(s, "DescribeRules", s.describeRules)
	register(s, "ModifyRule", s.modifyRule)
	register(s, "SetRulePriorities", s.setRulePriorities)
}
func (s *Service) createRule(ctx context.Context, tx Transaction, in *api.CreateRuleInput) (*api.CreateRuleOutput, error) {
	sc := scopeFor(ctx)
	l, e := listener(tx, sc, value(in.ListenerArn))
	if e != nil {
		return nil, e
	}
	lb, e := loadBalancer(tx, sc, value(l.Data.LoadBalancerArn))
	if e != nil {
		return nil, e
	}
	if in.Priority == nil || *in.Priority < 1 || *in.Priority > 50000 {
		return nil, invalid("Priority must be between 1 and 50000")
	}
	if len(in.Transforms) > 0 {
		return nil, unsupported("Rule transforms are not supported")
	}
	resource := strings.Replace(value(l.Data.ListenerArn), ":listener/", ":listener-rule/", 1) + "/*"
	if e = s.authorizeChildCreate(ctx, "CreateRule", value(l.Data.ListenerArn), l.Tags, resource, in.Tags, nil); e != nil {
		return nil, e
	}
	if e = validateConditions(in.Conditions); e != nil {
		return nil, e
	}
	if e = s.validateActions(tx, in.Actions, false); e != nil {
		return nil, e
	}
	if e = validateRedirectProtocol(value(l.Data.Protocol), in.Actions); e != nil {
		return nil, e
	}
	if e = validateActionNetwork(tx, lb, in.Actions); e != nil {
		return nil, e
	}
	rs, e := tx.Rules(sc)
	if e != nil {
		return nil, e
	}
	priority := strconv.FormatInt(int64(*in.Priority), 10)
	for _, r := range rs {
		if r.ListenerARN == value(l.Data.ListenerArn) && value(r.Data.Priority) == priority {
			return nil, failure("PriorityInUse", "The requested priority is in use")
		}
	}
	id, e := tx.NextID()
	if e != nil {
		return nil, e
	}
	r := RuleRecord{Scope: sc, ListenerARN: value(l.Data.ListenerArn), Tags: in.Tags, Data: api.Rule{Actions: in.Actions, Conditions: in.Conditions}}
	text(&r.Data.RuleArn, strings.TrimSuffix(resource, "*")+fmt.Sprintf("%016x", id))
	text(&r.Data.Priority, priority)
	boolean(&r.Data.IsDefault, false)
	if e = tx.PutRule(r); e != nil {
		return nil, e
	}
	if e = refreshAssociations(tx, sc); e != nil {
		return nil, e
	}
	if e = s.touchLoadBalancer(tx, sc, value(lb.Data.LoadBalancerArn)); e != nil {
		return nil, e
	}
	return &api.CreateRuleOutput{Rules: api.Rules{r.Data}}, nil
}
func (s *Service) deleteRule(ctx context.Context, tx Transaction, in *api.DeleteRuleInput) (*api.DeleteRuleOutput, error) {
	sc := scopeFor(ctx)
	r, e := rule(tx, sc, value(in.RuleArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "DeleteRule", value(in.RuleArn), r.Tags, nil); e != nil {
		return nil, e
	}
	if r.Data.IsDefault != nil && *r.Data.IsDefault {
		return nil, failure("OperationNotPermitted", "The default rule cannot be deleted")
	}
	l, e := listener(tx, sc, r.ListenerARN)
	if e != nil {
		return nil, e
	}
	if e = tx.DeleteRule(sc, value(in.RuleArn)); e != nil {
		return nil, e
	}
	if e = refreshAssociations(tx, sc); e != nil {
		return nil, e
	}
	if e = s.touchLoadBalancer(tx, sc, value(l.Data.LoadBalancerArn)); e != nil {
		return nil, e
	}
	return &api.DeleteRuleOutput{}, nil
}
func (s *Service) describeRules(ctx context.Context, tx Transaction, in *api.DescribeRulesInput) (*api.DescribeRulesOutput, error) {
	sc := scopeFor(ctx)
	if e := s.authorize(ctx, "DescribeRules", "*", nil, nil); e != nil {
		return nil, e
	}
	if in.ListenerArn != nil && len(in.RuleArns) > 0 {
		return nil, invalid("Specify a listener or rule ARNs")
	}
	if in.ListenerArn == nil && len(in.RuleArns) == 0 {
		return nil, invalid("ListenerArn or RuleArns is required")
	}
	if in.ListenerArn != nil {
		if _, e := listener(tx, sc, value(in.ListenerArn)); e != nil {
			return nil, e
		}
	}
	rs, e := tx.Rules(sc)
	if e != nil {
		return nil, e
	}
	out := api.Rules{}
	found := map[string]bool{}
	for _, r := range rs {
		if in.ListenerArn != nil && r.ListenerARN != value(in.ListenerArn) {
			continue
		}
		if len(in.RuleArns) > 0 && !slices.Contains(in.RuleArns, *r.Data.RuleArn) {
			continue
		}
		out = append(out, r.Data)
		found[value(r.Data.RuleArn)] = true
	}
	for _, a := range in.RuleArns {
		if !found[string(a)] {
			return nil, failure("RuleNotFound", "Rule does not exist")
		}
	}
	slices.SortFunc(out, func(a, b api.Rule) int { return strings.Compare(rulePageKey(a), rulePageKey(b)) })
	out, next, e := page(out, in.Marker, in.PageSize, fmt.Sprint("DescribeRules:", sc, value(in.ListenerArn), in.RuleArns), rulePageKey)
	return &api.DescribeRulesOutput{Rules: out, NextMarker: next}, e
}
func rulePageKey(r api.Rule) string {
	p := 50001
	if value(r.Priority) != "default" {
		p, _ = strconv.Atoi(value(r.Priority))
	}
	return fmt.Sprintf("%05d:%s", p, value(r.RuleArn))
}
func (s *Service) modifyRule(ctx context.Context, tx Transaction, in *api.ModifyRuleInput) (*api.ModifyRuleOutput, error) {
	sc := scopeFor(ctx)
	r, e := rule(tx, sc, value(in.RuleArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "ModifyRule", value(in.RuleArn), r.Tags, nil); e != nil {
		return nil, e
	}
	if len(in.Transforms) > 0 || (in.ResetTransforms != nil && *in.ResetTransforms) {
		return nil, unsupported("Rule transforms are not supported")
	}
	isDefault := r.Data.IsDefault != nil && *r.Data.IsDefault
	if isDefault && in.Conditions != nil {
		return nil, failure("OperationNotPermitted", "The default rule cannot have conditions")
	}
	if in.Conditions != nil {
		if e = validateConditions(in.Conditions); e != nil {
			return nil, e
		}
		r.Data.Conditions = in.Conditions
	}
	if in.Actions != nil {
		if e = s.validateActions(tx, in.Actions, bool(isDefault)); e != nil {
			return nil, e
		}
		r.Data.Actions = in.Actions
	}
	l, e := listener(tx, sc, r.ListenerARN)
	if e != nil {
		return nil, e
	}
	lb, e := loadBalancer(tx, sc, value(l.Data.LoadBalancerArn))
	if e != nil {
		return nil, e
	}
	if e = validateRedirectProtocol(value(l.Data.Protocol), r.Data.Actions); e != nil {
		return nil, e
	}
	if e = validateActionNetwork(tx, lb, r.Data.Actions); e != nil {
		return nil, e
	}
	if e = tx.PutRule(r); e != nil {
		return nil, e
	}
	if isDefault {
		l.Data.DefaultActions = r.Data.Actions
		if e = tx.PutListener(l); e != nil {
			return nil, e
		}
	}
	if e = refreshAssociations(tx, sc); e != nil {
		return nil, e
	}
	if e = s.touchLoadBalancer(tx, sc, value(lb.Data.LoadBalancerArn)); e != nil {
		return nil, e
	}
	return &api.ModifyRuleOutput{Rules: api.Rules{r.Data}}, nil
}
func (s *Service) setRulePriorities(ctx context.Context, tx Transaction, in *api.SetRulePrioritiesInput) (*api.SetRulePrioritiesOutput, error) {
	sc := scopeFor(ctx)
	if len(in.RulePriorities) == 0 {
		return nil, invalid("RulePriorities is required")
	}
	rs, e := tx.Rules(sc)
	if e != nil {
		return nil, e
	}
	byARN := map[string]RuleRecord{}
	for _, r := range rs {
		byARN[value(r.Data.RuleArn)] = r
	}
	changes := map[string]string{}
	for _, p := range in.RulePriorities {
		a := value(p.RuleArn)
		if _, ok := changes[a]; ok {
			return nil, invalid("A rule can be specified only once")
		}
		r, ok := byARN[a]
		if !ok {
			return nil, failure("RuleNotFound", "Rule does not exist")
		}
		if e = s.authorize(ctx, "SetRulePriorities", a, r.Tags, nil); e != nil {
			return nil, e
		}
		if r.Data.IsDefault != nil && *r.Data.IsDefault {
			return nil, failure("OperationNotPermitted", "The default rule cannot change priority")
		}
		if p.Priority == nil || *p.Priority < 1 || *p.Priority > 50000 {
			return nil, invalid("Priority must be between 1 and 50000")
		}
		changes[a] = strconv.FormatInt(int64(*p.Priority), 10)
	}
	used := map[string]bool{}
	for _, r := range rs {
		p := value(r.Data.Priority)
		if changed, ok := changes[value(r.Data.RuleArn)]; ok {
			p = changed
		}
		key := r.ListenerARN + ":" + p
		if used[key] {
			return nil, failure("PriorityInUse", "A priority is already in use")
		}
		used[key] = true
	}
	out := api.Rules{}
	for _, p := range in.RulePriorities {
		r := byARN[value(p.RuleArn)]
		text(&r.Data.Priority, changes[value(p.RuleArn)])
		if e = tx.PutRule(r); e != nil {
			return nil, e
		}
		l, e := listener(tx, sc, r.ListenerARN)
		if e != nil {
			return nil, e
		}
		if e = s.touchLoadBalancer(tx, sc, value(l.Data.LoadBalancerArn)); e != nil {
			return nil, e
		}
		out = append(out, r.Data)
	}
	return &api.SetRulePrioritiesOutput{Rules: out}, nil
}
