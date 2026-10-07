package elbv2

import (
	"context"
	"errors"
)

type cloudFormationOwnershipKey struct{}
type cloudFormationOwnership struct {
	Kind, Claim, Target string
	Enforce             bool
	Rows                map[string]string
}

// WithCloudFormationOwnership binds private native-row incarnation metadata.
func WithCloudFormationOwnership(ctx context.Context, kind, claim, target string, enforce bool, rows map[string]string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnershipKey{}, &cloudFormationOwnership{kind, claim, target, enforce, rows})
}

type cloudFormationTransaction struct {
	Transaction
	owner *cloudFormationOwnership
}

var nativeCloudFormationOwnership cloudFormationOwnership

func bindCloudFormationOwnership(tx Transaction) Transaction {
	owner, _ := tx.Context().Value(cloudFormationOwnershipKey{}).(*cloudFormationOwnership)
	if owner == nil {
		owner = &nativeCloudFormationOwnership
	}
	return &cloudFormationTransaction{tx, owner}
}
func (t *cloudFormationTransaction) observe(kind, id, claim string) error {
	if t.owner.Kind != kind {
		return nil
	}
	if t.owner.Rows != nil {
		t.owner.Rows[id] = claim
	}
	if t.owner.Enforce && (t.owner.Target == "" || t.owner.Target == id) && claim != t.owner.Claim {
		return failure("DuplicateListener", "Resource belongs to another CloudFormation incarnation")
	}
	return nil
}
func (t *cloudFormationTransaction) admit(kind, id, old string, exists bool) (string, error) {
	if t.owner.Kind != kind {
		if !exists {
			return "", nil
		}
		return old, nil
	}
	if exists && old != t.owner.Claim {
		return "", failure("DuplicateListener", "Resource belongs to another CloudFormation incarnation")
	}
	if !exists && t.owner.Enforce {
		return "", failure("DuplicateListener", "CloudFormation incarnation no longer exists")
	}
	if t.owner.Rows != nil {
		t.owner.Rows[id] = t.owner.Claim
	}
	return t.owner.Claim, nil
}
func (t *cloudFormationTransaction) LoadBalancer(sc Scope, id string) (LoadBalancerRecord, error) {
	v, e := t.Transaction.LoadBalancer(sc, id)
	if e == nil {
		e = t.observe("LoadBalancer", id, v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) LoadBalancers(sc Scope) ([]LoadBalancerRecord, error) {
	rows, e := t.Transaction.LoadBalancers(sc)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("LoadBalancer", value(v.Data.LoadBalancerArn), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cloudFormationTransaction) PutLoadBalancer(v LoadBalancerRecord) error {
	id := value(v.Data.LoadBalancerArn)
	old, e := t.Transaction.LoadBalancer(v.Scope, id)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	v.Ownership, e = t.admit("LoadBalancer", id, old.Ownership, e == nil)
	if e != nil {
		return e
	}
	return t.Transaction.PutLoadBalancer(v)
}
func (t *cloudFormationTransaction) DeleteLoadBalancer(sc Scope, id string) error {
	if _, e := t.LoadBalancer(sc, id); e != nil {
		return e
	}
	return t.Transaction.DeleteLoadBalancer(sc, id)
}
func (t *cloudFormationTransaction) TargetGroup(sc Scope, id string) (TargetGroupRecord, error) {
	v, e := t.Transaction.TargetGroup(sc, id)
	if e == nil {
		e = t.observe("TargetGroup", id, v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) TargetGroups(sc Scope) ([]TargetGroupRecord, error) {
	rows, e := t.Transaction.TargetGroups(sc)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("TargetGroup", value(v.Data.TargetGroupArn), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cloudFormationTransaction) PutTargetGroup(v TargetGroupRecord) error {
	id := value(v.Data.TargetGroupArn)
	old, e := t.Transaction.TargetGroup(v.Scope, id)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	v.Ownership, e = t.admit("TargetGroup", id, old.Ownership, e == nil)
	if e != nil {
		return e
	}
	return t.Transaction.PutTargetGroup(v)
}
func (t *cloudFormationTransaction) DeleteTargetGroup(sc Scope, id string) error {
	if _, e := t.TargetGroup(sc, id); e != nil {
		return e
	}
	return t.Transaction.DeleteTargetGroup(sc, id)
}
func (t *cloudFormationTransaction) Listener(sc Scope, id string) (ListenerRecord, error) {
	v, e := t.Transaction.Listener(sc, id)
	if e == nil {
		e = t.observe("Listener", id, v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) Listeners(sc Scope) ([]ListenerRecord, error) {
	rows, e := t.Transaction.Listeners(sc)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("Listener", value(v.Data.ListenerArn), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cloudFormationTransaction) PutListener(v ListenerRecord) error {
	id := value(v.Data.ListenerArn)
	old, e := t.Transaction.Listener(v.Scope, id)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	v.Ownership, e = t.admit("Listener", id, old.Ownership, e == nil)
	if e != nil {
		return e
	}
	return t.Transaction.PutListener(v)
}
func (t *cloudFormationTransaction) DeleteListener(sc Scope, id string) error {
	if _, e := t.Listener(sc, id); e != nil {
		return e
	}
	return t.Transaction.DeleteListener(sc, id)
}
func (t *cloudFormationTransaction) Rule(sc Scope, id string) (RuleRecord, error) {
	v, e := t.Transaction.Rule(sc, id)
	if e == nil {
		e = t.observe("Rule", id, v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) Rules(sc Scope) ([]RuleRecord, error) {
	rows, e := t.Transaction.Rules(sc)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("Rule", value(v.Data.RuleArn), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cloudFormationTransaction) PutRule(v RuleRecord) error {
	id := value(v.Data.RuleArn)
	old, e := t.Transaction.Rule(v.Scope, id)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	v.Ownership, e = t.admit("Rule", id, old.Ownership, e == nil)
	if e != nil {
		return e
	}
	return t.Transaction.PutRule(v)
}
func (t *cloudFormationTransaction) DeleteRule(sc Scope, id string) error {
	if _, e := t.Rule(sc, id); e != nil {
		return e
	}
	return t.Transaction.DeleteRule(sc, id)
}
