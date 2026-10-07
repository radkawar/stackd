package applicationautoscaling

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

// WithCloudFormationOwnership carries a private incarnation claim, never public tags.
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
		return failure("ValidationException", "Resource belongs to another CloudFormation incarnation")
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
		return "", failure("ValidationException", "Resource belongs to another CloudFormation incarnation")
	}
	if !exists && t.owner.Enforce {
		return "", failure("ObjectNotFoundException", "CloudFormation incarnation no longer exists")
	}
	if t.owner.Rows != nil {
		t.owner.Rows[id] = t.owner.Claim
	}
	return t.owner.Claim, nil
}
func targetOwnerID(k TargetKey) string { return k.ResourceID + "|" + k.Dimension + "|" + k.Namespace }
func (t *cloudFormationTransaction) Target(k TargetKey) (TargetRecord, error) {
	v, e := t.Transaction.Target(k)
	if e == nil {
		e = t.observe("ScalableTarget", targetOwnerID(k), v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) TargetByARN(sc Scope, id string) (TargetRecord, error) {
	v, e := t.Transaction.TargetByARN(sc, id)
	if e == nil {
		e = t.observe("ScalableTarget", targetOwnerID(v.Key), v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) Targets(k TargetQuery) ([]TargetRecord, error) {
	rows, e := t.Transaction.Targets(k)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("ScalableTarget", targetOwnerID(v.Key), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cloudFormationTransaction) PutTarget(v TargetRecord) error {
	old, e := t.Transaction.Target(v.Key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	v.Ownership, e = t.admit("ScalableTarget", targetOwnerID(v.Key), old.Ownership, e == nil)
	if e != nil {
		return e
	}
	return t.Transaction.PutTarget(v)
}
func (t *cloudFormationTransaction) DeleteTarget(k TargetKey) error {
	if _, e := t.Target(k); e != nil {
		return e
	}
	return t.Transaction.DeleteTarget(k)
}
func policyOwnerID(v PolicyRecord) string { return value(v.Data.PolicyARN) + "|" + v.Key.Dimension }
func (t *cloudFormationTransaction) Policy(k PolicyKey) (PolicyRecord, error) {
	v, e := t.Transaction.Policy(k)
	if e == nil {
		e = t.observe("ScalingPolicy", policyOwnerID(v), v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) Policies(k PolicyQuery) ([]PolicyRecord, error) {
	rows, e := t.Transaction.Policies(k)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("ScalingPolicy", policyOwnerID(v), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cloudFormationTransaction) PutPolicy(v PolicyRecord) error {
	old, e := t.Transaction.Policy(v.Key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	v.Ownership, e = t.admit("ScalingPolicy", policyOwnerID(v), old.Ownership, e == nil)
	if e != nil {
		return e
	}
	return t.Transaction.PutPolicy(v)
}
func (t *cloudFormationTransaction) DeletePolicy(k PolicyKey) error {
	if _, e := t.Policy(k); e != nil {
		return e
	}
	return t.Transaction.DeletePolicy(k)
}
