package autoscaling

import (
	"context"
	"errors"
	"strings"
)

type cloudFormationOwnershipKey struct{}
type cloudFormationOwnership struct {
	Kind, Claim, Target string
	Enforce             bool
	Rows                map[string]string
	InlineDirect        bool
}

// WithCloudFormationOwnership binds private native-row incarnation metadata.
func WithCloudFormationOwnership(ctx context.Context, kind, claim, target string, enforce bool, rows map[string]string) context.Context {
	return context.WithValue(ctx, cloudFormationOwnershipKey{}, &cloudFormationOwnership{Kind: kind, Claim: claim, Target: target, Enforce: enforce, Rows: rows})
}

// WithInlineLifecycleHookOwnership fences inline mutation against standalone hooks.
func WithInlineLifecycleHookOwnership(ctx context.Context, claim string, direct bool) context.Context {
	return context.WithValue(ctx, cloudFormationOwnershipKey{}, &cloudFormationOwnership{Kind: "InlineLifecycleHook", Claim: claim, InlineDirect: direct})
}
func (t *cloudFormationTransaction) inlineHookOwned(claim string) error {
	if t.owner.Kind != "AutoScalingGroup" && t.owner.Kind != "InlineLifecycleHook" {
		return nil
	}
	if t.owner.InlineDirect {
		if !strings.HasPrefix(claim, "AWS::AutoScaling::LifecycleHook/") {
			return nil
		}
	} else if claim == t.owner.Claim {
		return nil
	}
	return failure("AlreadyExists", "Lifecycle hook is not owned inline by this group incarnation")
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
	if t.owner.Kind == "InlineLifecycleHook" && kind == "AutoScalingGroup" && !t.owner.InlineDirect && claim != t.owner.Claim {
		return failure("AlreadyExists", "Inline lifecycle hook group incarnation no longer exists")
	}
	if t.owner.Kind != kind {
		return nil
	}
	if t.owner.Rows != nil {
		t.owner.Rows[id] = claim
	}
	if t.owner.Enforce && (t.owner.Target == "" || t.owner.Target == id) && claim != t.owner.Claim {
		return failure("AlreadyExists", "Resource belongs to another CloudFormation incarnation")
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
		return "", failure("AlreadyExists", "Resource belongs to another CloudFormation incarnation")
	}
	if !exists && t.owner.Enforce {
		return "", failure("AlreadyExists", "CloudFormation incarnation no longer exists")
	}
	if t.owner.Rows != nil {
		t.owner.Rows[id] = t.owner.Claim
	}
	return t.owner.Claim, nil
}
func (t *cloudFormationTransaction) Group(k GroupKey) (GroupRecord, error) {
	v, e := t.Transaction.Group(k)
	if e == nil {
		e = t.observe("AutoScalingGroup", k.Name, v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) Groups(q GroupQuery) ([]GroupRecord, error) {
	rows, e := t.Transaction.Groups(q)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("AutoScalingGroup", v.Key.Name, v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cloudFormationTransaction) PutGroup(v GroupRecord) error {
	old, e := t.Transaction.Group(v.Key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	v.Ownership, e = t.admit("AutoScalingGroup", v.Key.Name, old.Ownership, e == nil)
	if e != nil {
		return e
	}
	return t.Transaction.PutGroup(v)
}
func (t *cloudFormationTransaction) DeleteGroup(k GroupKey) error {
	if _, e := t.Group(k); e != nil {
		return e
	}
	return t.Transaction.DeleteGroup(k)
}
func (t *cloudFormationTransaction) Hook(k HookKey) (HookRecord, error) {
	v, e := t.Transaction.Hook(k)
	if e == nil {
		if e = t.inlineHookOwned(v.Ownership); e != nil {
			return v, e
		}
	}
	if e == nil {
		e = t.observe("LifecycleHook", v.Key.GroupKey.Name+"|"+v.Key.Name, v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) Hooks(k GroupKey) ([]HookRecord, error) {
	rows, e := t.Transaction.Hooks(k)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("LifecycleHook", v.Key.GroupKey.Name+"|"+v.Key.Name, v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cloudFormationTransaction) PutHook(v HookRecord) error {
	old, e := t.Transaction.Hook(v.Key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	if t.owner.Kind == "AutoScalingGroup" || t.owner.Kind == "InlineLifecycleHook" {
		if e == nil {
			if e = t.inlineHookOwned(old.Ownership); e != nil {
				return e
			}
			v.Ownership = old.Ownership
		} else {
			v.Ownership = t.owner.Claim
		}
		return t.Transaction.PutHook(v)
	}
	v.Ownership, e = t.admit("LifecycleHook", v.Key.GroupKey.Name+"|"+v.Key.Name, old.Ownership, e == nil)
	if e != nil {
		return e
	}
	return t.Transaction.PutHook(v)
}
func (t *cloudFormationTransaction) DeleteHook(k HookKey) error {
	if _, e := t.Hook(k); e != nil {
		return e
	}
	return t.Transaction.DeleteHook(k)
}
func (t *cloudFormationTransaction) Policy(k PolicyKey) (PolicyRecord, error) {
	v, e := t.Transaction.Policy(k)
	if e == nil {
		e = t.observe("ScalingPolicy", value(v.Data.PolicyARN), v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) Policies(k GroupKey) ([]PolicyRecord, error) {
	rows, e := t.Transaction.Policies(k)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("ScalingPolicy", value(v.Data.PolicyARN), v.Ownership); e != nil {
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
	v.Ownership, e = t.admit("ScalingPolicy", value(v.Data.PolicyARN), old.Ownership, e == nil)
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
func (t *cloudFormationTransaction) Schedule(k ScheduleKey) (ScheduleRecord, error) {
	v, e := t.Transaction.Schedule(k)
	if e == nil {
		e = t.observe("ScheduledAction", v.Key.GroupKey.Name+"|"+v.Key.Name, v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) Schedules(k GroupKey) ([]ScheduleRecord, error) {
	rows, e := t.Transaction.Schedules(k)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("ScheduledAction", v.Key.GroupKey.Name+"|"+v.Key.Name, v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cloudFormationTransaction) PutSchedule(v ScheduleRecord) error {
	old, e := t.Transaction.Schedule(v.Key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	v.Ownership, e = t.admit("ScheduledAction", v.Key.GroupKey.Name+"|"+v.Key.Name, old.Ownership, e == nil)
	if e != nil {
		return e
	}
	return t.Transaction.PutSchedule(v)
}
func (t *cloudFormationTransaction) DeleteSchedule(k ScheduleKey) error {
	if _, e := t.Schedule(k); e != nil {
		return e
	}
	return t.Transaction.DeleteSchedule(k)
}
