package ecs

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
		return failure("InvalidParameterException", "Resource belongs to another CloudFormation incarnation")
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
		return "", failure("InvalidParameterException", "Resource belongs to another CloudFormation incarnation")
	}
	if !exists && t.owner.Enforce {
		return "", failure("InvalidParameterException", "CloudFormation incarnation no longer exists")
	}
	if t.owner.Rows != nil {
		t.owner.Rows[id] = t.owner.Claim
	}
	return t.owner.Claim, nil
}
func (t *cloudFormationTransaction) Cluster(k ClusterKey) (ClusterRecord, error) {
	v, e := t.Transaction.Cluster(k)
	if e == nil {
		e = t.observe("Cluster", k.ARN(), v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) Clusters(q ClusterQuery) ([]ClusterRecord, error) {
	rows, e := t.Transaction.Clusters(q)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("Cluster", v.Key.ARN(), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cloudFormationTransaction) PutCluster(v ClusterRecord) error {
	old, e := t.Transaction.Cluster(v.Key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	v.Ownership, e = t.admit("Cluster", v.Key.ARN(), old.Ownership, e == nil && value(old.Data.Status) != "INACTIVE")
	if e != nil {
		return e
	}
	return t.Transaction.PutCluster(v)
}
func (t *cloudFormationTransaction) TaskDefinition(k TaskDefinitionKey) (TaskDefinitionRecord, error) {
	v, e := t.Transaction.TaskDefinition(k)
	if e == nil {
		e = t.observe("TaskDefinition", k.ARN(), v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) TaskDefinitions(q TaskDefinitionQuery) ([]TaskDefinitionRecord, error) {
	rows, e := t.Transaction.TaskDefinitions(q)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("TaskDefinition", v.Key.ARN(), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cloudFormationTransaction) PutTaskDefinition(v TaskDefinitionRecord) error {
	old, e := t.Transaction.TaskDefinition(v.Key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	v.Ownership, e = t.admit("TaskDefinition", v.Key.ARN(), old.Ownership, e == nil)
	if e != nil {
		return e
	}
	return t.Transaction.PutTaskDefinition(v)
}
func (t *cloudFormationTransaction) Service(k ServiceKey) (ServiceRecord, error) {
	v, e := t.Transaction.Service(k)
	if e == nil {
		e = t.observe("Service", k.ARN(), v.Ownership)
	}
	return v, e
}
func (t *cloudFormationTransaction) Services(q ServiceQuery) ([]ServiceRecord, error) {
	rows, e := t.Transaction.Services(q)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("Service", v.Key.ARN(), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cloudFormationTransaction) PutService(v ServiceRecord) error {
	old, e := t.Transaction.Service(v.Key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	v.Ownership, e = t.admit("Service", v.Key.ARN(), old.Ownership, e == nil && value(old.Data.Status) != "INACTIVE")
	if e != nil {
		return e
	}
	return t.Transaction.PutService(v)
}
func (t *cloudFormationTransaction) DeleteTaskDefinition(k TaskDefinitionKey) error {
	if _, e := t.TaskDefinition(k); e != nil {
		return e
	}
	return t.Transaction.DeleteTaskDefinition(k)
}
