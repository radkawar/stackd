package memorydb

import (
	"context"
	"errors"
	"slices"
	"strings"
)

type cloudFormationParameterReplacementKey struct{}

// WithCloudFormationParameterReplacement applies a complete desired parameter
// set atomically under the existing UpdateParameterGroup owner authorization.
// The native lifecycle observes only the final configuration, including resets.
func WithCloudFormationParameterReplacement(ctx context.Context) context.Context {
	return context.WithValue(ctx, cloudFormationParameterReplacementKey{}, true)
}

type cloudFormationOwnerKey struct{}
type cloudFormationOwner struct {
	Kind, Name, Claim string
	Creating          bool
}

// WithCloudFormationOwner binds one private CloudFormation incarnation claim to
// the single native row a command targets. Creating stamps the claim onto a
// newly admitted row only. Otherwise the target exists for this command only
// when its persisted claim is exactly this incarnation; another incarnation's
// same-name row is absent. Public tags never carry or prove this authority.
func WithCloudFormationOwner(ctx context.Context, kind, name, claim string, creating bool) context.Context {
	if strings.HasPrefix(name, "arn:") {
		name = name[strings.LastIndex(name, "/")+1:]
	}
	return context.WithValue(ctx, cloudFormationOwnerKey{}, cloudFormationOwner{kind, strings.ToLower(name), claim, creating})
}

// cloudFormationTransaction fences the owner's ordinary command transaction, so
// the claim check and the native row effect commit atomically.
type cloudFormationTransaction struct {
	Transaction
	owner cloudFormationOwner
}

func bindCloudFormationOwner(tx Transaction) Transaction {
	owner, ok := tx.Context().Value(cloudFormationOwnerKey{}).(cloudFormationOwner)
	if !ok || owner.Claim == "" {
		return tx
	}
	return cloudFormationTransaction{tx, owner}
}
func (t cloudFormationTransaction) target(k Key) bool {
	return k.Kind == t.owner.Kind && k.Name == t.owner.Name
}
func (t cloudFormationTransaction) hidden(k Key, claim string) bool {
	return !t.owner.Creating && t.target(k) && claim != t.owner.Claim
}

// admit returns the immutable claim for a target write. Only a create command
// may stamp a new row; an existing row keeps its exact incarnation.
func (t cloudFormationTransaction) admit(k Key, claim string, present bool) (string, error) {
	switch {
	case present && claim == t.owner.Claim:
		return claim, nil
	case present && t.owner.Creating:
		return "", exists(k.Kind)
	case !present && t.owner.Creating:
		return t.owner.Claim, nil
	}
	return "", notFound(k.Kind)
}
func rowExists(e error) (bool, error) {
	if errors.Is(e, ErrNotFound) {
		return false, nil
	}
	return e == nil, e
}

func (t cloudFormationTransaction) Cluster(k Key) (Cluster, error) {
	v, e := t.Transaction.Cluster(k)
	if e == nil && t.hidden(k, v.CloudFormationOwner) {
		return Cluster{}, ErrNotFound
	}
	return v, e
}
func (t cloudFormationTransaction) Clusters(sc Scope) ([]Cluster, error) {
	rows, e := t.Transaction.Clusters(sc)
	return slices.DeleteFunc(rows, func(v Cluster) bool { return t.hidden(v.Key, v.CloudFormationOwner) }), e
}
func (t cloudFormationTransaction) PutCluster(v Cluster) error {
	if !t.target(v.Key) {
		return t.Transaction.PutCluster(v)
	}
	old, e := t.Transaction.Cluster(v.Key)
	present, e := rowExists(e)
	if e != nil {
		return e
	}
	if v.CloudFormationOwner, e = t.admit(v.Key, old.CloudFormationOwner, present); e != nil {
		return e
	}
	return t.Transaction.PutCluster(v)
}
func (t cloudFormationTransaction) DeleteCluster(k Key) error {
	if t.target(k) {
		if _, e := t.Cluster(k); e != nil {
			return e
		}
	}
	return t.Transaction.DeleteCluster(k)
}
func (t cloudFormationTransaction) User(k Key) (User, error) {
	v, e := t.Transaction.User(k)
	if e == nil && t.hidden(k, v.CloudFormationOwner) {
		return User{}, ErrNotFound
	}
	return v, e
}
func (t cloudFormationTransaction) Users(sc Scope) ([]User, error) {
	rows, e := t.Transaction.Users(sc)
	return slices.DeleteFunc(rows, func(v User) bool { return t.hidden(v.Key, v.CloudFormationOwner) }), e
}
func (t cloudFormationTransaction) PutUser(v User) error {
	if !t.target(v.Key) {
		return t.Transaction.PutUser(v)
	}
	old, e := t.Transaction.User(v.Key)
	present, e := rowExists(e)
	if e != nil {
		return e
	}
	if v.CloudFormationOwner, e = t.admit(v.Key, old.CloudFormationOwner, present); e != nil {
		return e
	}
	return t.Transaction.PutUser(v)
}
func (t cloudFormationTransaction) DeleteUser(k Key) error {
	if t.target(k) {
		if _, e := t.User(k); e != nil {
			return e
		}
	}
	return t.Transaction.DeleteUser(k)
}
func (t cloudFormationTransaction) ACL(k Key) (ACL, error) {
	v, e := t.Transaction.ACL(k)
	if e == nil && t.hidden(k, v.CloudFormationOwner) {
		return ACL{}, ErrNotFound
	}
	return v, e
}
func (t cloudFormationTransaction) ACLs(sc Scope) ([]ACL, error) {
	rows, e := t.Transaction.ACLs(sc)
	return slices.DeleteFunc(rows, func(v ACL) bool { return t.hidden(v.Key, v.CloudFormationOwner) }), e
}
func (t cloudFormationTransaction) PutACL(v ACL) error {
	if !t.target(v.Key) {
		return t.Transaction.PutACL(v)
	}
	old, e := t.Transaction.ACL(v.Key)
	present, e := rowExists(e)
	if e != nil {
		return e
	}
	if v.CloudFormationOwner, e = t.admit(v.Key, old.CloudFormationOwner, present); e != nil {
		return e
	}
	return t.Transaction.PutACL(v)
}
func (t cloudFormationTransaction) DeleteACL(k Key) error {
	if t.target(k) {
		if _, e := t.ACL(k); e != nil {
			return e
		}
	}
	return t.Transaction.DeleteACL(k)
}
func (t cloudFormationTransaction) ParameterGroup(k Key) (ParameterGroup, error) {
	v, e := t.Transaction.ParameterGroup(k)
	if e == nil && t.hidden(k, v.CloudFormationOwner) {
		return ParameterGroup{}, ErrNotFound
	}
	return v, e
}
func (t cloudFormationTransaction) ParameterGroups(sc Scope) ([]ParameterGroup, error) {
	rows, e := t.Transaction.ParameterGroups(sc)
	return slices.DeleteFunc(rows, func(v ParameterGroup) bool { return t.hidden(v.Key, v.CloudFormationOwner) }), e
}
func (t cloudFormationTransaction) PutParameterGroup(v ParameterGroup) error {
	if !t.target(v.Key) {
		return t.Transaction.PutParameterGroup(v)
	}
	old, e := t.Transaction.ParameterGroup(v.Key)
	present, e := rowExists(e)
	if e != nil {
		return e
	}
	if v.CloudFormationOwner, e = t.admit(v.Key, old.CloudFormationOwner, present); e != nil {
		return e
	}
	return t.Transaction.PutParameterGroup(v)
}
func (t cloudFormationTransaction) DeleteParameterGroup(k Key) error {
	if t.target(k) {
		if _, e := t.ParameterGroup(k); e != nil {
			return e
		}
	}
	return t.Transaction.DeleteParameterGroup(k)
}
func (t cloudFormationTransaction) SubnetGroup(k Key) (SubnetGroup, error) {
	v, e := t.Transaction.SubnetGroup(k)
	if e == nil && t.hidden(k, v.CloudFormationOwner) {
		return SubnetGroup{}, ErrNotFound
	}
	return v, e
}
func (t cloudFormationTransaction) SubnetGroups(sc Scope) ([]SubnetGroup, error) {
	rows, e := t.Transaction.SubnetGroups(sc)
	return slices.DeleteFunc(rows, func(v SubnetGroup) bool { return t.hidden(v.Key, v.CloudFormationOwner) }), e
}
func (t cloudFormationTransaction) PutSubnetGroup(v SubnetGroup) error {
	if !t.target(v.Key) {
		return t.Transaction.PutSubnetGroup(v)
	}
	old, e := t.Transaction.SubnetGroup(v.Key)
	present, e := rowExists(e)
	if e != nil {
		return e
	}
	if v.CloudFormationOwner, e = t.admit(v.Key, old.CloudFormationOwner, present); e != nil {
		return e
	}
	return t.Transaction.PutSubnetGroup(v)
}
func (t cloudFormationTransaction) DeleteSubnetGroup(k Key) error {
	if t.target(k) {
		if _, e := t.SubnetGroup(k); e != nil {
			return e
		}
	}
	return t.Transaction.DeleteSubnetGroup(k)
}
func (t cloudFormationTransaction) Snapshot(k Key) (Snapshot, error) {
	v, e := t.Transaction.Snapshot(k)
	if e == nil && t.hidden(k, v.CloudFormationOwner) {
		return Snapshot{}, ErrNotFound
	}
	return v, e
}
func (t cloudFormationTransaction) Snapshots(sc Scope) ([]Snapshot, error) {
	rows, e := t.Transaction.Snapshots(sc)
	return slices.DeleteFunc(rows, func(v Snapshot) bool { return t.hidden(v.Key, v.CloudFormationOwner) }), e
}
func (t cloudFormationTransaction) PutSnapshot(v Snapshot) error {
	if !t.target(v.Key) {
		return t.Transaction.PutSnapshot(v)
	}
	old, e := t.Transaction.Snapshot(v.Key)
	present, e := rowExists(e)
	if e != nil {
		return e
	}
	if v.CloudFormationOwner, e = t.admit(v.Key, old.CloudFormationOwner, present); e != nil {
		return e
	}
	return t.Transaction.PutSnapshot(v)
}
func (t cloudFormationTransaction) DeleteSnapshot(k Key) error {
	if t.target(k) {
		if _, e := t.Snapshot(k); e != nil {
			return e
		}
	}
	return t.Transaction.DeleteSnapshot(k)
}
