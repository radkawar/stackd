package elasticache

import (
	"context"
	"errors"
	"slices"
	"strings"
)

type cloudFormationParameterReplacementKey struct{}

// WithCloudFormationParameterReplacement selects complete desired parameters in
// the existing ModifyCacheParameterGroup transaction. Ordinary AWS modifications
// retain their documented patch semantics. A single native rollout prevents an
// intermediate reset from making the second owner command invalid.
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
		name = name[strings.LastIndex(name, ":")+1:]
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
func (t cloudFormationTransaction) admit(k Key, claim string, exists bool) (string, error) {
	switch {
	case exists && claim == t.owner.Claim:
		return claim, nil
	case exists && t.owner.Creating:
		return "", existsError(k.Kind)
	case !exists && t.owner.Creating:
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
	exists, e := rowExists(e)
	if e != nil {
		return e
	}
	if v.CloudFormationOwner, e = t.admit(v.Key, old.CloudFormationOwner, exists); e != nil {
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
	exists, e := rowExists(e)
	if e != nil {
		return e
	}
	if v.CloudFormationOwner, e = t.admit(v.Key, old.CloudFormationOwner, exists); e != nil {
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
func (t cloudFormationTransaction) UserGroup(k Key) (UserGroup, error) {
	v, e := t.Transaction.UserGroup(k)
	if e == nil && t.hidden(k, v.CloudFormationOwner) {
		return UserGroup{}, ErrNotFound
	}
	return v, e
}
func (t cloudFormationTransaction) UserGroups(sc Scope) ([]UserGroup, error) {
	rows, e := t.Transaction.UserGroups(sc)
	return slices.DeleteFunc(rows, func(v UserGroup) bool { return t.hidden(v.Key, v.CloudFormationOwner) }), e
}
func (t cloudFormationTransaction) PutUserGroup(v UserGroup) error {
	if !t.target(v.Key) {
		return t.Transaction.PutUserGroup(v)
	}
	old, e := t.Transaction.UserGroup(v.Key)
	exists, e := rowExists(e)
	if e != nil {
		return e
	}
	if v.CloudFormationOwner, e = t.admit(v.Key, old.CloudFormationOwner, exists); e != nil {
		return e
	}
	return t.Transaction.PutUserGroup(v)
}
func (t cloudFormationTransaction) DeleteUserGroup(k Key) error {
	if t.target(k) {
		if _, e := t.UserGroup(k); e != nil {
			return e
		}
	}
	return t.Transaction.DeleteUserGroup(k)
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
	exists, e := rowExists(e)
	if e != nil {
		return e
	}
	if v.CloudFormationOwner, e = t.admit(v.Key, old.CloudFormationOwner, exists); e != nil {
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
	exists, e := rowExists(e)
	if e != nil {
		return e
	}
	if v.CloudFormationOwner, e = t.admit(v.Key, old.CloudFormationOwner, exists); e != nil {
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
