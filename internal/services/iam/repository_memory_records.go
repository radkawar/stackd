package iam

import (
	"slices"
	"strings"
)

func (t *memoryTx) User(scope Scope, name string) (User, error) {
	if err := t.check(false); err != nil {
		return User{}, err
	}
	record, ok := t.state.users[scope][strings.ToLower(name)]
	if !ok {
		return User{}, ErrRecordNotFound
	}
	return cloneUser(record), nil
}
func (t *memoryTx) Users(scope Scope) ([]User, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	result := make([]User, 0, len(t.state.users[scope]))
	for _, record := range t.state.users[scope] {
		result = append(result, cloneUser(record))
	}
	slices.SortFunc(result, func(a, b User) int { return strings.Compare(a.UserName, b.UserName) })
	return result, nil
}
func (t *memoryTx) PutUser(scope Scope, record User) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.users[scope] == nil {
		t.state.users[scope] = make(map[string]User)
	}
	t.state.users[scope][strings.ToLower(record.UserName)] = cloneUser(record)
	return nil
}
func (t *memoryTx) DeleteUser(scope Scope, name string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, ok := t.state.users[scope][strings.ToLower(name)]; !ok {
		return ErrRecordNotFound
	}
	delete(t.state.users[scope], strings.ToLower(name))
	return nil
}
func (t *memoryTx) Group(scope Scope, name string) (Group, error) {
	if err := t.check(false); err != nil {
		return Group{}, err
	}
	record, ok := t.state.groups[scope][strings.ToLower(name)]
	if !ok {
		return Group{}, ErrRecordNotFound
	}
	return cloneGroup(record), nil
}
func (t *memoryTx) Groups(scope Scope) ([]Group, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	result := make([]Group, 0, len(t.state.groups[scope]))
	for _, record := range t.state.groups[scope] {
		result = append(result, cloneGroup(record))
	}
	slices.SortFunc(result, func(a, b Group) int { return strings.Compare(a.GroupName, b.GroupName) })
	return result, nil
}
func (t *memoryTx) PutGroup(scope Scope, record Group) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.groups[scope] == nil {
		t.state.groups[scope] = make(map[string]Group)
	}
	t.state.groups[scope][strings.ToLower(record.GroupName)] = cloneGroup(record)
	return nil
}
func (t *memoryTx) DeleteGroup(scope Scope, name string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, ok := t.state.groups[scope][strings.ToLower(name)]; !ok {
		return ErrRecordNotFound
	}
	delete(t.state.groups[scope], strings.ToLower(name))
	return nil
}
func (t *memoryTx) Role(scope Scope, name string) (Role, error) {
	if err := t.check(false); err != nil {
		return Role{}, err
	}
	record, ok := t.state.roles[scope][strings.ToLower(name)]
	if !ok {
		return Role{}, ErrRecordNotFound
	}
	return cloneRole(record), nil
}
func (t *memoryTx) Roles(scope Scope) ([]Role, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	result := make([]Role, 0, len(t.state.roles[scope]))
	for _, record := range t.state.roles[scope] {
		result = append(result, cloneRole(record))
	}
	slices.SortFunc(result, func(a, b Role) int { return strings.Compare(a.RoleName, b.RoleName) })
	return result, nil
}
func (t *memoryTx) PutRole(scope Scope, record Role) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.roles[scope] == nil {
		t.state.roles[scope] = make(map[string]Role)
	}
	t.state.roles[scope][strings.ToLower(record.RoleName)] = cloneRole(record)
	return nil
}
func (t *memoryTx) DeleteRole(scope Scope, name string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, ok := t.state.roles[scope][strings.ToLower(name)]; !ok {
		return ErrRecordNotFound
	}
	delete(t.state.roles[scope], strings.ToLower(name))
	return nil
}
func (t *memoryTx) ManagedPolicy(scope Scope, name string) (ManagedPolicy, error) {
	if err := t.check(false); err != nil {
		return ManagedPolicy{}, err
	}
	record, ok := t.state.policies[scope][name]
	if !ok {
		return ManagedPolicy{}, ErrRecordNotFound
	}
	return clonePolicy(record), nil
}
func (t *memoryTx) ManagedPolicies(scope Scope) ([]ManagedPolicy, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	result := make([]ManagedPolicy, 0, len(t.state.policies[scope]))
	for _, record := range t.state.policies[scope] {
		result = append(result, clonePolicy(record))
	}
	slices.SortFunc(result, func(a, b ManagedPolicy) int { return strings.Compare(a.Arn, b.Arn) })
	return result, nil
}
func (t *memoryTx) PutManagedPolicy(scope Scope, record ManagedPolicy) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.policies[scope] == nil {
		t.state.policies[scope] = make(map[string]ManagedPolicy)
	}
	t.state.policies[scope][record.Arn] = clonePolicy(record)
	return nil
}
func (t *memoryTx) DeleteManagedPolicy(scope Scope, name string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, ok := t.state.policies[scope][name]; !ok {
		return ErrRecordNotFound
	}
	delete(t.state.policies[scope], name)
	return nil
}
