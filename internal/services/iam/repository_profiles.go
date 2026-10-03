package iam

import (
	"slices"
	"strings"
)

func (t *memoryTx) InstanceProfile(scope Scope, name string) (InstanceProfile, error) {
	if err := t.check(false); err != nil {
		return InstanceProfile{}, err
	}
	record, ok := t.state.instanceProfiles[scope][strings.ToLower(name)]
	if !ok {
		return InstanceProfile{}, ErrRecordNotFound
	}
	return cloneInstanceProfile(record), nil
}

func (t *memoryTx) InstanceProfiles(scope Scope) ([]InstanceProfile, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	result := make([]InstanceProfile, 0, len(t.state.instanceProfiles[scope]))
	for _, record := range t.state.instanceProfiles[scope] {
		result = append(result, cloneInstanceProfile(record))
	}
	slices.SortFunc(result, func(a, b InstanceProfile) int { return strings.Compare(a.InstanceProfileName, b.InstanceProfileName) })
	return result, nil
}

func (t *memoryTx) PutInstanceProfile(scope Scope, record InstanceProfile) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.instanceProfiles[scope] == nil {
		t.state.instanceProfiles[scope] = make(map[string]InstanceProfile)
	}
	t.state.instanceProfiles[scope][strings.ToLower(record.InstanceProfileName)] = cloneInstanceProfile(record)
	return nil
}

func (t *memoryTx) DeleteInstanceProfile(scope Scope, name string) error {
	if err := t.check(true); err != nil {
		return err
	}
	key := strings.ToLower(name)
	if _, ok := t.state.instanceProfiles[scope][key]; !ok {
		return ErrRecordNotFound
	}
	delete(t.state.instanceProfiles[scope], key)
	return nil
}

func cloneInstanceProfile(p InstanceProfile) InstanceProfile {
	p.Tags = slices.Clone(p.Tags)
	return p
}
