package iam

import (
	"slices"
	"strings"
)

func (t *memoryTx) ServiceLinkedRoleDeletion(scope Scope, id string) (ServiceLinkedRoleDeletion, error) {
	if err := t.check(false); err != nil {
		return ServiceLinkedRoleDeletion{}, err
	}
	record, ok := t.state.serviceLinkedDeletions[scope][id]
	if !ok {
		return ServiceLinkedRoleDeletion{}, ErrRecordNotFound
	}
	return cloneServiceLinkedRoleDeletion(record), nil
}

func (t *memoryTx) ServiceLinkedRoleDeletions(scope Scope) ([]ServiceLinkedRoleDeletion, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	result := make([]ServiceLinkedRoleDeletion, 0, len(t.state.serviceLinkedDeletions[scope]))
	for _, record := range t.state.serviceLinkedDeletions[scope] {
		result = append(result, cloneServiceLinkedRoleDeletion(record))
	}
	slices.SortFunc(result, func(a, b ServiceLinkedRoleDeletion) int { return strings.Compare(a.ID, b.ID) })
	return result, nil
}

func (t *memoryTx) ServiceLinkedRoleDeletionScopes() ([]Scope, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	result := make([]Scope, 0, len(t.state.serviceLinkedDeletions))
	for scope := range t.state.serviceLinkedDeletions {
		result = append(result, scope)
	}
	slices.SortFunc(result, func(a, b Scope) int {
		if c := strings.Compare(a.Partition, b.Partition); c != 0 {
			return c
		}
		return strings.Compare(a.AccountID, b.AccountID)
	})
	return result, nil
}

func (t *memoryTx) PutServiceLinkedRoleDeletion(scope Scope, record ServiceLinkedRoleDeletion) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.serviceLinkedDeletions[scope] == nil {
		t.state.serviceLinkedDeletions[scope] = make(map[string]ServiceLinkedRoleDeletion)
	}
	t.state.serviceLinkedDeletions[scope][record.ID] = cloneServiceLinkedRoleDeletion(record)
	return nil
}

func cloneServiceLinkedRoleDeletion(record ServiceLinkedRoleDeletion) ServiceLinkedRoleDeletion {
	record.Usage = cloneServiceLinkedUsage(record.Usage)
	return record
}

func cloneServiceLinkedUsage(usage []ServiceLinkedRoleUsage) []ServiceLinkedRoleUsage {
	result := slices.Clone(usage)
	for i := range result {
		result[i].ResourceARNs = slices.Clone(result[i].ResourceARNs)
	}
	return result
}
