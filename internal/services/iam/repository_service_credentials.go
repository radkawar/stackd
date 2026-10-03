package iam

import (
	"slices"
	"strings"
)

func (t *memoryTx) ServiceCredential(scope Scope, id string) (ServiceCredentialRecord, error) {
	if err := t.check(false); err != nil {
		return ServiceCredentialRecord{}, err
	}
	record, ok := t.state.serviceCredentials[scope][id]
	if !ok {
		return ServiceCredentialRecord{}, ErrRecordNotFound
	}
	return cloneServiceCredential(record), nil
}

func (t *memoryTx) ServiceCredentials(scope Scope) ([]ServiceCredentialRecord, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	records := make([]ServiceCredentialRecord, 0, len(t.state.serviceCredentials[scope]))
	for _, record := range t.state.serviceCredentials[scope] {
		records = append(records, cloneServiceCredential(record))
	}
	slices.SortFunc(records, func(a, b ServiceCredentialRecord) int { return strings.Compare(a.ID, b.ID) })
	return records, nil
}

func (t *memoryTx) PutServiceCredential(scope Scope, record ServiceCredentialRecord) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.serviceCredentials[scope] == nil {
		t.state.serviceCredentials[scope] = make(map[string]ServiceCredentialRecord)
	}
	t.state.serviceCredentials[scope][record.ID] = cloneServiceCredential(record)
	return nil
}

func (t *memoryTx) DeleteServiceCredential(scope Scope, id string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, exists := t.state.serviceCredentials[scope][id]; !exists {
		return ErrRecordNotFound
	}
	delete(t.state.serviceCredentials[scope], id)
	return nil
}
