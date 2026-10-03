package iam

import (
	"cmp"
	"slices"
)

func (t *memoryTx) AccountMetadata(scope Scope) (AccountMetadata, error) {
	if err := t.check(false); err != nil {
		return AccountMetadata{}, err
	}
	metadata, ok := t.state.accountMetadata[scope]
	if !ok {
		return AccountMetadata{}, ErrRecordNotFound
	}
	return metadata, nil
}

func (t *memoryTx) PutAccountMetadata(scope Scope, metadata AccountMetadata) error {
	if err := t.check(true); err != nil {
		return err
	}
	t.state.accountMetadata[scope] = metadata
	return nil
}

func (t *memoryTx) CredentialReport(scope Scope) (CredentialReportRecord, error) {
	if err := t.check(false); err != nil {
		return CredentialReportRecord{}, err
	}
	report, ok := t.state.credentialReports[scope]
	if !ok {
		return CredentialReportRecord{}, ErrRecordNotFound
	}
	report.Content = slices.Clone(report.Content)
	return report, nil
}

func (t *memoryTx) PutCredentialReport(scope Scope, report CredentialReportRecord) error {
	if err := t.check(true); err != nil {
		return err
	}
	report.Content = slices.Clone(report.Content)
	t.state.credentialReports[scope] = report
	return nil
}

func (t *memoryTx) CredentialReportScopes() ([]Scope, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	scopes := make([]Scope, 0, len(t.state.credentialReports))
	for scope := range t.state.credentialReports {
		scopes = append(scopes, scope)
	}
	slices.SortFunc(scopes, func(a, b Scope) int {
		if order := cmp.Compare(a.Partition, b.Partition); order != 0 {
			return order
		}
		return cmp.Compare(a.AccountID, b.AccountID)
	})
	return scopes, nil
}
