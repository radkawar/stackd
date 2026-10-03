package iam

import (
	"slices"
	"strings"
)

func (t *memoryTx) OIDCProvider(scope Scope, arn string) (OIDCProviderRecord, error) {
	if err := t.check(false); err != nil {
		return OIDCProviderRecord{}, err
	}
	record, ok := t.state.oidcProviders[scope][arn]
	if !ok {
		return OIDCProviderRecord{}, ErrRecordNotFound
	}
	return cloneOIDCProvider(record), nil
}
func (t *memoryTx) OIDCProviders(scope Scope) ([]OIDCProviderRecord, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	result := make([]OIDCProviderRecord, 0, len(t.state.oidcProviders[scope]))
	for _, record := range t.state.oidcProviders[scope] {
		result = append(result, cloneOIDCProvider(record))
	}
	slices.SortFunc(result, func(a, b OIDCProviderRecord) int { return strings.Compare(a.ARN, b.ARN) })
	return result, nil
}
func (t *memoryTx) PutOIDCProvider(scope Scope, record OIDCProviderRecord) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.oidcProviders[scope] == nil {
		t.state.oidcProviders[scope] = make(map[string]OIDCProviderRecord)
	}
	t.state.oidcProviders[scope][record.ARN] = cloneOIDCProvider(record)
	return nil
}
func (t *memoryTx) DeleteOIDCProvider(scope Scope, arn string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, ok := t.state.oidcProviders[scope][arn]; !ok {
		return ErrRecordNotFound
	}
	delete(t.state.oidcProviders[scope], arn)
	return nil
}
func (t *memoryTx) SAMLProvider(scope Scope, arn string) (SAMLProviderRecord, error) {
	if err := t.check(false); err != nil {
		return SAMLProviderRecord{}, err
	}
	record, ok := t.state.samlProviders[scope][arn]
	if !ok {
		return SAMLProviderRecord{}, ErrRecordNotFound
	}
	return cloneSAMLProvider(record), nil
}
func (t *memoryTx) SAMLProviders(scope Scope) ([]SAMLProviderRecord, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	result := make([]SAMLProviderRecord, 0, len(t.state.samlProviders[scope]))
	for _, record := range t.state.samlProviders[scope] {
		result = append(result, cloneSAMLProvider(record))
	}
	slices.SortFunc(result, func(a, b SAMLProviderRecord) int { return strings.Compare(a.ARN, b.ARN) })
	return result, nil
}
func (t *memoryTx) PutSAMLProvider(scope Scope, record SAMLProviderRecord) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.samlProviders[scope] == nil {
		t.state.samlProviders[scope] = make(map[string]SAMLProviderRecord)
	}
	t.state.samlProviders[scope][record.ARN] = cloneSAMLProvider(record)
	return nil
}
func (t *memoryTx) DeleteSAMLProvider(scope Scope, arn string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, ok := t.state.samlProviders[scope][arn]; !ok {
		return ErrRecordNotFound
	}
	delete(t.state.samlProviders[scope], arn)
	return nil
}

func cloneOIDCProvider(p OIDCProviderRecord) OIDCProviderRecord {
	p.ClientIDs = slices.Clone(p.ClientIDs)
	p.Thumbprints = slices.Clone(p.Thumbprints)
	p.Tags = slices.Clone(p.Tags)
	return p
}
func cloneSAMLProvider(p SAMLProviderRecord) SAMLProviderRecord {
	p.Issuers = slices.Clone(p.Issuers)
	for i := range p.Issuers {
		p.Issuers[i].SigningCertificates = cloneFederationBytes(p.Issuers[i].SigningCertificates)
	}
	p.PrivateKeys = slices.Clone(p.PrivateKeys)
	for i := range p.PrivateKeys {
		p.PrivateKeys[i].PKCS8DER = slices.Clone(p.PrivateKeys[i].PKCS8DER)
	}
	p.Tags = slices.Clone(p.Tags)
	return p
}
func cloneFederationBytes(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for i, value := range values {
		result[i] = slices.Clone(value)
	}
	return result
}
