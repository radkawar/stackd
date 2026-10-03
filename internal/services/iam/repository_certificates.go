package iam

import (
	"slices"
	"strings"
)

func cloneSigningCertificate(record SigningCertificateRecord) SigningCertificateRecord {
	record.DER = slices.Clone(record.DER)
	return record
}
func (t *memoryTx) SigningCertificate(scope Scope, id string) (SigningCertificateRecord, error) {
	if err := t.check(false); err != nil {
		return SigningCertificateRecord{}, err
	}
	record, ok := t.state.signingCertificates[scope][id]
	if !ok {
		return SigningCertificateRecord{}, ErrRecordNotFound
	}
	return cloneSigningCertificate(record), nil
}
func (t *memoryTx) SigningCertificates(scope Scope) ([]SigningCertificateRecord, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := make([]SigningCertificateRecord, 0, len(t.state.signingCertificates[scope]))
	for _, record := range t.state.signingCertificates[scope] {
		out = append(out, cloneSigningCertificate(record))
	}
	slices.SortFunc(out, func(a, b SigningCertificateRecord) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}
func (t *memoryTx) PutSigningCertificate(scope Scope, record SigningCertificateRecord) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.signingCertificates[scope] == nil {
		t.state.signingCertificates[scope] = make(map[string]SigningCertificateRecord)
	}
	t.state.signingCertificates[scope][record.ID] = cloneSigningCertificate(record)
	return nil
}
func (t *memoryTx) DeleteSigningCertificate(scope Scope, id string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, ok := t.state.signingCertificates[scope][id]; !ok {
		return ErrRecordNotFound
	}
	delete(t.state.signingCertificates[scope], id)
	return nil
}
func cloneSSHPublicKey(record SSHPublicKeyRecord) SSHPublicKeyRecord {
	record.Wire = slices.Clone(record.Wire)
	return record
}
func (t *memoryTx) SSHPublicKey(scope Scope, id string) (SSHPublicKeyRecord, error) {
	if err := t.check(false); err != nil {
		return SSHPublicKeyRecord{}, err
	}
	record, ok := t.state.sshKeys[scope][id]
	if !ok {
		return SSHPublicKeyRecord{}, ErrRecordNotFound
	}
	return cloneSSHPublicKey(record), nil
}
func (t *memoryTx) SSHPublicKeys(scope Scope) ([]SSHPublicKeyRecord, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := make([]SSHPublicKeyRecord, 0, len(t.state.sshKeys[scope]))
	for _, record := range t.state.sshKeys[scope] {
		out = append(out, cloneSSHPublicKey(record))
	}
	slices.SortFunc(out, func(a, b SSHPublicKeyRecord) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}
func (t *memoryTx) PutSSHPublicKey(scope Scope, record SSHPublicKeyRecord) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.sshKeys[scope] == nil {
		t.state.sshKeys[scope] = make(map[string]SSHPublicKeyRecord)
	}
	t.state.sshKeys[scope][record.ID] = cloneSSHPublicKey(record)
	return nil
}
func (t *memoryTx) DeleteSSHPublicKey(scope Scope, id string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, ok := t.state.sshKeys[scope][id]; !ok {
		return ErrRecordNotFound
	}
	delete(t.state.sshKeys[scope], id)
	return nil
}
func cloneServerCertificate(record ServerCertificateRecord) ServerCertificateRecord {
	record.PrivateKey = slices.Clone(record.PrivateKey)
	record.Tags = slices.Clone(record.Tags)
	return record
}
func (t *memoryTx) ServerCertificate(scope Scope, id string) (ServerCertificateRecord, error) {
	if err := t.check(false); err != nil {
		return ServerCertificateRecord{}, err
	}
	record, ok := t.state.serverCertificates[scope][strings.ToLower(id)]
	if !ok {
		return ServerCertificateRecord{}, ErrRecordNotFound
	}
	return cloneServerCertificate(record), nil
}
func (t *memoryTx) ServerCertificates(scope Scope) ([]ServerCertificateRecord, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := make([]ServerCertificateRecord, 0, len(t.state.serverCertificates[scope]))
	for _, record := range t.state.serverCertificates[scope] {
		out = append(out, cloneServerCertificate(record))
	}
	slices.SortFunc(out, func(a, b ServerCertificateRecord) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
func (t *memoryTx) PutServerCertificate(scope Scope, record ServerCertificateRecord) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.serverCertificates[scope] == nil {
		t.state.serverCertificates[scope] = make(map[string]ServerCertificateRecord)
	}
	t.state.serverCertificates[scope][strings.ToLower(record.Name)] = cloneServerCertificate(record)
	return nil
}
func (t *memoryTx) DeleteServerCertificate(scope Scope, id string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, ok := t.state.serverCertificates[scope][strings.ToLower(id)]; !ok {
		return ErrRecordNotFound
	}
	delete(t.state.serverCertificates[scope], strings.ToLower(id))
	return nil
}
