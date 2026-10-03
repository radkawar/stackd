package iam

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"
)

type transactionKey struct{}
type serviceTransaction struct {
	service     *Service
	tx          ReadTx
	currentTime time.Time
}

func (s *Service) view(ctx context.Context, fn func(ReadTx) error) error {
	if transaction, ok := ctx.Value(transactionKey{}).(serviceTransaction); ok && transaction.service == s {
		return fn(transaction.tx)
	}
	return s.repository.View(ctx, fn)
}

// viewAt gives trusted credential consumers the owning transaction's instant.
// New snapshots capture it only after storage has acquired the read boundary.
func (s *Service) viewAt(ctx context.Context, fn func(ReadTx, time.Time) error) error {
	if transaction, ok := ctx.Value(transactionKey{}).(serviceTransaction); ok && transaction.service == s {
		return fn(transaction.tx, transaction.currentTime)
	}
	return s.repository.View(ctx, func(tx ReadTx) error {
		return fn(tx, s.clock.Now().UTC())
	})
}

// updateAt joins trusted credential and service-owned writes to the current IAM
// transaction, or acquires a write boundary and its instant when called standalone.
func (s *Service) updateAt(ctx context.Context, fn func(WriteTx, time.Time) error) error {
	if transaction, ok := ctx.Value(transactionKey{}).(serviceTransaction); ok && transaction.service == s {
		tx, ok := transaction.tx.(WriteTx)
		if !ok {
			return errors.New("operation requires an IAM write transaction")
		}
		return fn(tx, transaction.currentTime)
	}
	return s.repository.Update(ctx, func(tx WriteTx) error {
		return fn(tx, s.clock.Now().UTC())
	})
}

func loadAccount(tx ReadTx, scope Scope) (*account, error) {
	a := newAccount()
	a.partition = scope.Partition
	signingCertificates, certErr := tx.SigningCertificates(scope)
	if certErr != nil {
		return nil, certErr
	}
	for _, r := range signingCertificates {
		a.signingCertificates[r.ID] = &r
	}
	sshKeys, certErr := tx.SSHPublicKeys(scope)
	if certErr != nil {
		return nil, certErr
	}
	for _, r := range sshKeys {
		a.sshKeys[r.ID] = &r
	}
	serverCertificates, certErr := tx.ServerCertificates(scope)
	if certErr != nil {
		return nil, certErr
	}
	for _, r := range serverCertificates {
		a.serverCertificates[strings.ToLower(r.Name)] = &r
	}

	users, err := tx.Users(scope)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		a.users[strings.ToLower(u.UserName)] = &u
	}
	groups, err := tx.Groups(scope)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		a.groups[strings.ToLower(g.GroupName)] = &g
	}
	roles, err := tx.Roles(scope)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		a.roles[strings.ToLower(r.RoleName)] = &r
	}
	policies, err := tx.ManagedPolicies(scope)
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		a.policies[p.Arn] = &p
	}
	devices, err := tx.MFADevices(scope)
	if err != nil {
		return nil, err
	}
	for _, device := range devices {
		if device.RetiredAt.IsZero() {
			a.mfaDevices[device.SerialNumber] = &device
		}
	}
	profiles, err := tx.InstanceProfiles(scope)
	if err != nil {
		return nil, err
	}
	for _, profile := range profiles {
		a.instanceProfiles[strings.ToLower(profile.InstanceProfileName)] = &profile
	}
	logins, err := tx.LoginProfiles(scope)
	if err != nil {
		return nil, err
	}
	for _, login := range logins {
		a.loginProfiles[login.UserID] = &login
	}
	serviceCredentials, err := tx.ServiceCredentials(scope)
	if err != nil {
		return nil, err
	}
	for _, credential := range serviceCredentials {
		a.serviceCredentials[credential.ID] = &credential
	}
	oidcProviders, err := tx.OIDCProviders(scope)
	if err != nil {
		return nil, err
	}
	for _, provider := range oidcProviders {
		a.oidcProviders[provider.ARN] = &provider
	}
	samlProviders, err := tx.SAMLProviders(scope)
	if err != nil {
		return nil, err
	}
	for _, provider := range samlProviders {
		a.samlProviders[provider.ARN] = &provider
	}
	deletions, err := tx.ServiceLinkedRoleDeletions(scope)
	if err != nil {
		return nil, err
	}
	for _, deletion := range deletions {
		a.serviceLinkedDeletions[deletion.ID] = &deletion
	}
	a.settings, err = tx.AccountSettings(scope)
	if err != nil {
		return nil, err
	}
	metadata, err := tx.AccountMetadata(scope)
	if err == nil {
		a.metadata = &metadata
	} else if !errors.Is(err, ErrRecordNotFound) {
		return nil, err
	}
	installAWSManagedPolicies(a, scope.Partition)
	return a, nil
}

func saveAccount(tx WriteTx, scope Scope, before, after *account) error {
	if after.metadata != nil && !reflect.DeepEqual(before.metadata, after.metadata) {
		if err := tx.PutAccountMetadata(scope, *after.metadata); err != nil {
			return err
		}
	}
	if err := saveRecords(before.signingCertificates, after.signingCertificates, func(r SigningCertificateRecord) error { return tx.PutSigningCertificate(scope, r) }, func(id string) error { return tx.DeleteSigningCertificate(scope, id) }); err != nil {
		return err
	}
	if err := saveRecords(before.sshKeys, after.sshKeys, func(r SSHPublicKeyRecord) error { return tx.PutSSHPublicKey(scope, r) }, func(id string) error { return tx.DeleteSSHPublicKey(scope, id) }); err != nil {
		return err
	}
	if err := saveRecords(before.serverCertificates, after.serverCertificates, func(r ServerCertificateRecord) error { return tx.PutServerCertificate(scope, r) }, func(id string) error { return tx.DeleteServerCertificate(scope, id) }); err != nil {
		return err
	}

	if err := saveRecords(before.users, after.users, func(u User) error { return tx.PutUser(scope, u) }, func(name string) error { return tx.DeleteUser(scope, name) }); err != nil {
		return err
	}
	if err := saveRecords(before.groups, after.groups, func(g Group) error { return tx.PutGroup(scope, g) }, func(name string) error { return tx.DeleteGroup(scope, name) }); err != nil {
		return err
	}
	if err := saveRecords(before.roles, after.roles, func(r Role) error { return tx.PutRole(scope, r) }, func(name string) error { return tx.DeleteRole(scope, name) }); err != nil {
		return err
	}
	if err := saveRecords(customerPolicyRecords(before.policies), customerPolicyRecords(after.policies), func(p ManagedPolicy) error { return tx.PutManagedPolicy(scope, p) }, func(arn string) error { return tx.DeleteManagedPolicy(scope, arn) }); err != nil {
		return err
	}
	if err := saveRecords(before.instanceProfiles, after.instanceProfiles, func(p InstanceProfile) error { return tx.PutInstanceProfile(scope, p) }, func(name string) error { return tx.DeleteInstanceProfile(scope, name) }); err != nil {
		return err
	}
	if err := saveRecords(before.loginProfiles, after.loginProfiles, func(p LoginProfileRecord) error { return tx.PutLoginProfile(scope, p) }, func(id string) error { return tx.DeleteLoginProfile(scope, id) }); err != nil {
		return err
	}
	if !reflect.DeepEqual(before.settings, after.settings) {
		if err := tx.PutAccountSettings(scope, after.settings); err != nil {
			return err
		}
	}
	if err := saveRecords(before.serviceCredentials, after.serviceCredentials, func(c ServiceCredentialRecord) error { return tx.PutServiceCredential(scope, c) }, func(id string) error { return tx.DeleteServiceCredential(scope, id) }); err != nil {
		return err
	}
	if err := saveRecords(before.oidcProviders, after.oidcProviders, func(p OIDCProviderRecord) error { return tx.PutOIDCProvider(scope, p) }, func(arn string) error { return tx.DeleteOIDCProvider(scope, arn) }); err != nil {
		return err
	}
	if err := saveRecords(before.samlProviders, after.samlProviders, func(p SAMLProviderRecord) error { return tx.PutSAMLProvider(scope, p) }, func(arn string) error { return tx.DeleteSAMLProvider(scope, arn) }); err != nil {
		return err
	}
	for id, deletion := range after.serviceLinkedDeletions {
		if !reflect.DeepEqual(before.serviceLinkedDeletions[id], deletion) {
			if err := tx.PutServiceLinkedRoleDeletion(scope, *deletion); err != nil {
				return err
			}
		}
	}
	return saveMFADevices(tx, scope, before, after)
}

func customerPolicyRecords(records map[string]*ManagedPolicy) map[string]*ManagedPolicy {
	result := make(map[string]*ManagedPolicy)
	for arn, record := range records {
		if !isAWSManagedPolicyARN(arn) {
			result[arn] = record
		}
	}
	return result
}

func saveRecords[T any](before, after map[string]*T, put func(T) error, remove func(string) error) error {
	for key, record := range after {
		if !reflect.DeepEqual(before[key], record) {
			if err := put(*record); err != nil {
				return err
			}
		}
	}
	for key := range before {
		if after[key] == nil {
			if err := remove(key); err != nil {
				return err
			}
		}
	}
	return nil
}
