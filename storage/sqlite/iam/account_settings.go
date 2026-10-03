package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) AccountSettings(scope domain.Scope) (domain.AccountSettingsRecord, error) {
	var result domain.AccountSettingsRecord
	row, err := r.q.GetAccountSettings(r.ctx, sqlcgen.GetAccountSettingsParams{Partition: scope.Partition, Account: scope.AccountID})
	if errors.Is(err, sql.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	var record domain.AccountSettingsRecord
	record.Alias = row.Alias
	record.RoleManagerEnabled = row.RoleManagerEnabled
	record.GlobalEndpointAllRegions.Value = row.GlobalEndpointAllRegionsValue
	record.GlobalEndpointAllRegions.VisibleValue = row.GlobalEndpointAllRegionsVisibleValue
	{
		child, err := r.readAccountSettingsPasswordPolicy(row.Partition, row.Account)
		if err != nil {
			return result, err
		}
		record.PasswordPolicy = child
	}
	{
		child, err := r.readAccountSettingsRootLoginProfile(row.Partition, row.Account)
		if err != nil {
			return result, err
		}
		record.RootLoginProfile = child
	}
	{
		child, err := r.readAccountSettingsOutboundWebIdentity(row.Partition, row.Account)
		if err != nil {
			return result, err
		}
		record.OutboundWebIdentity = child
	}
	{
		child, err := r.readAccountSettingsGlobalEndpointAllRegions(row.Partition, row.Account)
		if err != nil {
			return result, err
		}
		record.GlobalEndpointAllRegions.Pending = child
	}
	return record, nil
}

func (w writer) PutAccountSettings(scope domain.Scope, record domain.AccountSettingsRecord) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteAccountSettings(w.ctx, sqlcgen.DeleteAccountSettingsParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if err := w.q.InsertAccountSettings(w.ctx, sqlcgen.InsertAccountSettingsParams{Partition: scope.Partition, Account: scope.AccountID, Alias: record.Alias, RoleManagerEnabled: record.RoleManagerEnabled, GlobalEndpointAllRegionsValue: record.GlobalEndpointAllRegions.Value, GlobalEndpointAllRegionsVisibleValue: record.GlobalEndpointAllRegions.VisibleValue}); err != nil {
		return err
	}
	if err := w.writeAccountSettingsPasswordPolicy(scope.Partition, scope.AccountID, record.PasswordPolicy); err != nil {
		return err
	}
	if err := w.writeAccountSettingsRootLoginProfile(scope.Partition, scope.AccountID, record.RootLoginProfile); err != nil {
		return err
	}
	if err := w.writeAccountSettingsOutboundWebIdentity(scope.Partition, scope.AccountID, record.OutboundWebIdentity); err != nil {
		return err
	}
	if err := w.writeAccountSettingsGlobalEndpointAllRegions(scope.Partition, scope.AccountID, record.GlobalEndpointAllRegions.Pending); err != nil {
		return err
	}
	return nil
}

func (r reader) readAccountSettingsPasswordPolicy(partition string, account string) (*domain.AccountPasswordPolicy, error) {
	var result *domain.AccountPasswordPolicy
	row, err := r.q.GetAccountSettingsPasswordPolicy(r.ctx, sqlcgen.GetAccountSettingsPasswordPolicyParams{Partition: partition, Account: account})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return result, err
	}
	record := &domain.AccountPasswordPolicy{}
	record.MinimumPasswordLength = int(row.MinimumPasswordLength)
	record.MaxPasswordAge = int(row.MaxPasswordAge)
	record.PasswordReusePrevention = int(row.PasswordReusePrevention)
	record.RequireSymbols = row.RequireSymbols
	record.RequireNumbers = row.RequireNumbers
	record.RequireUppercaseCharacters = row.RequireUppercaseCharacters
	record.RequireLowercaseCharacters = row.RequireLowercaseCharacters
	record.AllowUsersToChangePassword = row.AllowUsersToChangePassword
	record.HardExpiry = row.HardExpiry
	return record, nil
}

func (r reader) readAccountSettingsRootLoginProfile(partition string, account string) (*domain.RootLoginProfileRecord, error) {
	var result *domain.RootLoginProfileRecord
	row, err := r.q.GetAccountSettingsRootLoginProfile(r.ctx, sqlcgen.GetAccountSettingsRootLoginProfileParams{Partition: partition, Account: account})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return result, err
	}
	record := &domain.RootLoginProfileRecord{}
	record.CreateDate = row.CreateDate
	return record, nil
}

func (r reader) readAccountSettingsOutboundWebIdentity(partition string, account string) (*domain.OutboundWebIdentityRecord, error) {
	var result *domain.OutboundWebIdentityRecord
	row, err := r.q.GetAccountSettingsOutboundWebIdentity(r.ctx, sqlcgen.GetAccountSettingsOutboundWebIdentityParams{Partition: partition, Account: account})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return result, err
	}
	record := &domain.OutboundWebIdentityRecord{}
	record.IssuerID = row.IssuerID
	record.IssuerURL = row.IssuerUrl
	record.RS256.ID = row.Rs256ID
	record.ES384.ID = row.Es384ID
	record.RS256.PKCS8DER = row.Rs256Pkcs8Der
	record.ES384.PKCS8DER = row.Es384Pkcs8Der
	record.Enabled.Value = row.EnabledValue
	record.Enabled.VisibleValue = row.EnabledVisibleValue
	{
		child, err := r.readAccountSettingsOutboundWebIdentityEnabled(row.Partition, row.Account)
		if err != nil {
			return result, err
		}
		record.Enabled.Pending = child
	}
	return record, nil
}

func (r reader) readAccountSettingsOutboundWebIdentityEnabled(partition string, account string) ([]domain.PropagationChange[bool], error) {
	var result []domain.PropagationChange[bool]
	rows, err := r.q.ListAccountSettingsOutboundWebIdentityEnabled(r.ctx, sqlcgen.ListAccountSettingsOutboundWebIdentityEnabledParams{Partition: partition, Account: account})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.PropagationChange[bool]
		record.Value = row.Value
		record.VisibleAt = row.VisibleAt
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readAccountSettingsGlobalEndpointAllRegions(partition string, account string) ([]domain.PropagationChange[bool], error) {
	var result []domain.PropagationChange[bool]
	rows, err := r.q.ListAccountSettingsGlobalEndpointAllRegions(r.ctx, sqlcgen.ListAccountSettingsGlobalEndpointAllRegionsParams{Partition: partition, Account: account})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.PropagationChange[bool]
		record.Value = row.Value
		record.VisibleAt = row.VisibleAt
		result = append(result, record)
	}
	return result, nil
}

func (w writer) writeAccountSettingsPasswordPolicy(partition string, account string, record *domain.AccountPasswordPolicy) error {
	if record == nil {
		return nil
	}
	if err := w.q.InsertAccountSettingsPasswordPolicy(w.ctx, sqlcgen.InsertAccountSettingsPasswordPolicyParams{Partition: partition, Account: account, MinimumPasswordLength: int64(record.MinimumPasswordLength), MaxPasswordAge: int64(record.MaxPasswordAge), PasswordReusePrevention: int64(record.PasswordReusePrevention), RequireSymbols: record.RequireSymbols, RequireNumbers: record.RequireNumbers, RequireUppercaseCharacters: record.RequireUppercaseCharacters, RequireLowercaseCharacters: record.RequireLowercaseCharacters, AllowUsersToChangePassword: record.AllowUsersToChangePassword, HardExpiry: record.HardExpiry}); err != nil {
		return err
	}
	return nil
}

func (w writer) writeAccountSettingsRootLoginProfile(partition string, account string, record *domain.RootLoginProfileRecord) error {
	if record == nil {
		return nil
	}
	if err := w.q.InsertAccountSettingsRootLoginProfile(w.ctx, sqlcgen.InsertAccountSettingsRootLoginProfileParams{Partition: partition, Account: account, CreateDate: record.CreateDate}); err != nil {
		return err
	}
	return nil
}

func (w writer) writeAccountSettingsOutboundWebIdentity(partition string, account string, record *domain.OutboundWebIdentityRecord) error {
	if record == nil {
		return nil
	}
	if err := w.q.InsertAccountSettingsOutboundWebIdentity(w.ctx, sqlcgen.InsertAccountSettingsOutboundWebIdentityParams{Partition: partition, Account: account, IssuerID: record.IssuerID, IssuerUrl: record.IssuerURL, Rs256ID: record.RS256.ID, Es384ID: record.ES384.ID, Rs256Pkcs8Der: record.RS256.PKCS8DER, Es384Pkcs8Der: record.ES384.PKCS8DER, EnabledValue: record.Enabled.Value, EnabledVisibleValue: record.Enabled.VisibleValue}); err != nil {
		return err
	}
	if err := w.writeAccountSettingsOutboundWebIdentityEnabled(partition, account, record.Enabled.Pending); err != nil {
		return err
	}
	return nil
}

func (w writer) writeAccountSettingsOutboundWebIdentityEnabled(partition string, account string, value []domain.PropagationChange[bool]) error {
	for position2, record := range value {
		if err := w.q.InsertAccountSettingsOutboundWebIdentityEnabled(w.ctx, sqlcgen.InsertAccountSettingsOutboundWebIdentityEnabledParams{Partition: partition, Account: account, Position2: int64(position2), Value: record.Value, VisibleAt: record.VisibleAt}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeAccountSettingsGlobalEndpointAllRegions(partition string, account string, value []domain.PropagationChange[bool]) error {
	for position1, record := range value {
		if err := w.q.InsertAccountSettingsGlobalEndpointAllRegions(w.ctx, sqlcgen.InsertAccountSettingsGlobalEndpointAllRegionsParams{Partition: partition, Account: account, Position1: int64(position1), Value: record.Value, VisibleAt: record.VisibleAt}); err != nil {
			return err
		}
	}
	return nil
}
