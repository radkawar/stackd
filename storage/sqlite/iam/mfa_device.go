package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) MFADevice(scope domain.Scope, key string) (domain.MFADevice, error) {
	var result domain.MFADevice
	row, err := r.q.GetMFADevice(r.ctx, sqlcgen.GetMFADeviceParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.MFADevice
	record.EnableDate = row.EnableDate
	record.RetiredAt = row.RetiredAt
	record.VerificationCount.Window = row.VerificationCountWindow
	record.LastPairStep = row.LastPairStep
	record.VerificationCount.Count = int(row.VerificationCountCount)
	record.SerialNumber = row.SerialNumber
	record.Binding.Value.Seed = row.BindingValueSeed
	record.Binding.Value.UserID = row.BindingValueUserID
	record.Binding.VisibleValue.Seed = row.BindingVisibleValueSeed
	record.Binding.VisibleValue.UserID = row.BindingVisibleValueUserID
	record.Binding.Value.SkewSteps = row.BindingValueSkewSteps
	record.Binding.VisibleValue.SkewSteps = row.BindingVisibleValueSkewSteps
	{
		child, err := r.readMFADeviceBindingPending(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Binding.Pending = child
	}
	{
		child, err := r.readMFADeviceUsedCodes(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.UsedCodes = child
	}
	{
		child, err := r.readMFADeviceTags(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Tags = child
	}
	return record, nil
}

func (r reader) MFADevices(scope domain.Scope) ([]domain.MFADevice, error) {
	rows, err := r.q.ListMFADeviceKeys(r.ctx, sqlcgen.ListMFADeviceKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.MFADevice
	for _, row := range rows {
		record, err := r.MFADevice(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutMFADevice(scope domain.Scope, record domain.MFADevice) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteMFADevice(w.ctx, sqlcgen.DeleteMFADeviceParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.SerialNumber}); err != nil {
		return err
	}
	if err := w.q.InsertMFADevice(w.ctx, sqlcgen.InsertMFADeviceParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.SerialNumber, EnableDate: record.EnableDate, RetiredAt: record.RetiredAt, VerificationCountWindow: record.VerificationCount.Window, LastPairStep: record.LastPairStep, VerificationCountCount: int64(record.VerificationCount.Count), SerialNumber: record.SerialNumber, BindingValueSeed: record.Binding.Value.Seed, BindingValueUserID: record.Binding.Value.UserID, BindingVisibleValueSeed: record.Binding.VisibleValue.Seed, BindingVisibleValueUserID: record.Binding.VisibleValue.UserID, BindingValueSkewSteps: record.Binding.Value.SkewSteps, BindingVisibleValueSkewSteps: record.Binding.VisibleValue.SkewSteps}); err != nil {
		return err
	}
	if err := w.writeMFADeviceBindingPending(scope.Partition, scope.AccountID, record.SerialNumber, record.Binding.Pending); err != nil {
		return err
	}
	if err := w.writeMFADeviceUsedCodes(scope.Partition, scope.AccountID, record.SerialNumber, record.UsedCodes); err != nil {
		return err
	}
	if err := w.writeMFADeviceTags(scope.Partition, scope.AccountID, record.SerialNumber, record.Tags); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteMFADevice(scope domain.Scope, key string) error {
	count, err := w.q.DeleteMFADevice(w.ctx, sqlcgen.DeleteMFADeviceParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}

func (r reader) readMFADeviceBindingPending(partition string, account string, resourceKey string) ([]domain.PropagationChange[domain.MFABinding], error) {
	var result []domain.PropagationChange[domain.MFABinding]
	rows, err := r.q.ListMFADeviceBindingPending(r.ctx, sqlcgen.ListMFADeviceBindingPendingParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.PropagationChange[domain.MFABinding]
		record.Value.Seed = row.ValueSeed
		record.Value.UserID = row.ValueUserID
		record.Value.SkewSteps = row.ValueSkewSteps
		record.VisibleAt = row.VisibleAt
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readMFADeviceUsedCodes(partition string, account string, resourceKey string) ([]domain.MFAUsedCode, error) {
	var result []domain.MFAUsedCode
	rows, err := r.q.ListMFADeviceUsedCodes(r.ctx, sqlcgen.ListMFADeviceUsedCodesParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.MFAUsedCode
		record.Seed = row.Seed
		record.Step = row.Step
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readMFADeviceTags(partition string, account string, resourceKey string) ([]domain.Tag, error) {
	var result []domain.Tag
	rows, err := r.q.ListMFADeviceTags(r.ctx, sqlcgen.ListMFADeviceTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.Tag
		record.Key = row.Key
		record.Value = row.Value
		result = append(result, record)
	}
	return result, nil
}

func (w writer) writeMFADeviceBindingPending(partition string, account string, resourceKey string, value []domain.PropagationChange[domain.MFABinding]) error {
	for position1, record := range value {
		if err := w.q.InsertMFADeviceBindingPending(w.ctx, sqlcgen.InsertMFADeviceBindingPendingParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), ValueSeed: record.Value.Seed, ValueUserID: record.Value.UserID, ValueSkewSteps: record.Value.SkewSteps, VisibleAt: record.VisibleAt}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeMFADeviceUsedCodes(partition string, account string, resourceKey string, value []domain.MFAUsedCode) error {
	for position1, record := range value {
		if err := w.q.InsertMFADeviceUsedCodes(w.ctx, sqlcgen.InsertMFADeviceUsedCodesParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Seed: record.Seed, Step: record.Step}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeMFADeviceTags(partition string, account string, resourceKey string, value []domain.Tag) error {
	for position1, record := range value {
		if err := w.q.InsertMFADeviceTags(w.ctx, sqlcgen.InsertMFADeviceTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Key: record.Key, Value: record.Value}); err != nil {
			return err
		}
	}
	return nil
}
