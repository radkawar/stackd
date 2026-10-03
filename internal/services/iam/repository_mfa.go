package iam

import (
	"slices"
	"strings"
	"time"
)

func (t *memoryTx) MFADevice(scope Scope, serial string) (MFADevice, error) {
	if err := t.check(false); err != nil {
		return MFADevice{}, err
	}
	d, ok := t.state.mfaDevices[scope][serial]
	if !ok {
		return MFADevice{}, ErrRecordNotFound
	}
	return cloneMFADevice(d), nil
}
func (t *memoryTx) MFADevices(scope Scope) ([]MFADevice, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	result := make([]MFADevice, 0, len(t.state.mfaDevices[scope]))
	for _, d := range t.state.mfaDevices[scope] {
		result = append(result, cloneMFADevice(d))
	}
	slices.SortFunc(result, func(a, b MFADevice) int { return strings.Compare(a.SerialNumber, b.SerialNumber) })
	return result, nil
}
func (t *memoryTx) PutMFADevice(scope Scope, d MFADevice) error {
	if err := t.check(true); err != nil {
		return err
	}
	if t.state.mfaDevices[scope] == nil {
		t.state.mfaDevices[scope] = make(map[string]MFADevice)
	}
	t.state.mfaDevices[scope][d.SerialNumber] = cloneMFADevice(d)
	return nil
}
func (t *memoryTx) DeleteMFADevice(scope Scope, serial string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, ok := t.state.mfaDevices[scope][serial]; !ok {
		return ErrRecordNotFound
	}
	delete(t.state.mfaDevices[scope], serial)
	return nil
}
func cloneMFADevice(d MFADevice) MFADevice {
	d.Binding = d.Binding.clone()
	d.Tags = slices.Clone(d.Tags)
	d.UsedCodes = slices.Clone(d.UsedCodes)
	if d.LastPairStep != nil {
		step := *d.LastPairStep
		d.LastPairStep = &step
	}
	return d
}

// saveMFADevices owns the split between immediate IAM deletion and delayed STS
// revocation. Retired rows are absent from the IAM working set. Recreating an
// ARN preserves its preceding STS binding until the replacement propagates.
func saveMFADevices(tx WriteTx, scope Scope, before, after *account) error {
	devices, err := tx.MFADevices(scope)
	if err != nil {
		return err
	}
	now := after.currentTime
	for _, retired := range devices {
		if retired.RetiredAt.IsZero() {
			continue
		}
		if replacement := after.mfaDevices[retired.SerialNumber]; replacement != nil {
			binding := retired.Binding
			binding.set(replacement.Binding.Value, now)
			replacement.Binding = binding
			replacement.UsedCodes = retired.UsedCodes
			replacement.VerificationCount = retired.VerificationCount
			replacement.pruneUsedCodes(now)
		} else if !now.Before(retired.RetiredAt.Add(stsPropagationDelay)) && !now.Before(retired.VerificationCount.Window.Add(mfaAttemptWindow)) {
			if err := tx.DeleteMFADevice(scope, retired.SerialNumber); err != nil {
				return err
			}
		}
	}
	return saveRecords(before.mfaDevices, after.mfaDevices, func(d MFADevice) error {
		return tx.PutMFADevice(scope, d)
	}, func(serial string) error {
		d := *before.mfaDevices[serial]
		d.RetiredAt = now
		d.Binding.set(MFABinding{}, now)
		d.EnableDate = time.Time{}
		d.Tags = nil
		d.LastPairStep = nil
		return tx.PutMFADevice(scope, d)
	})
}
