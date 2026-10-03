package ssm

import (
	"errors"

	"stackd/storage/sqlite/ssm/internal/sqlcgen"
	domain "stackd/storage/ssm"
)

func (r reader) Version(k domain.VersionKey) (domain.VersionRecord, error) {
	row, err := r.versionRow(k)
	if err != nil {
		return domain.VersionRecord{}, err
	}
	return r.version(k.Parameter, row)
}
func (r reader) Versions(k domain.ParameterKey) ([]domain.VersionRecord, error) {
	id, err := r.parameterID(k)
	if errors.Is(err, domain.ErrNotFound) {
		return []domain.VersionRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListVersions(r.ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]domain.VersionRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.version(k, row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) version(k domain.ParameterKey, row sqlcgen.SsmVersion) (domain.VersionRecord, error) {
	out := domain.VersionRecord{Key: domain.VersionKey{Parameter: k, Version: row.Version}, Type: row.Type, Tier: row.Tier, DataType: row.DataType, Description: row.Description, AllowedPattern: row.AllowedPattern, KeyID: row.KeyID, KeyARN: row.KeyArn, ModifiedUser: row.ModifiedUser, Modified: row.Modified.UTC()}
	value, err := r.q.GetValue(r.ctx, row.ID)
	if err != nil {
		return out, err
	}
	out.Value, out.WrappedKey = value.Value, value.WrappedKey
	if row.LabelsPresent {
		labels, err := r.q.ListLabels(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Labels = make([]string, 0, len(labels))
		for _, label := range labels {
			out.Labels = append(out.Labels, label.Value)
		}
	}
	if row.PoliciesPresent {
		policies, err := r.versionPolicies(row.ID)
		if err != nil {
			return out, err
		}
		out.Policies = policies
	}
	return out, nil
}
func (w writer) PutVersion(v domain.VersionRecord) error {
	parent, err := w.parameterID(v.Key.Parameter)
	if err != nil {
		return err
	}
	id, err := w.q.PutVersion(w.ctx, sqlcgen.PutVersionParams{ParentID: parent, Version: v.Key.Version, Type: v.Type, Tier: v.Tier, DataType: v.DataType, Description: v.Description, AllowedPattern: v.AllowedPattern, KeyID: v.KeyID, KeyArn: v.KeyARN, ModifiedUser: v.ModifiedUser, Modified: v.Modified.UTC(), LabelsPresent: v.Labels != nil, PoliciesPresent: v.Policies != nil})
	if err != nil {
		return err
	}
	if err := w.q.PutValue(w.ctx, sqlcgen.PutValueParams{ParentID: id, Value: v.Value, WrappedKey: v.WrappedKey}); err != nil {
		return err
	}
	if err := w.q.DeleteLabels(w.ctx, id); err != nil {
		return err
	}
	for i, label := range v.Labels {
		if err := w.q.PutLabels(w.ctx, sqlcgen.PutLabelsParams{ParentID: id, Position: int64(i), Value: label}); err != nil {
			return err
		}
	}
	return w.putVersionPolicies(id, v.Policies)
}
func (w writer) DeleteVersion(k domain.VersionKey) error {
	p := k.Parameter
	return w.q.DeleteVersion(w.ctx, sqlcgen.DeleteVersionParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, Name: p.Name, Version: k.Version})
}
func (r reader) Settings(s domain.Scope) ([]domain.SettingRecord, error) {
	rows, err := r.q.ListSettings(r.ctx, sqlcgen.ListSettingsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SettingRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.SettingRecord{Scope: s, ID: row.SettingID, Value: row.Value, ModifiedUser: row.ModifiedUser, Modified: row.Modified.UTC()})
	}
	return out, nil
}
func (w writer) PutSetting(v domain.SettingRecord) error {
	return w.q.PutSetting(w.ctx, sqlcgen.PutSettingParams{Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, SettingID: v.ID, Value: v.Value, ModifiedUser: v.ModifiedUser, Modified: v.Modified.UTC()})
}
