package appconfig

import (
	"database/sql"
	"errors"
	domain "stackd/storage/appconfig"
	"stackd/storage/sqlite/appconfig/internal/sqlcgen"
)

func (r reader) Tags(s domain.Scope, arn string) (map[string]string, error) {
	rows, err := r.q.ListTags(r.ctx, sqlcgen.ListTagsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Arn: arn})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(rows))
	for _, v := range rows {
		out[v.Key] = v.Value
	}
	return out, nil
}
func (w writer) PutTags(s domain.Scope, arn string, tags map[string]string) error {
	if err := w.q.ClearTags(w.ctx, sqlcgen.ClearTagsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Arn: arn}); err != nil {
		return err
	}
	for key, value := range tags {
		if err := w.q.InsertTag(w.ctx, sqlcgen.InsertTagParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Arn: arn, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}
func (r reader) Settings(s domain.Scope) (domain.Settings, bool, error) {
	v, err := r.q.GetSettings(r.ctx, sqlcgen.GetSettingsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Settings{}, false, nil
	}
	if err != nil {
		return domain.Settings{}, false, err
	}
	return domain.Settings{Scope: s, DeletionProtectionEnabled: v.DeletionProtectionEnabled, ProtectionMinutes: int32(v.ProtectionMinutes), VendedMetricsEnabled: v.VendedMetricsEnabled, VendedMetricsSet: v.VendedMetricsSet}, true, nil
}
func (w writer) PutSettings(v domain.Settings) error {
	return w.q.PutSettings(w.ctx, sqlcgen.PutSettingsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DeletionProtectionEnabled: v.DeletionProtectionEnabled, ProtectionMinutes: int64(v.ProtectionMinutes), VendedMetricsEnabled: v.VendedMetricsEnabled, VendedMetricsSet: v.VendedMetricsSet})
}
