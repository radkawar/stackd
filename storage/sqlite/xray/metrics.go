package xray

import (
	"stackd/storage/sqlite/xray/internal/sqlcgen"
	domain "stackd/storage/xray"
)

func (r reader) NextGroupMetric() (domain.GroupMetricRecord, error) {
	row, err := r.q.NextGroupMetric(r.ctx)
	if err != nil {
		return domain.GroupMetricRecord{}, missing(err)
	}
	return domain.GroupMetricRecord{Key: domain.GroupMetricKey{Group: domain.GroupKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.GroupID, Name: row.GroupName}, Minute: row.Minute}, Count: row.Count}, nil
}

func (w writer) AddGroupMetric(key domain.GroupMetricKey) error {
	group := key.Group
	return w.q.AddGroupMetric(w.ctx, sqlcgen.AddGroupMetricParams{Partition: group.Partition, AccountID: group.AccountID, Region: group.Region, GroupID: group.ID, GroupName: group.Name, Minute: key.Minute})
}

func (w writer) DeleteGroupMetric(key domain.GroupMetricKey) error {
	group := key.Group
	return w.q.DeleteGroupMetric(w.ctx, sqlcgen.DeleteGroupMetricParams{Partition: group.Partition, AccountID: group.AccountID, Region: group.Region, GroupID: group.ID, Minute: key.Minute})
}
