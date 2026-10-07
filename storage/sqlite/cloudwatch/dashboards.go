package cloudwatch

import (
	"database/sql"
	"errors"

	domain "stackd/storage/cloudwatch"
	"stackd/storage/sqlite/cloudwatch/internal/sqlcgen"
)

func (r reader) Dashboard(key domain.DashboardKey) (domain.DashboardRecord, error) {
	row, err := r.q.GetDashboard(r.ctx, sqlcgen.GetDashboardParams{Partition: key.Partition, AccountID: key.AccountID, Name: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.DashboardRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.DashboardRecord{}, err
	}
	tags, err := r.q.ListDashboardTags(r.ctx, sqlcgen.ListDashboardTagsParams{Partition: key.Partition, AccountID: key.AccountID, DashboardName: key.Name})
	if err != nil {
		return domain.DashboardRecord{}, err
	}
	out := domain.DashboardRecord{
		CFNOwner:       row.CfnOwner,
		DashboardEntry: domain.DashboardEntry{Key: key, Updated: row.Updated, Size: row.Size},
		Body:           row.Body, Tags: make(map[string]string, len(tags)), TaggingInitialized: row.TaggingInitialized,
	}
	for _, tag := range tags {
		out.Tags[tag.Key] = tag.Value
	}
	return out, nil
}

func (r reader) Dashboards(query domain.DashboardQuery) ([]domain.DashboardEntry, error) {
	rows, err := r.q.ListDashboards(r.ctx, sqlcgen.ListDashboardsParams{
		Partition: query.Partition, AccountID: query.AccountID, Prefix: query.Prefix,
		AfterName: query.After, PageLimit: int64(query.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.DashboardEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.DashboardEntry{
			Key:     domain.DashboardKey{Partition: row.Partition, AccountID: row.AccountID, Name: row.Name},
			Updated: row.Updated, Size: row.Size,
		})
	}
	return out, nil
}

func (w writer) PutDashboard(record domain.DashboardRecord) error {
	key := record.Key
	if err := w.q.PutDashboard(w.ctx, sqlcgen.PutDashboardParams{
		Partition: key.Partition, AccountID: key.AccountID, Name: key.Name,
		CfnOwner: record.CFNOwner,
		Body:     record.Body, Updated: record.Updated, Size: record.Size, TaggingInitialized: record.TaggingInitialized,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteDashboardTags(w.ctx, sqlcgen.DeleteDashboardTagsParams{Partition: key.Partition, AccountID: key.AccountID, DashboardName: key.Name}); err != nil {
		return err
	}
	for name, value := range record.Tags {
		if err := w.q.PutDashboardTag(w.ctx, sqlcgen.PutDashboardTagParams{Partition: key.Partition, AccountID: key.AccountID, DashboardName: key.Name, Key: name, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteDashboard(key domain.DashboardKey) error {
	return w.q.DeleteDashboard(w.ctx, sqlcgen.DeleteDashboardParams{Partition: key.Partition, AccountID: key.AccountID, Name: key.Name})
}
