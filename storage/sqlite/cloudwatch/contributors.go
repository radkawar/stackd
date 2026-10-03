package cloudwatch

import (
	"database/sql"

	domain "stackd/storage/cloudwatch"
	"stackd/storage/sqlite/cloudwatch/internal/sqlcgen"
)

func alarmContributorID(contributor *domain.AlarmContributorIdentity) sql.NullString {
	if contributor == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: contributor.ID, Valid: true}
}

func (r reader) AlarmContributors(q domain.AlarmContributorQuery) ([]domain.AlarmContributorRecord, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]domain.AlarmContributorRecord, 0, min(max(q.Limit, 0), readPageSize))
	if q.Limit <= 0 {
		return out, nil
	}
	params := sqlcgen.ListAlarmContributorsParams{AlarmID: q.AlarmID, AfterID: q.AfterID, PageLimit: int64(min(q.Limit, readPageSize))}
	for {
		rows, err := r.q.ListAlarmContributors(r.ctx, params)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			attributes, err := r.q.ListAlarmContributorAttributes(r.ctx, sqlcgen.ListAlarmContributorAttributesParams{AlarmID: row.AlarmID, ContributorID: row.ContributorID})
			if err != nil {
				return nil, err
			}
			contributor := domain.AlarmContributorRecord{
				AlarmContributorIdentity: domain.AlarmContributorIdentity{ID: row.ContributorID, Attributes: make(map[string]string, len(attributes))},
				Reason:                   row.Reason, Transitioned: row.Transitioned.UTC(),
			}
			for _, attribute := range attributes {
				contributor.Attributes[attribute.Key] = attribute.Value
			}
			out = append(out, contributor)
			if len(out) == q.Limit {
				return out, nil
			}
		}
		if len(rows) < int(params.PageLimit) {
			return out, r.ctx.Err()
		}
		params.AfterID = rows[len(rows)-1].ContributorID
		params.PageLimit = int64(min(q.Limit-len(out), readPageSize))
	}
}

func (w writer) PutAlarmContributor(alarmID string, contributor domain.AlarmContributorRecord) error {
	if err := w.q.PutAlarmContributor(w.ctx, sqlcgen.PutAlarmContributorParams{AlarmID: alarmID, ContributorID: contributor.ID, Reason: contributor.Reason, Transitioned: contributor.Transitioned.UTC()}); err != nil {
		return err
	}
	if err := w.q.DeleteAlarmContributorAttributes(w.ctx, sqlcgen.DeleteAlarmContributorAttributesParams{AlarmID: alarmID, ContributorID: contributor.ID}); err != nil {
		return err
	}
	for key, value := range contributor.Attributes {
		if err := w.q.PutAlarmContributorAttribute(w.ctx, sqlcgen.PutAlarmContributorAttributeParams{AlarmID: alarmID, ContributorID: contributor.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteAlarmContributor(alarmID, contributorID string) error {
	return w.q.DeleteAlarmContributor(w.ctx, sqlcgen.DeleteAlarmContributorParams{AlarmID: alarmID, ContributorID: contributorID})
}
