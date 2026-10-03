package dynamodb

import (
	"database/sql"
	"encoding/json"
	"time"

	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
)

func (r reader) Recovery(id string) (domain.RecoveryRecord, error) {
	row, err := r.q.GetRecovery(r.ctx, id)
	if err != nil {
		return domain.RecoveryRecord{}, missing(err)
	}
	return recoveryData(row)
}

func (r reader) RecoverySequence(id string) (int64, error) {
	return r.q.GetRecoverySequence(r.ctx, id)
}

func (r reader) Recoveries(databaseID string) ([]domain.RecoveryRecord, error) {
	rows, err := r.q.ListRecoveries(r.ctx, databaseID)
	return recoveryRecords(rows, err)
}

func (r reader) UnsettledRecoveries(databaseID string) ([]domain.RecoveryRecord, error) {
	rows, err := r.q.ListUnsettledRecoveries(r.ctx, databaseID)
	return recoveryRecords(rows, err)
}

func recoveryRecords(rows []sqlcgen.DynamodbRecovery, err error) ([]domain.RecoveryRecord, error) {
	if err != nil {
		return nil, err
	}
	out := make([]domain.RecoveryRecord, len(rows))
	for i, row := range rows {
		out[i], err = recoveryData(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func recoveryData(row sqlcgen.DynamodbRecovery) (domain.RecoveryRecord, error) {
	out := domain.RecoveryRecord{
		ID:         row.ID,
		Table:      domain.TableKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.TableName},
		DatabaseID: row.DatabaseID, SourcePhysicalName: row.SourcePhysicalName, PhysicalName: row.PhysicalName,
		RecoveryPeriodInDays: int(row.RecoveryPeriodInDays), EarliestAt: row.EarliestAt,
		SnapshotAt: timePointer(row.SnapshotAt), CompactThrough: timePointer(row.CompactThrough),
	}
	err := unmarshalFields(jsonReadField{row.KeySchema, &out.KeySchema}, jsonReadField{row.AttributeDefinitions, &out.AttributeDefinitions})
	return out, err
}

func (w writer) PutRecovery(v domain.RecoveryRecord) error {
	params := sqlcgen.PutRecoveryParams{
		ID: v.ID, Partition: v.Table.Partition, AccountID: v.Table.AccountID, Region: v.Table.Region, TableName: v.Table.Name,
		DatabaseID: v.DatabaseID, SourcePhysicalName: v.SourcePhysicalName, PhysicalName: v.PhysicalName,
		RecoveryPeriodInDays: int64(v.RecoveryPeriodInDays), EarliestAt: v.EarliestAt.UTC(),
		SnapshotAt: nullableTime(v.SnapshotAt), CompactThrough: nullableTime(v.CompactThrough),
	}
	if err := marshalFields(jsonWriteField{&params.KeySchema, v.KeySchema}, jsonWriteField{&params.AttributeDefinitions, v.AttributeDefinitions}); err != nil {
		return err
	}
	return w.q.PutRecovery(w.ctx, params)
}

func (w writer) DeleteRecovery(id string) error {
	return w.q.DeleteRecovery(w.ctx, id)
}

func (r reader) RecoveryChanges(query domain.RecoveryChangeQuery) ([]domain.RecoveryChange, error) {
	var sequence sql.NullInt64
	if query.ThroughSequence != nil {
		sequence = sql.NullInt64{Int64: *query.ThroughSequence, Valid: true}
	}
	rows, err := r.q.ListRecoveryChanges(r.ctx, sqlcgen.ListRecoveryChangesParams{
		RecoveryID: query.RecoveryID, AfterSequence: query.After,
		ThroughTime: sql.NullTime{Time: query.Through.UTC(), Valid: !query.Through.IsZero()}, RowLimit: rowLimit(query.Limit),
		ThroughSequence: sequence,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.RecoveryChange, len(rows))
	for i, row := range rows {
		v := domain.RecoveryChange{RecoveryID: row.RecoveryID, Sequence: row.Sequence, At: row.At}
		if err := json.Unmarshal(row.KeyData, &v.Key); err != nil {
			return nil, err
		}
		if row.ItemData != nil {
			if err := json.Unmarshal(row.ItemData, &v.Item); err != nil {
				return nil, err
			}
		}
		out[i] = v
	}
	return out, nil
}

func (w writer) AppendRecoveryChanges(changes []domain.RecoveryChange) error {
	for _, v := range changes {
		params := sqlcgen.AppendRecoveryChangeParams{RecoveryID: v.RecoveryID, At: v.At.UTC()}
		var err error
		params.KeyData, err = json.Marshal(v.Key)
		if err != nil {
			return err
		}
		if v.Item != nil {
			params.ItemData, err = json.Marshal(v.Item)
			if err != nil {
				return err
			}
		}
		if err := w.q.AppendRecoveryChange(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteRecoveryChanges(id string, through time.Time) error {
	return w.q.DeleteRecoveryChanges(w.ctx, sqlcgen.DeleteRecoveryChangesParams{RecoveryID: id, ThroughTime: through.UTC()})
}
