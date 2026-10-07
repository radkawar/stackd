package dynamodb

import (
	"database/sql"
	"errors"

	api "stackd/internal/awsapi/dynamodb"
	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
)

func (r reader) Table(k domain.TableKey) (domain.TableRecord, error) {
	row, err := r.q.GetTable(r.ctx, sqlcgen.GetTableParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.TableRecord{}, missing(err)
	}
	return r.table(row)
}

func (r reader) Tables(q domain.TableQuery) ([]domain.TableRecord, error) {
	rows, err := r.q.ListTables(r.ctx, sqlcgen.ListTablesParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, AfterName: q.After, RowLimit: rowLimit(q.Limit)})
	if err != nil {
		return nil, err
	}
	return r.tables(rows)
}

func (r reader) PendingTables() ([]domain.TableRecord, error) {
	rows, err := r.q.ListPendingTables(r.ctx)
	if err != nil {
		return nil, err
	}
	return r.tables(rows)
}

func (r reader) TTLTables() ([]domain.TableRecord, error) {
	rows, err := r.q.ListTTLTables(r.ctx)
	if err != nil {
		return nil, err
	}
	return r.tables(rows)
}

func (r reader) tables(rows []sqlcgen.DynamodbTable) ([]domain.TableRecord, error) {
	out := make([]domain.TableRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.table(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) table(row sqlcgen.DynamodbTable) (domain.TableRecord, error) {
	k := domain.TableKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name}
	out := domain.TableRecord{Key: k, DatabaseID: row.DatabaseID, PhysicalName: row.PhysicalName,
		Owner:        domain.ResourceOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken},
		TTL:          api.TimeToLiveDescription{AttributeName: stringPointer[api.TimeToLiveAttributeName](row.TtlAttributeName), TimeToLiveStatus: stringPointer[api.TimeToLiveStatus](row.TtlStatus)},
		TTLChangedAt: row.TtlChangedAt, TTLNextScan: row.TtlNextScan,
		MetricsNextAt: row.MetricsNextAt,
		RecoveryID:    row.RecoveryID, RestoreRecoveryID: row.RestoreRecoveryID,
		RestoreRecoverySequence: row.RestoreRecoverySequence,
		Replica: domain.ReplicaState{GroupID: row.ReplicaGroupID, Cursor: row.ReplicaCursor,
			LastSourceAt: row.ReplicaLastSourceAt.UTC(), UnauthorizedAt: timePointer(row.ReplicaUnauthorizedAt), SettingsPending: row.ReplicaSettingsPending},
	}
	var err error
	out.Data, err = tableData(row)
	if err != nil {
		return out, err
	}
	create, err := r.q.GetPendingCreate(r.ctx, sqlcgen.GetPendingCreateParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err == nil {
		d, err := pendingCreateData(create)
		if err != nil {
			return out, err
		}
		if create.TagsPresent {
			tags, err := r.q.ListCreateTags(r.ctx, sqlcgen.ListCreateTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
			if err != nil {
				return out, err
			}
			d.Tags = make(api.TagList, len(tags))
			for i, tag := range tags {
				d.Tags[i] = api.Tag{Key: stringPointer[api.TagKeyString](tag.Key), Value: stringPointer[api.TagValueString](tag.Value)}
			}
		}
		out.PendingCreate = &d
	} else if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	update, err := r.q.GetPendingUpdate(r.ctx, sqlcgen.GetPendingUpdateParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err == nil {
		d, err := pendingUpdateData(update)
		if err != nil {
			return out, err
		}
		out.PendingUpdate = &d
		out.UpdateAcceptedAt = update.AcceptedAt
	} else if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	return out, nil
}

func (w writer) PutTable(v domain.TableRecord) error {
	k := v.Key
	params, err := tableParams(k, &v.Data)
	if err != nil {
		return err
	}
	params.DatabaseID, params.PhysicalName = v.DatabaseID, v.PhysicalName
	params.TtlAttributeName, params.TtlStatus = nullableString(v.TTL.AttributeName), nullableString(v.TTL.TimeToLiveStatus)
	params.TtlChangedAt, params.TtlNextScan = v.TTLChangedAt, v.TTLNextScan
	params.MetricsNextAt = v.MetricsNextAt
	params.RecoveryID, params.RestoreRecoveryID = v.RecoveryID, v.RestoreRecoveryID
	params.RestoreRecoverySequence = v.RestoreRecoverySequence
	if err := w.q.PutTable(w.ctx, params); err != nil {
		return err
	}
	if err := w.q.SetTableOwner(w.ctx, sqlcgen.SetTableOwnerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token}); err != nil {
		return err
	}
	if err := w.q.SetTableReplica(w.ctx, sqlcgen.SetTableReplicaParams{
		ReplicaGroupID: v.Replica.GroupID, ReplicaCursor: v.Replica.Cursor,
		ReplicaLastSourceAt: v.Replica.LastSourceAt.UTC(), ReplicaUnauthorizedAt: nullableTime(v.Replica.UnauthorizedAt),
		ReplicaSettingsPending: v.Replica.SettingsPending,
		Partition:              k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
	}); err != nil {
		return err
	}
	if err := w.q.DeletePendingCreate(w.ctx, sqlcgen.DeletePendingCreateParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	if v.PendingCreate != nil {
		params, err := pendingCreateParams(k, v.PendingCreate)
		if err != nil {
			return err
		}
		if err := w.q.PutPendingCreate(w.ctx, params); err != nil {
			return err
		}
		for i, tag := range v.PendingCreate.Tags {
			if err := w.q.PutCreateTag(w.ctx, sqlcgen.PutCreateTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
				return err
			}
		}
	}
	if err := w.q.DeletePendingUpdate(w.ctx, sqlcgen.DeletePendingUpdateParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	if v.PendingUpdate != nil {
		params, err := pendingUpdateParams(k, v.PendingUpdate)
		if err != nil {
			return err
		}
		params.AcceptedAt = v.UpdateAcceptedAt
		if err := w.q.PutPendingUpdate(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteTable(k domain.TableKey) error {
	if err := w.q.DeleteTable(w.ctx, sqlcgen.DeleteTableParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	return w.q.DeleteTagSet(w.ctx, sqlcgen.DeleteTagSetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
