package dynamodb

import (
	"database/sql"
	"encoding/json"
	"errors"

	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
)

func (r reader) ActiveWriteConsumers(k domain.TableKey, physicalName string) (domain.WriteConsumers, error) {
	row, err := r.q.GetActiveWriteConsumers(r.ctx, sqlcgen.GetActiveWriteConsumersParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, PhysicalName: physicalName,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.WriteConsumers{}, nil
	}
	if err != nil {
		return domain.WriteConsumers{}, err
	}
	consumers, err := r.q.ListActiveKinesisConsumers(r.ctx, physicalName)
	if err != nil {
		return domain.WriteConsumers{}, err
	}
	out := domain.WriteConsumers{RecoveryID: row.RecoveryID, ReplicationGroupID: row.ReplicaGroupID}
	for _, consumer := range consumers {
		out.Kinesis = append(out.Kinesis, domain.KinesisConsumer{ID: consumer.ID, StreamARN: consumer.StreamArn, Precision: consumer.Precision, CaptureUntil: consumer.CaptureUntil.UTC()})
	}
	return out, nil
}

func (r reader) MutationCapture(databaseID string) (domain.MutationCapture, error) {
	row, err := r.q.GetMutationCapture(r.ctx, databaseID)
	if err != nil {
		return domain.MutationCapture{}, missing(err)
	}
	sources, err := r.q.ListMutationSources(r.ctx, databaseID)
	if err != nil {
		return domain.MutationCapture{}, err
	}
	out := domain.MutationCapture{Version: row.Version, DatabaseID: row.DatabaseID, At: row.At.UTC(), Sources: make([]domain.MutationSource, len(sources)), ParentEventID: row.ParentEventID, Transactional: row.Transactional, TTL: row.Ttl}
	for i, source := range sources {
		v := domain.MutationSource{
			Table:          domain.TableKey{Scope: domain.Scope{Partition: source.Partition, AccountID: source.AccountID, Region: source.Region}, Name: source.TableName},
			PhysicalName:   source.PhysicalName,
			WriteConsumers: domain.WriteConsumers{RecoveryID: source.RecoveryID, ReplicationGroupID: source.ReplicationGroupID},
		}
		consumers, err := r.q.ListMutationKinesisConsumers(r.ctx, sqlcgen.ListMutationKinesisConsumersParams{DatabaseID: databaseID, SourcePosition: source.Position})
		if err != nil {
			return domain.MutationCapture{}, err
		}
		for _, consumer := range consumers {
			v.Kinesis = append(v.Kinesis, domain.KinesisConsumer{ID: consumer.DestinationID, StreamARN: consumer.StreamArn, Precision: consumer.Precision, CaptureUntil: consumer.CaptureUntil.UTC()})
		}
		if err := json.Unmarshal(source.KeySchema, &v.KeySchema); err != nil {
			return domain.MutationCapture{}, err
		}
		items, err := r.q.ListMutationItems(r.ctx, sqlcgen.ListMutationItemsParams{DatabaseID: databaseID, SourcePosition: source.Position})
		if err != nil {
			return domain.MutationCapture{}, err
		}
		v.Items = make([]domain.MutationItem, len(items))
		for j, item := range items {
			v.Items[j].ReplicaSequence = item.ReplicaSequence
			if err := json.Unmarshal(item.KeyData, &v.Items[j].Key); err != nil {
				return domain.MutationCapture{}, err
			}
			if item.BeforeData != nil {
				if err := json.Unmarshal(item.BeforeData, &v.Items[j].Before); err != nil {
					return domain.MutationCapture{}, err
				}
			}
		}
		out.Sources[i] = v
	}
	return out, nil
}

func (w writer) CreateMutationCapture(v domain.MutationCapture) (int64, error) {
	version, err := w.q.CreateMutationCapture(w.ctx, sqlcgen.CreateMutationCaptureParams{DatabaseID: v.DatabaseID, At: v.At.UTC(), ParentEventID: v.ParentEventID, Transactional: v.Transactional, Ttl: v.TTL})
	if err != nil {
		return 0, err
	}
	for i, source := range v.Sources {
		params := sqlcgen.PutMutationSourceParams{
			DatabaseID: v.DatabaseID, Position: int64(i), Partition: source.Table.Partition,
			AccountID: source.Table.AccountID, Region: source.Table.Region, TableName: source.Table.Name,
			PhysicalName: source.PhysicalName, RecoveryID: source.RecoveryID, ReplicationGroupID: source.ReplicationGroupID,
		}
		params.KeySchema, err = json.Marshal(source.KeySchema)
		if err != nil {
			return 0, err
		}
		if err := w.q.PutMutationSource(w.ctx, params); err != nil {
			return 0, err
		}
		for _, consumer := range source.Kinesis {
			if err := w.q.PutMutationKinesisConsumer(w.ctx, sqlcgen.PutMutationKinesisConsumerParams{DatabaseID: v.DatabaseID, SourcePosition: int64(i), DestinationID: consumer.ID, StreamArn: consumer.StreamARN, Precision: consumer.Precision, CaptureUntil: consumer.CaptureUntil.UTC()}); err != nil {
				return 0, err
			}
		}
		for j, item := range source.Items {
			params := sqlcgen.PutMutationItemParams{DatabaseID: v.DatabaseID, SourcePosition: int64(i), Position: int64(j), ReplicaSequence: item.ReplicaSequence}
			params.KeyData, err = json.Marshal(item.Key)
			if err != nil {
				return 0, err
			}
			if item.Before != nil {
				params.BeforeData, err = json.Marshal(item.Before)
				if err != nil {
					return 0, err
				}
			}
			if err := w.q.PutMutationItem(w.ctx, params); err != nil {
				return 0, err
			}
		}
	}
	return version, nil
}

func (w writer) DeleteMutationCapture(databaseID string) error {
	return w.q.DeleteMutationCapture(w.ctx, databaseID)
}
