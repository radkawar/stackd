package dynamodb

import (
	"errors"
	"slices"

	api "stackd/internal/awsapi/dynamodb"
)

func cloneMutationCapture(v MutationCapture) MutationCapture {
	v.Sources = slices.Clone(v.Sources)
	for i := range v.Sources {
		source := &v.Sources[i]
		source.KeySchema = api.CloneKeySchema(source.KeySchema)
		source.Kinesis = slices.Clone(source.Kinesis)
		source.Items = slices.Clone(source.Items)
		for j := range source.Items {
			source.Items[j].Key = api.CloneKey(source.Items[j].Key)
			source.Items[j].Before = api.CloneAttributeMap(source.Items[j].Before)
		}
	}
	return v
}

func (r memoryReader) ActiveWriteConsumers(key TableKey, physicalName string) (WriteConsumers, error) {
	if err := r.tx.Check(false); err != nil {
		return WriteConsumers{}, err
	}
	table, ok := r.s.tables[key]
	if !ok || table.PhysicalName != physicalName {
		return WriteConsumers{}, nil
	}
	destinations, err := r.KinesisDestinations()
	if err != nil {
		return WriteConsumers{}, err
	}
	return WriteConsumers{RecoveryID: table.RecoveryID, ReplicationGroupID: table.Replica.GroupID, Kinesis: kinesisConsumers(destinations, physicalName)}, nil
}

func (r memoryReader) MutationCapture(databaseID string) (MutationCapture, error) {
	if err := r.tx.Check(false); err != nil {
		return MutationCapture{}, err
	}
	v, ok := r.s.mutationCaptures[databaseID]
	if !ok {
		return MutationCapture{}, ErrNotFound
	}
	return cloneMutationCapture(v), nil
}

func (w memoryWriter) CreateMutationCapture(v MutationCapture) (int64, error) {
	if err := w.tx.Check(true); err != nil {
		return 0, err
	}
	if _, ok := w.s.mutationCaptures[v.DatabaseID]; ok {
		return 0, errors.New("DynamoDB mutation capture already exists for database")
	}
	w.s.mutationVersion++
	v.Version = w.s.mutationVersion
	w.s.mutationCaptures[v.DatabaseID] = cloneMutationCapture(v)
	return v.Version, nil
}

func (w memoryWriter) DeleteMutationCapture(databaseID string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.mutationCaptures, databaseID)
	return nil
}
