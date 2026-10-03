package dynamodb

import (
	"bytes"
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/dynamodb"
	streams "stackd/internal/awsapi/dynamodbstreams"
)

// deleteTTLItem prepares ownership only for an actual expiry candidate, after
// draining older records and before the external effect. Native calls never hold
// a repository transaction. The database gate excludes every other native write.
func (s *Service) deleteTTLItem(ctx context.Context, table *TableRecord, in *api.DeleteItemInput) error {
	release, err := s.engines.lockData(ctx, table.DatabaseID)
	if err != nil {
		return err
	}
	defer release()
	if err := s.prepareMutation(ctx, table.DatabaseID); err != nil {
		return err
	}
	if err := s.captureTableStreams(ctx, table); err != nil {
		return err
	}
	prepared, eligible := false, false
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Table(table.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.DatabaseID != table.DatabaseID || current.PhysicalName != table.PhysicalName || !current.TTLChangedAt.Equal(table.TTLChangedAt) || value(current.TTL.TimeToLiveStatus) != "ENABLED" {
			return nil
		}
		eligible = true
		// The scan may predate consumer enrollment. Use the live incarnation
		// and its current PITR/replica consumers while the data gate is held.
		table = &current
		if current.Data.StreamSpecification == nil || current.Data.StreamSpecification.StreamEnabled == nil || !bool(*current.Data.StreamSpecification.StreamEnabled) {
			return nil
		}
		g, err := tx.Stream(PolicyKey{Scope: table.Key.Scope, ResourceARN: value(current.Data.LatestStreamArn)})
		if err != nil {
			return err
		}
		pending := TTLDeletion{Table: table.Key, DatabaseID: table.DatabaseID, PhysicalName: table.PhysicalName, StreamARN: g.Key.ResourceARN, NativeARN: g.NativeARN, Key: in.Key, Attribute: in.ExpressionAttributeNames["#ttl"], Expiry: value(in.ExpressionAttributeValues[":seen"].N), CreatedAt: s.clock.Now()}
		if err := tx.PutTTLDeletion(pending); err != nil {
			return err
		}
		prepared = true
		return nil
	})
	if err != nil || !eligible {
		return err
	}
	defer s.engines.wake()
	if prepared {
		return s.resolveTTLDeletion(ctx, table.DatabaseID)
	}
	return s.deleteTTLWithMutation(ctx, table, in, nil)
}

// resolveTTLDeletion runs under lockData, before ingestion or another mutation.
// Reissuing the same conditional expiry is safe: a committed delete makes the
// condition false, while a pre-write crash still expires the original candidate.
// A changed incarnation never receives that retry. Its retained old stream may
// still own the original REMOVE, so drain it before retiring the pending work.
func (s *Service) resolveTTLDeletion(ctx context.Context, databaseID string) error {
	var pending TTLDeletion
	var generation StreamGeneration
	var table *TableRecord
	var retry, retained bool
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		pending, err = r.TTLDeletion(databaseID)
		if err != nil {
			return err
		}
		generation, err = r.Stream(PolicyKey{Scope: pending.Table.Scope, ResourceARN: pending.StreamARN})
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		retained = generation.DatabaseID == pending.DatabaseID && generation.PhysicalName == pending.PhysicalName && generation.NativeARN == pending.NativeARN && !streamExpired(generation, s.clock.Now())
		if !retained {
			return nil
		}
		current, err := r.Table(pending.Table)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		retry = current.DatabaseID == pending.DatabaseID && current.PhysicalName == pending.PhysicalName && value(current.Data.LatestStreamArn) == pending.StreamARN && value(current.TTL.TimeToLiveStatus) == "ENABLED" && value(current.TTL.AttributeName) == string(pending.Attribute) && generation.ClosedAt.IsZero()
		if retry {
			table = &current
		}
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if retry {
		in := api.DeleteItemInput{TableName: dataPhysical(table), Key: pending.Key, ConditionExpression: new(api.ConditionExpression("#ttl = :seen")), ExpressionAttributeNames: api.ExpressionAttributeNameMap{"#ttl": pending.Attribute}, ExpressionAttributeValues: api.ExpressionAttributeValueMap{":seen": {N: new(api.NumberAttributeValue(pending.Expiry))}}}
		if err := s.deleteTTLWithMutation(ctx, table, &in, &pending.CreatedAt); err != nil && !engineCode(err, "ConditionalCheckFailedException") && !engineCode(err, "ResourceNotFoundException") {
			// Transport/process errors are ambiguous. Keep ownership and block
			// subsequent writes until a real native result can resolve it.
			return err
		}
	}
	if retained {
		if err := s.ingestNativeStream(ctx, generation, &pending); err != nil {
			return err
		}
	}
	// A matching REMOVE cleared ownership with its record and checkpoint. No
	// record means the conditional attempt had no effect (or native retention
	// already lost it). Clear before any later customer delete can use this key.
	return s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteTTLDeletion(databaseID) })
}

// deleteTTLWithMutation runs under the data gate without preparing mutations
// recursively. Only an accepted native conditional delete has a nil postimage;
// ambiguous failures are resolved from the actual item by the capture owner.
func (s *Service) deleteTTLWithMutation(ctx context.Context, table *TableRecord, in *api.DeleteItemInput, createdAt *time.Time) error {
	if createdAt == nil {
		now := s.clock.Now()
		createdAt = &now
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		consumers, err := r.ActiveWriteConsumers(table.Key, table.PhysicalName)
		if err != nil {
			return err
		}
		table.RecoveryID = consumers.RecoveryID
		table.Replica.GroupID = consumers.ReplicationGroupID
		table.KinesisConsumers = consumers.Kinesis
		return nil
	}); err != nil {
		return err
	}
	writes := []capacityWrite{{table: table, key: in.Key}}
	pending, err := s.beginMutationWrite(ctx, writes, createdAt)
	if err != nil {
		return err
	}
	var out api.DeleteItemOutput
	if err := s.callEngine(ctx, table, "DeleteItem", in, &out); err != nil {
		if captureErr := s.failMutationWrite(ctx, table.DatabaseID, err); captureErr != nil {
			// Do not let a benign conditional failure hide a capture-store error.
			return captureErr
		}
		return err
	}
	return s.finishMutationWrite(ctx, pending, writes, nil)
}

func ttlRecordMatches(pending *TTLDeletion, record streams.Record) bool {
	if pending == nil || value(record.EventName) != "REMOVE" || record.Dynamodb == nil || len(record.Dynamodb.Keys) != len(pending.Key) {
		return false
	}
	for name, expected := range pending.Key {
		actual, ok := record.Dynamodb.Keys[streams.AttributeName(name)]
		if !ok || (expected.S != nil) != (actual.S != nil) || (expected.N != nil) != (actual.N != nil) || (expected.B != nil) != (actual.B != nil) || value(expected.S) != value(actual.S) || value(expected.N) != value(actual.N) || !bytes.Equal(expected.B, actual.B) {
			return false
		}
	}
	return true
}

func cloneTTLDeletion(v TTLDeletion) TTLDeletion {
	v.Key = api.CloneKey(v.Key)
	return v
}

func (r memoryReader) TTLDeletion(databaseID string) (TTLDeletion, error) {
	if err := r.tx.Check(false); err != nil {
		return TTLDeletion{}, err
	}
	v, ok := r.s.ttlDeletions[databaseID]
	if !ok {
		return TTLDeletion{}, ErrNotFound
	}
	return cloneTTLDeletion(v), nil
}

func (w memoryWriter) PutTTLDeletion(v TTLDeletion) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.ttlDeletions[v.DatabaseID] = cloneTTLDeletion(v)
	return nil
}

func (w memoryWriter) DeleteTTLDeletion(databaseID string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.ttlDeletions, databaseID)
	return nil
}
