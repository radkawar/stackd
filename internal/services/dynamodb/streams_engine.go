package dynamodb

import (
	"context"
	"errors"
	"fmt"
	engine "stackd/engine/dynamodb"
	tableapi "stackd/internal/awsapi/dynamodb"
	api "stackd/internal/awsapi/dynamodbstreams"
	"stackd/internal/awscatalog"
	"time"
)

const streamLabelLayout = "2006-01-02T15:04:05.000"

// assignStreamIdentity publishes the public identity at control admission.
// Native activation later binds that identity to the engine's stream.
func (s *Service) assignStreamIdentity(r Reader, table *TableRecord) error {
	now := s.clock.Now().UTC()
	for {
		label := now.Format(streamLabelLayout)
		resource := table.Key.ARN() + "/stream/" + label
		_, err := r.Stream(PolicyKey{Scope: table.Key.Scope, ResourceARN: resource})
		if errors.Is(err, ErrNotFound) {
			table.Data.LatestStreamArn = new(tableapi.StreamArn(resource))
			table.Data.LatestStreamLabel = new(tableapi.String(label))
			return nil
		}
		if err != nil {
			return err
		}
		// Retained generations cannot collide when service time is frozen.
		now = now.Add(time.Millisecond)
	}
}

// observeStream joins table publication. Native effects happened before this
// callback: publishing ACTIVE and publishing its stream owner are atomic.
func (s *Service) observeStream(tx Transaction, table *TableRecord, native *tableapi.TableDescription) error {
	generations, err := tx.Streams()
	if err != nil {
		return err
	}
	enabled := native.StreamSpecification != nil && native.StreamSpecification.StreamEnabled != nil && bool(*native.StreamSpecification.StreamEnabled)
	nativeARN := value(native.LatestStreamArn)
	found := false
	for _, g := range generations {
		if g.DatabaseID != table.DatabaseID || g.PhysicalName != table.PhysicalName {
			continue
		}
		if g.NativeARN == nativeARN {
			table.Data.LatestStreamArn = new(tableapi.StreamArn(g.Key.ResourceARN))
			table.Data.LatestStreamLabel = new(tableapi.String(g.Label))
			if enabled {
				found = true
				continue
			}
		}
		if g.ClosedAt.IsZero() {
			g.ClosedAt = s.clock.Now()
			if err := tx.PutStream(g); err != nil {
				return err
			}
		}
	}
	if !enabled || found {
		return nil
	}
	if nativeARN == "" {
		return errors.New("native enabled stream omitted ARN")
	}
	label := value(table.Data.LatestStreamLabel)
	createdAt, err := time.Parse(streamLabelLayout, label)
	if err != nil {
		return fmt.Errorf("decode retained stream creation time: %w", err)
	}
	g := StreamGeneration{Key: PolicyKey{Scope: table.Key.Scope, ResourceARN: value(table.Data.LatestStreamArn)}, Table: table.Key, DatabaseID: table.DatabaseID, PhysicalName: table.PhysicalName, NativeARN: nativeARN, Label: label, CreatedAt: createdAt, ViewType: api.StreamViewType(value(native.StreamSpecification.StreamViewType))}
	for _, k := range table.Data.KeySchema {
		g.KeySchema = append(g.KeySchema, api.KeySchemaElement{AttributeName: new(api.KeySchemaAttributeName(value(k.AttributeName))), KeyType: new(api.KeyType(value(k.KeyType)))})
	}
	if err := tx.PutStream(g); err != nil {
		return err
	}
	table.Data.LatestStreamArn = new(tableapi.StreamArn(g.Key.ResourceARN))
	table.Data.LatestStreamLabel = new(tableapi.String(g.Label))
	return nil
}

// The caller holds lockData and has resolved pending TTL work for the database.
func (s *Service) captureTableStreams(ctx context.Context, table *TableRecord) error {
	var generations []StreamGeneration
	if err := s.repository.View(ctx, func(r Reader) error { var err error; generations, err = r.Streams(); return err }); err != nil {
		return err
	}
	for _, g := range generations {
		if g.DatabaseID == table.DatabaseID && g.PhysicalName == table.PhysicalName && !streamExpired(g, s.clock.Now()) {
			if err := s.ingestNativeStream(ctx, g, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Service) streamNative(ctx context.Context, g StreamGeneration, action string, in, out any) error {
	db, err := s.engines.database(ctx, engine.Specification{ID: g.DatabaseID, Partition: g.Table.Partition, AccountID: g.Table.AccountID, Region: g.Table.Region})
	if err != nil {
		return err
	}
	model, _ := awscatalog.LookupService("dynamodbstreams")
	return nativeCall(ctx, db, model, action, in, out, nil)
}

func (s *Service) nativeStreamIterator(ctx context.Context, g StreamGeneration, sh StreamShard, horizon bool) (*api.ShardIterator, error) {
	kind := api.ShardIteratorTypeTRIM_HORIZON
	in := &api.GetShardIteratorInput{StreamArn: new(api.StreamArn(g.NativeARN)), ShardId: new(api.ShardId(sh.ID)), ShardIteratorType: &kind}
	if !horizon && sh.Checkpoint != "" {
		kind = api.ShardIteratorTypeAFTER_SEQUENCE_NUMBER
		in.SequenceNumber = new(api.SequenceNumber(sh.Checkpoint))
	}
	var out api.GetShardIteratorOutput
	err := s.streamNative(ctx, g, "GetShardIterator", in, &out)
	if in.SequenceNumber != nil && engineCode(err, "TrimmedDataAccessException") {
		// Native retention uses host time, not the public virtual clock. Resume
		// at the documented oldest untrimmed record and deduplicate against
		// the durable checkpoint; already copied public records remain intact.
		// TODO: Comeback — native records lost before capture during downtime
		// longer than native retention cannot be reconstructed from snapshots.
		kind = api.ShardIteratorTypeTRIM_HORIZON
		in.SequenceNumber = nil
		err = s.streamNative(ctx, g, "GetShardIterator", in, &out)
	}
	return out.ShardIterator, err
}

// ingestStream copies native records, never derives changes from table images.
// A failed commit leaves the checkpoint untouched and replay is idempotent.
func (s *Service) ingestStream(ctx context.Context, g StreamGeneration) error {
	if err := s.prepareMutation(ctx, g.DatabaseID); err != nil {
		return err
	}
	return s.ingestNativeStream(ctx, g, nil)
}

func (s *Service) ingestNativeStream(ctx context.Context, g StreamGeneration, pending *TTLDeletion) error {
	var shards []StreamShard
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		g, err = r.Stream(g.Key)
		if err != nil {
			return err
		}
		if streamExpired(g, s.clock.Now()) {
			return ErrNotFound
		}
		shards, err = r.StreamShards(g.Key.ResourceARN)
		return err
	}); err != nil {
		return err
	}
	if !g.ClosedAt.IsZero() && len(shards) > 0 {
		drained := true
		for _, sh := range shards {
			drained = drained && sh.Drained
		}
		if drained {
			return nil
		}
	}
	byID := make(map[string]StreamShard, len(shards))
	for _, sh := range shards {
		byID[sh.ID] = sh
	}
	var after *api.ShardId
	for {
		var out api.DescribeStreamOutput
		if err := s.streamNative(ctx, g, "DescribeStream", &api.DescribeStreamInput{StreamArn: new(api.StreamArn(g.NativeARN)), ExclusiveStartShardId: after}, &out); err != nil {
			return err
		}
		if out.StreamDescription == nil {
			return errors.New("native DescribeStream omitted description")
		}
		for _, native := range out.StreamDescription.Shards {
			id := value(native.ShardId)
			if id == "" {
				return errors.New("native stream omitted shard ID")
			}
			sh := byID[id]
			sh.StreamARN = g.Key.ResourceARN
			sh.ID = id
			sh.ParentID = value(native.ParentShardId)
			if native.SequenceNumberRange != nil {
				sh.Start = value(native.SequenceNumberRange.StartingSequenceNumber)
				sh.End = value(native.SequenceNumberRange.EndingSequenceNumber)
			}
			byID[id] = sh
		}
		after = out.StreamDescription.LastEvaluatedShardId
		if after == nil {
			break
		}
	}
	for _, sh := range byID {
		if sh.Drained {
			continue
		}
		iterator, err := s.nativeStreamIterator(ctx, g, sh, false)
		if err != nil {
			return err
		}
		recovered := false
		for iterator != nil {
			var out api.GetRecordsOutput
			if err := s.streamNative(ctx, g, "GetRecords", &api.GetRecordsInput{ShardIterator: iterator}, &out); err != nil {
				if !recovered && engineCode(err, "TrimmedDataAccessException") {
					// Trimming can race iterator acquisition. Restart from the
					// native horizon once; never spin on repeated native errors.
					iterator, err = s.nativeStreamIterator(ctx, g, sh, true)
					if err != nil {
						return err
					}
					recovered = true
					continue
				}
				return err
			}
			now := s.clock.Now()
			entries := make([]StreamEntry, 0, len(out.Records))
			completedTTL := false
			for _, record := range out.Records {
				if record.Dynamodb == nil || value(record.Dynamodb.SequenceNumber) == "" {
					return fmt.Errorf("native shard %s omitted sequence", sh.ID)
				}
				sequence := value(record.Dynamodb.SequenceNumber)
				if sh.Checkpoint != "" && compareSequence(sequence, sh.Checkpoint) <= 0 {
					continue
				}
				record.AwsRegion = new(api.String(g.Table.Region))
				createdAt := now
				if !completedTTL && ttlRecordMatches(pending, record) {
					createdAt = pending.CreatedAt
					record.UserIdentity = &api.Identity{Type: new(api.String("Service")), PrincipalId: new(api.String("dynamodb.amazonaws.com"))}
					completedTTL = true
				}
				record.Dynamodb.ApproximateCreationDateTime = &createdAt
				entries = append(entries, StreamEntry{StreamARN: g.Key.ResourceARN, ShardID: sh.ID, Sequence: sequence, CreatedAt: createdAt, Data: record})
				sh.Checkpoint = sequence
			}
			sh.Drained = out.NextShardIterator == nil || len(out.Records) == 0 && (!g.ClosedAt.IsZero() || sh.End != "")
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if _, err := tx.Stream(g.Key); err != nil {
					return err
				}
				current, err := getStreamShard(tx, g.Key.ResourceARN, sh.ID)
				if err != nil && !errors.Is(err, ErrNotFound) {
					return err
				}
				if compareSequence(current.TrimmedThrough, sh.TrimmedThrough) > 0 {
					sh.TrimmedThrough = current.TrimmedThrough
				}
				for _, entry := range entries {
					if err := tx.PutStreamEntry(entry); err != nil {
						return err
					}
				}
				if completedTTL {
					if err := tx.DeleteTTLDeletion(pending.DatabaseID); err != nil {
						return err
					}
				}
				return tx.PutStreamShard(sh)
			}); err != nil {
				return err
			}
			if completedTTL {
				pending = nil
			}
			if len(out.Records) == 0 || sh.Drained {
				break
			}
			iterator = out.NextShardIterator
		}
	}
	return nil
}

// maintainStreams is the recovery/retirement owner. Deadlines use the service
// clock; host polling only drains native data before its own retention can trim.
func (s *Service) maintainStreams(ctx context.Context) (time.Time, bool, error) {
	var generations []StreamGeneration
	if err := s.repository.View(ctx, func(r Reader) error { var err error; generations, err = r.Streams(); return err }); err != nil {
		return time.Time{}, true, err
	}
	var deadline time.Time
	poll := false
	now := s.clock.Now()
	var ingestErr error
	for _, g := range generations {
		if !streamExpired(g, now) {
			release, err := s.engines.lockData(ctx, g.DatabaseID)
			if err != nil {
				return deadline, true, err
			}
			err = s.ingestStream(ctx, g)
			release()
			ingestErr = errors.Join(ingestErr, err)
			poll = true
			if !g.ClosedAt.IsZero() {
				at := g.ClosedAt.Add(24 * time.Hour)
				if deadline.IsZero() || at.Before(deadline) {
					deadline = at
				}
			}
		}
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		for _, g := range generations {
			if streamExpired(g, now) {
				if err := tx.DeleteStream(g.Key); err != nil {
					return err
				}
				if err := tx.DeletePolicy(g.Key); err != nil {
					return err
				}
				continue
			}
			oldest, err := tx.TrimStreamEntries(g.Key.ResourceARN, now.Add(-24*time.Hour))
			if err != nil {
				return err
			}
			if !oldest.IsZero() {
				at := oldest.Add(24 * time.Hour)
				if deadline.IsZero() || at.Before(deadline) {
					deadline = at
				}
			}
		}
		databases, err := tx.Databases()
		if err != nil {
			return err
		}
		retained, err := tx.Streams()
		if err != nil {
			return err
		}
		for _, db := range databases {
			if db.Retiring {
				continue
			}
			tables, err := tx.Tables(TableQuery{Scope: Scope{db.Spec.Partition, db.Spec.AccountID, db.Spec.Region}})
			if err != nil {
				return err
			}
			owned := false
			for _, table := range tables {
				if table.DatabaseID == db.Spec.ID {
					owned = true
					break
				}
			}
			for _, g := range retained {
				if g.DatabaseID == db.Spec.ID {
					owned = true
					break
				}
			}
			if !owned {
				owned, err = tx.HasDatabaseBackups(db.Spec.ID)
				if err != nil {
					return err
				}
			}
			if !owned {
				recoveries, err := tx.Recoveries(db.Spec.ID)
				if err != nil {
					return err
				}
				owned = len(recoveries) != 0
			}
			if !owned {
				bootstraps, err := tx.ReplicaBootstraps(db.Spec.ID)
				if err != nil {
					return err
				}
				owned = len(bootstraps) != 0
			}
			if !owned {
				db.Retiring = true
				if err := tx.PutDatabase(db); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return deadline, poll, errors.Join(ingestErr, err)
}
