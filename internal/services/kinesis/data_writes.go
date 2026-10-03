package kinesis

import (
	"context"
	"time"

	engine "stackd/engine/kinesis"
	api "stackd/internal/awsapi/kinesis"
)

func recordEncryption(stream StreamRecord) *api.EncryptionType {
	if value(stream.Data.EncryptionType) == string(api.EncryptionTypeKMS) {
		return new(api.EncryptionTypeKMS)
	}
	return nil
}

func (s *Service) putRecord(ctx context.Context, in *api.PutRecordInput) (*api.PutRecordOutput, error) {
	if in == nil {
		return nil, failure("ValidationException", "Request must not be null.")
	}
	if err := validateRecord(in.Data, in.PartitionKey, in.ExplicitHashKey); err != nil {
		return nil, err
	}
	if in.SequenceNumberForOrdering != nil && !decimalCoordinate.MatchString(value(in.SequenceNumberForOrdering)) {
		return nil, failure("ValidationException", "SequenceNumberForOrdering must be a decimal sequence number.")
	}
	if isDryRun(in.DryRun) {
		stream, err := s.dryRunStream(ctx, value(in.StreamName), value(in.StreamARN), "PutRecord")
		if err != nil {
			return nil, err
		}
		if err := validateRecordSize(stream, in.Data, value(in.PartitionKey)); err != nil {
			return nil, err
		}
		return nil, dryRunResult("PutRecord")
	}
	stream, shards, log, release, err := s.openStream(ctx, value(in.StreamName), value(in.StreamARN), "PutRecord")
	if err != nil {
		return nil, err
	}
	defer release()
	if err := validateRecordSize(stream, in.Data, value(in.PartitionKey)); err != nil {
		return nil, err
	}
	routes, err := shardRoutes(shards)
	if err != nil {
		return nil, err
	}
	index, err := routeRecord(routes, value(in.PartitionKey), in.ExplicitHashKey)
	if err != nil {
		return nil, err
	}
	shard := routes[index].shard
	size := len(in.Data) + len(value(in.PartitionKey))
	if err := s.admitWrite(ctx, stream, shard, size); err != nil {
		return nil, err
	}
	records := []engine.Record{{Timestamp: s.clock.Now().UTC().Truncate(time.Millisecond), PartitionKey: value(in.PartitionKey), Data: in.Data}}
	if err := s.encryptRecords(ctx, stream, records); err != nil {
		return nil, err
	}
	offset, err := log.Append(ctx, shard.Key.Partition, records)
	if err != nil {
		return nil, err
	}
	s.dataSample(ctx, "IncomingRecords", shard.Key.ID(), 1)
	s.dataSample(ctx, "IncomingBytes", shard.Key.ID(), float64(size))
	s.dataSample(ctx, "PutRecord.Bytes", "", float64(size))
	s.dataSample(ctx, "PutRecord.Success", "", 1)
	return &api.PutRecordOutput{ShardId: new(api.ShardId(shard.Key.ID())), SequenceNumber: new(sequenceFor(shard).number(offset)), EncryptionType: recordEncryption(stream)}, nil
}

type nativeWriteBatch struct {
	records []engine.Record
	indices []int
}

func (s *Service) putRecords(ctx context.Context, in *api.PutRecordsInput) (*api.PutRecordsOutput, error) {
	if in == nil || len(in.Records) < 1 || len(in.Records) > 500 {
		return nil, failure("ValidationException", "Records must contain between 1 and 500 entries.")
	}
	total := 0
	for _, entry := range in.Records {
		if err := validateRecord(entry.Data, entry.PartitionKey, entry.ExplicitHashKey); err != nil {
			return nil, err
		}
		total += len(entry.Data) + len(value(entry.PartitionKey))
	}
	if total > maxDataBytes {
		return nil, failure("InvalidArgumentException", "Records must not exceed 10485760 bytes in total.")
	}
	if isDryRun(in.DryRun) {
		stream, err := s.dryRunStream(ctx, value(in.StreamName), value(in.StreamARN), "PutRecords")
		if err != nil {
			return nil, err
		}
		for _, entry := range in.Records {
			if err := validateRecordSize(stream, entry.Data, value(entry.PartitionKey)); err != nil {
				return nil, err
			}
		}
		return nil, dryRunResult("PutRecords")
	}
	stream, shards, log, release, err := s.openStream(ctx, value(in.StreamName), value(in.StreamARN), "PutRecords")
	if err != nil {
		return nil, err
	}
	defer release()
	routes, err := shardRoutes(shards)
	if err != nil {
		return nil, err
	}
	records := make([]engine.Record, len(in.Records))
	targets := make([]int, len(in.Records))
	arrival := s.clock.Now().UTC().Truncate(time.Millisecond)
	// Validate every member before admitting or appending any of them.
	for i, entry := range in.Records {
		if err := validateRecordSize(stream, entry.Data, value(entry.PartitionKey)); err != nil {
			return nil, err
		}
		targets[i], err = routeRecord(routes, value(entry.PartitionKey), entry.ExplicitHashKey)
		if err != nil {
			return nil, err
		}
		records[i] = engine.Record{Timestamp: arrival, PartitionKey: value(entry.PartitionKey), Data: entry.Data}
	}
	if err := s.encryptRecords(ctx, stream, records); err != nil {
		return nil, err
	}
	out := &api.PutRecordsOutput{Records: make(api.PutRecordsResultEntryList, len(records)), EncryptionType: recordEncryption(stream)}
	batches := make([]nativeWriteBatch, len(routes))
	failed, throttled, successfulBytes := 0, 0, 0
	reject := func(index int, err error) {
		rejected := wireError(err)
		code := rejected.Code
		if code != "ProvisionedThroughputExceededException" {
			code = "InternalFailure"
		} else {
			throttled++
		}
		out.Records[index] = api.PutRecordsResultEntry{ErrorCode: new(api.ErrorCode(code)), ErrorMessage: new(api.ErrorMessage(rejected.Message))}
		failed++
	}
	for i, record := range records {
		target := targets[i]
		entry := in.Records[i]
		if err := s.admitWrite(ctx, stream, routes[target].shard, len(entry.Data)+len(record.PartitionKey)); err != nil {
			reject(i, err)
			continue
		}
		batches[target].records = append(batches[target].records, record)
		batches[target].indices = append(batches[target].indices, i)
	}
	for i, batch := range batches {
		if len(batch.records) == 0 {
			continue
		}
		shard := routes[i].shard
		offset, err := log.Append(ctx, shard.Key.Partition, batch.records)
		if err != nil {
			for _, index := range batch.indices {
				reject(index, err)
			}
			continue
		}
		sequence := sequenceFor(shard)
		shardID := shard.Key.ID()
		s.dataSample(ctx, "IncomingRecords", shardID, float64(len(batch.records)))
		for j, index := range batch.indices {
			out.Records[index] = api.PutRecordsResultEntry{ShardId: new(api.ShardId(shardID)), SequenceNumber: new(sequence.number(offset + int64(j)))}
			size := len(in.Records[index].Data) + len(value(in.Records[index].PartitionKey))
			successfulBytes += size
			s.dataSample(ctx, "IncomingBytes", shardID, float64(size))
		}
	}
	out.FailedRecordCount = new(api.PositiveIntegerObject(failed))
	s.dataSample(ctx, "PutRecords.Bytes", "", float64(successfulBytes))
	s.dataSample(ctx, "PutRecords.TotalRecords", "", float64(len(records)))
	s.dataSample(ctx, "PutRecords.SuccessfulRecords", "", float64(len(records)-failed))
	s.dataSample(ctx, "PutRecords.FailedRecords", "", float64(failed-throttled))
	s.dataSample(ctx, "PutRecords.ThrottledRecords", "", float64(throttled))
	if failed < len(records) {
		s.dataSample(ctx, "PutRecords.Success", "", 1)
	} else {
		s.dataSample(ctx, "PutRecords.Success", "", 0)
	}
	return out, nil
}
