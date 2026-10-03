package firehose

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/firehose"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const (
	maxRecordBytes = 1024000
	maxBatchBytes  = 4194304
)

func registerData(s *Service) {
	registerControl(s, "PutRecord", s.putRecord)
	registerControl(s, "PutRecordBatch", s.putRecordBatch)
}

// PutRecord is the same authorized, retained command used by the HTTP frontend.
func (s *Service) PutRecord(ctx context.Context, in *api.PutRecordInput) (*api.PutRecordOutput, *awswire.Error) {
	return runCommand(s, ctx, "PutRecord", in, s.putRecord)
}

// PutRecordBatch shares the frontend's batch authorization, atomic admission
// and audit outcome with service producers such as SNS.
func (s *Service) PutRecordBatch(ctx context.Context, in *api.PutRecordBatchInput) (*api.PutRecordBatchOutput, *awswire.Error) {
	return runCommand(s, ctx, "PutRecordBatch", in, s.putRecordBatch)
}

func (s *Service) putRecord(ctx context.Context, tx Transaction, in *api.PutRecordInput) (*api.PutRecordOutput, error) {
	if in == nil || in.Record == nil {
		return nil, failure("ValidationException", "Record must not be null.")
	}
	if len(in.Record.Data) > maxRecordBytes {
		return nil, failure("ValidationException", "Record data must not exceed 1024000 bytes.")
	}
	stream, err := s.directPutStream(ctx, tx, value(in.DeliveryStreamName), "PutRecord")
	if err != nil {
		return nil, err
	}
	if err := s.appendRecords(ctx, tx, &stream, []RecordRecord{{Data: in.Record.Data, Arrived: s.clock.Now().UTC()}}); err != nil {
		return nil, err
	}
	if err := s.addSamples(tx, stream.Key, []MetricSample{
		{Name: "IncomingRecords", Value: 1, SampleCount: 1},
		{Name: "IncomingBytes", Value: float64(len(in.Record.Data)), SampleCount: 1},
	}); err != nil {
		return nil, err
	}
	return &api.PutRecordOutput{RecordId: new(api.PutResponseRecordId(uuid.NewString())), Encrypted: new(api.BooleanObject(false))}, nil
}

func (s *Service) putRecordBatch(ctx context.Context, tx Transaction, in *api.PutRecordBatchInput) (*api.PutRecordBatchOutput, error) {
	if in == nil || len(in.Records) < 1 || len(in.Records) > 500 {
		return nil, failure("ValidationException", "Records must contain between 1 and 500 entries.")
	}
	total := 0
	for _, record := range in.Records {
		if len(record.Data) > maxRecordBytes {
			return nil, failure("ValidationException", "Record data must not exceed 1024000 bytes.")
		}
		total += len(record.Data)
	}
	if total > maxBatchBytes {
		return nil, failure("InvalidArgumentException", "The total size of the records exceeds the maximum allowed size of 4194304 bytes.")
	}
	stream, err := s.directPutStream(ctx, tx, value(in.DeliveryStreamName), "PutRecordBatch")
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	records := make([]RecordRecord, len(in.Records))
	out := &api.PutRecordBatchOutput{Encrypted: new(api.BooleanObject(false)), FailedPutCount: new(api.NonNegativeIntegerObject(0)), RequestResponses: make(api.PutRecordBatchResponseEntryList, len(in.Records))}
	for i, record := range in.Records {
		records[i] = RecordRecord{Data: record.Data, Arrived: now}
		out.RequestResponses[i].RecordId = new(api.PutResponseRecordId(uuid.NewString()))
	}
	if err := s.appendRecords(ctx, tx, &stream, records); err != nil {
		return nil, err
	}
	if err := s.addSamples(tx, stream.Key, []MetricSample{
		{Name: "IncomingRecords", Value: float64(len(in.Records)), SampleCount: 1},
		{Name: "IncomingBytes", Value: float64(total), SampleCount: 1},
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) directPutStream(ctx context.Context, tx Transaction, name, action string) (StreamRecord, error) {
	// TODO: Comeback — enforce regional record/request/byte throughput admission
	// and its native quota transitions; payload size limits are not rate limits.
	stream, err := s.loadStream(ctx, tx, name, action)
	if err != nil {
		return StreamRecord{}, err
	}
	if stream.Source != nil {
		return StreamRecord{}, failure("InvalidArgumentException", "This operation is not permitted on KinesisStreamAsSource delivery stream type.")
	}
	if stream.Status != "ACTIVE" {
		return StreamRecord{}, failure("ResourceNotFoundException", fmt.Sprintf("Firehose %s is not active in %s account.", name, stream.Key.AccountID))
	}
	if decompress, _ := sourceProcessing(stream.Destination); decompress && awsctx.FromContext(ctx).InvokedBy != "logs.amazonaws.com" {
		return StreamRecord{}, failure("InvalidSourceException", fmt.Sprintf("Put to Firehose failed for AccountId: %s, FirehoseName: %s because the request is not originating from CloudWatch.", stream.Key.AccountID, name))
	}
	return stream, nil
}

// appendRecords owns only persistence. The caller owns source admission,
// checkpoints and incoming metrics in the same transaction.
func (s *Service) appendRecords(ctx context.Context, tx Transaction, stream *StreamRecord, records []RecordRecord) error {
	if len(records) == 0 {
		return nil
	}
	var buffer BufferRecord
	if stream.BufferID != "" {
		var err error
		buffer, err = tx.Buffer(stream.BufferID)
		if err != nil {
			return err
		}
	} else {
		parent := apievents.EventID(ctx)
		if parent == "" {
			parent = awsctx.FromContext(ctx).ParentEventID
		}
		buffer = BufferRecord{ID: uuid.NewString(), StreamID: stream.ID, Stream: stream.Key, Created: records[0].Arrived, ParentEventID: parent}
		stream.BufferID = buffer.ID
	}
	for i, record := range records {
		if record.Arrived.Before(buffer.Created) {
			buffer.Created = record.Arrived
		}
		records[i].Key = RecordKey{BufferID: buffer.ID, Position: buffer.Count}
		records[i].OriginalBytes = int64(len(record.Data))
		buffer.Count++
		buffer.Bytes += int64(len(record.Data))
	}
	buffer.Due = deliveryBufferDue(buffer, stream.Destination)
	if err := tx.PutBuffer(buffer); err != nil {
		return err
	}
	for _, record := range records {
		if err := tx.PutRecord(record); err != nil {
			return err
		}
	}
	return tx.PutStream(*stream)
}

func deliveryBufferDue(buffer BufferRecord, destination api.ExtendedS3DestinationDescription) time.Time {
	interval := time.Duration(*destination.BufferingHints.IntervalInSeconds) * time.Second
	size := int64(*destination.BufferingHints.SizeInMBs) * 1024 * 1024
	if processor, enabled := lambdaProcessing(destination); enabled {
		interval, size = processor.interval, processor.size
	} else if value(destination.S3BackupMode) == "Enabled" {
		backup := destination.S3BackupDescription.BufferingHints
		interval = min(interval, time.Duration(*backup.IntervalInSeconds)*time.Second)
		size = min(size, int64(*backup.SizeInMBs)*1024*1024)
	}
	if buffer.Bytes >= size {
		return buffer.Created
	}
	return buffer.Created.Add(interval)
}
