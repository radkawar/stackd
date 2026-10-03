package firehose

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/firehose"
)

func (s *Service) completeProcessing(tx Transaction, claim ProcessingRecord, input BufferRecord, originals []RecordRecord, results []processingResult, functionARN string) error {
	now := s.clock.Now().UTC()
	outputStart := now
	if functionARN == "" {
		// Without Lambda's separate input buffer, the source buffer already
		// accounts for the destination's buffering interval.
		outputStart = input.Created
	}
	primary := make([]RecordRecord, 0, len(results))
	var failed, decompressionFailed []RecordRecord
	var successBytes int64
	for _, result := range results {
		if result.failure != nil {
			record := result.record
			attempts, lambdaARN := claim.Attempts, functionARN
			if result.kind == BufferDecompressionFailed {
				attempts, lambdaARN = 1, ""
			}
			// Derived records retain their position in the immutable input buffer.
			// Failure and backup objects carry source bytes, not Lambda input bytes.
			raw := originals[record.Key.Position].Data
			body, err := json.Marshal(processingErrorEnvelope{RawData: base64.StdEncoding.EncodeToString(raw), ErrorCode: result.failure.Code, ErrorMessage: result.failure.Message, AttemptsMade: attempts, ArrivalTimestamp: record.Arrived.UnixMilli(), AttemptEndingTimestamp: now.UnixMilli(), LambdaARN: lambdaARN})
			if err != nil {
				return err
			}
			record.Data = body
			if result.kind == BufferDecompressionFailed {
				decompressionFailed = append(decompressionFailed, record)
			} else {
				failed = append(failed, record)
			}
		} else if result.result == "Ok" {
			primary = append(primary, result.record)
			successBytes += result.record.OriginalBytes
		}
	}
	if err := s.enqueueOutput(tx, input, BufferPrimary, *input.Configuration, primary, outputStart); err != nil {
		return err
	}
	if err := s.enqueueOutput(tx, input, BufferFailed, *input.Configuration, failed, outputStart); err != nil {
		return err
	}
	if err := s.enqueueOutput(tx, input, BufferDecompressionFailed, *input.Configuration, decompressionFailed, outputStart); err != nil {
		return err
	}
	if value(input.Configuration.S3BackupMode) == "Enabled" {
		if err := s.enqueueOutput(tx, input, BufferBackup, extendedBackup(*input.Configuration.S3BackupDescription), originals, outputStart); err != nil {
			return err
		}
	}
	if functionARN != "" && len(results) > len(decompressionFailed) {
		if err := s.addSamples(tx, input.Stream, []MetricSample{
			{Name: "SucceedProcessing.Records", Value: float64(len(primary)), SampleCount: 1},
			{Name: "SucceedProcessing.Bytes", Value: float64(successBytes), SampleCount: 1},
		}); err != nil {
			return err
		}
	}
	return tx.DeleteBuffer(input.ID)
}

// enqueueOutput joins an existing open output only for the same immutable
// stream incarnation, configuration version and obligation. S3 retries own
// sealed objects; they cannot append bytes or run the transformation again.
func (s *Service) enqueueOutput(tx Transaction, input BufferRecord, kind BufferKind, destination api.ExtendedS3DestinationDescription, records []RecordRecord, start time.Time) error {
	if len(records) == 0 {
		return nil
	}
	buffer, err := tx.OpenOutputBuffer(input.StreamID, input.StreamVersion, kind)
	if errors.Is(err, ErrNotFound) {
		buffer = BufferRecord{ID: uuid.NewString(), StreamID: input.StreamID, Stream: input.Stream, Kind: kind, Created: records[0].Arrived, Due: start.Add(time.Duration(*destination.BufferingHints.IntervalInSeconds) * time.Second), ParentEventID: input.ParentEventID, StreamVersion: input.StreamVersion, Configuration: &destination}
	} else if err != nil {
		return err
	}
	first := buffer.Count
	for _, record := range records {
		buffer.Count++
		buffer.Bytes += int64(len(record.Data))
		if record.Arrived.Before(buffer.Created) {
			buffer.Created = record.Arrived
		}
	}
	if buffer.Bytes >= int64(*destination.BufferingHints.SizeInMBs)*1024*1024 && s.clock.Now().Before(buffer.Due) {
		buffer.Due = s.clock.Now()
	}
	if err := tx.PutBuffer(buffer); err != nil {
		return err
	}
	for i, record := range records {
		record.Key, record.Kinesis = RecordKey{BufferID: buffer.ID, Position: first + int64(i)}, nil
		if err := tx.PutRecord(record); err != nil {
			return err
		}
	}
	return nil
}
