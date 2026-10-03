package firehose

import (
	"context"
	"errors"
	"time"

	"stackd/internal/scheduler"
)

// Retry pacing is a local scheduling policy, not a native cadence guarantee.
const deliveryRetryInterval = 30 * time.Second

type deliveryJobs struct{ s *Service }

func (j deliveryJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	err = j.s.repository.View(ctx, func(r Reader) error {
		buffer, e := r.NextDelivery()
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		job, found = scheduler.Job{Key: buffer.ID, Due: buffer.Due}, true
		return nil
	})
	return
}

func (j deliveryJobs) Run(ctx context.Context, job scheduler.Job) error {
	return j.s.deliverBuffer(ctx, job)
}

func (s *Service) deliverBuffer(ctx context.Context, job scheduler.Job) error {
	var buffer BufferRecord
	var stream StreamRecord
	var records []RecordRecord
	prepared := false
	now := s.clock.Now().UTC()
	// Seal and retain the destination/object identity before invoking S3. The
	// rows are immutable after this commit; crash recovery regenerates identical
	// bytes rather than interpreting acknowledgements as incoming records.
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Buffer(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !current.Due.Equal(job.Due) || current.Due.After(now) {
			return nil
		}
		stream, err = tx.StreamByID(current.StreamID)
		if errors.Is(err, ErrNotFound) {
			return tx.DeleteBuffer(current.ID)
		}
		if err != nil {
			return err
		}
		if stream.Status != "ACTIVE" {
			current.Due = now.Add(deliveryRetryInterval)
			return tx.PutBuffer(current)
		}
		if current.Configuration == nil {
			due := deliveryBufferDue(current, stream.Destination)
			if due.After(now) {
				current.Due = due
				return tx.PutBuffer(current)
			}
		}
		records, err = tx.Records(current.ID)
		if err != nil {
			return err
		}
		retention := streamRetention(stream)
		if current.Configuration == nil && retention > 0 {
			live := records[:0]
			for _, record := range records {
				if record.Arrived.Add(retention).After(now) {
					live = append(live, record)
				}
			}
			if len(live) != 0 && len(live) != len(records) {
				if err := tx.DeleteBuffer(current.ID); err != nil {
					return err
				}
				current.Count, current.Bytes = int64(len(live)), 0
				for i := range live {
					live[i].Key.Position = int64(i)
					current.Bytes += int64(len(live[i].Data))
					if i == 0 || live[i].Arrived.Before(current.Created) {
						current.Created = live[i].Arrived
					}
				}
				if err := tx.PutBuffer(current); err != nil {
					return err
				}
				for _, record := range live {
					if err := tx.PutRecord(record); err != nil {
						return err
					}
				}
			}
			records = live
		}
		// TODO: Comeback — calibrate mixed-age prepared object expiry against AWS.
		// Prepared objects expire as one batch at their oldest retained record's
		// bound; younger rows may retire with it. Native per-record expiry is unmeasured.
		var expires time.Time
		for _, record := range records {
			if retention > 0 && (expires.IsZero() || record.Arrived.Add(retention).Before(expires)) {
				expires = record.Arrived.Add(retention)
			}
		}
		if len(records) == 0 || !expires.IsZero() && !expires.After(now) {
			if stream.BufferID == current.ID {
				stream.BufferID = ""
				if err := tx.PutStream(stream); err != nil {
					return err
				}
			}
			return tx.DeleteBuffer(current.ID)
		}
		if current.Configuration == nil {
			configuration := stream.Destination
			current.Configuration, current.StreamVersion = &configuration, stream.Version
			if stream.BufferID == current.ID {
				stream.BufferID = ""
				if err := tx.PutStream(stream); err != nil {
					return err
				}
			}
		}
		if current.Kind == BufferInput {
			_, lambdaEnabled := lambdaProcessing(*current.Configuration)
			decompress, _ := sourceProcessing(*current.Configuration)
			if lambdaEnabled || decompress {
				if err := tx.PutBuffer(current); err != nil {
					return err
				}
				return tx.PutProcessing(ProcessingRecord{BufferID: current.ID, State: ProcessingQueued, Due: now})
			}
			if value(current.Configuration.S3BackupMode) == "Enabled" {
				if err := s.enqueueOutput(tx, current, BufferPrimary, *current.Configuration, records, current.Created); err != nil {
					return err
				}
				if err := s.enqueueOutput(tx, current, BufferBackup, extendedBackup(*current.Configuration.S3BackupDescription), records, current.Created); err != nil {
					return err
				}
				return tx.DeleteBuffer(current.ID)
			}
		}
		if current.ObjectKey == "" {
			sealed := stream
			sealed.Destination, sealed.Version = *current.Configuration, current.StreamVersion
			current.ObjectKey, err = s3ObjectKey(sealed, current)
			if err != nil {
				return err
			}
		}
		current.Due = now.Add(deliveryRetryInterval)
		if !expires.IsZero() && expires.Before(current.Due) {
			current.Due = expires
		}
		if err := tx.PutBuffer(current); err != nil {
			return err
		}
		buffer, prepared = current, true
		return nil
	})
	if err != nil || !prepared {
		return err
	}
	body, err := deliveryBody(*buffer.Configuration, records, buffer.Kind)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.destination == nil {
		return errors.New("firehose: S3 destination adapter is not configured")
	}
	rejected := s.destination.Write(ctx, buffer, body)
	if err := ctx.Err(); err != nil {
		return err
	}
	var originalBytes int64
	for _, record := range records {
		originalBytes += record.OriginalBytes
	}
	recordCount, byteCount, success := float64(buffer.Count), float64(originalBytes), float64(1)
	metricPrefix := "DeliveryToS3"
	if buffer.Kind == BufferBackup {
		metricPrefix = "BackupToS3"
	}
	if rejected != nil {
		recordCount, byteCount, success = 0, 0, 0
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		_, err := tx.Buffer(buffer.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.addSamples(tx, buffer.Stream, []MetricSample{
			{Name: metricPrefix + ".Records", Value: recordCount, SampleCount: 1},
			{Name: metricPrefix + ".Bytes", Value: byteCount, SampleCount: 1},
			{Name: metricPrefix + ".Success", Value: success, SampleCount: 1},
		}); err != nil {
			return err
		}
		if rejected != nil {
			return nil
		}
		return tx.DeleteBuffer(buffer.ID)
	})
	if err != nil {
		return err
	}
	if rejected != nil && (rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException") && s.diagnostics != nil {
		stream.Destination, stream.Version = *buffer.Configuration, buffer.StreamVersion
		return s.diagnostics.Report(ctx, stream, "S3.AccessDenied", "Access was denied. Ensure that the trust policy for the provided IAM role allows Firehose to assume the role, and the access policy allows access to the S3 bucket.")
	}
	return nil
}

func streamRetention(stream StreamRecord) time.Duration {
	if stream.Source == nil {
		return 24 * time.Hour
	}
	return time.Duration(stream.Source.RetentionHours) * time.Hour
}
