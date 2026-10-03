package firehose

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// Start recovers interrupted customer execution before enabling new claims.
// A crash may repeat a Lambda invocation; retained S3 output does not re-invoke it.
func (s *Service) Start() error {
	err := s.repository.Update(s.lifetime, func(tx Transaction) error {
		rows, err := tx.InFlightProcessing()
		if err != nil {
			return err
		}
		for _, row := range rows {
			row.State, row.Due = ProcessingQueued, s.clock.Now().UTC()
			if err := tx.PutProcessing(row); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	s.jobs.Wake()
	return nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.jobs.Close()
	s.work.Wait()
	return nil
}

type processingJobs struct{ s *Service }

func (j processingJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	s := j.s
	s.mu.Lock()
	enabled := s.started && !s.closed
	s.mu.Unlock()
	if !enabled {
		return
	}
	err = s.repository.View(ctx, func(r Reader) error {
		row, err := r.NextProcessing()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		job, found = scheduler.Job{Key: row.BufferID, Due: row.Due, Version: uint64(row.Attempts)}, true
		return nil
	})
	return
}

func (j processingJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	s.mu.Lock()
	if !s.started || s.closed {
		s.mu.Unlock()
		return nil
	}
	s.work.Add(1)
	s.mu.Unlock()
	var claim ProcessingRecord
	var buffer BufferRecord
	var stream StreamRecord
	var records []RecordRecord
	launch := false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		row, err := tx.Processing(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if row.State != ProcessingQueued || row.Due.After(s.clock.Now()) || uint64(row.Attempts) != job.Version {
			return nil
		}
		buffer, err = tx.Buffer(row.BufferID)
		if err != nil {
			return err
		}
		stream, err = tx.StreamByID(buffer.StreamID)
		if err != nil {
			return err
		}
		if stream.Status != "ACTIVE" {
			row.Due = s.clock.Now().Add(deliveryRetryInterval)
			return tx.PutProcessing(row)
		}
		if !buffer.Created.Add(streamRetention(stream)).After(s.clock.Now()) {
			return tx.DeleteBuffer(buffer.ID)
		}
		records, err = tx.Records(buffer.ID)
		if err != nil {
			return err
		}
		row.State, row.Attempts = ProcessingInFlight, row.Attempts+1
		if err := tx.PutProcessing(row); err != nil {
			return err
		}
		claim, launch = row, true
		return nil
	})
	if err != nil || !launch {
		s.work.Done()
		return err
	}
	// Joined scheduler drivers share a drain gate. Customer code must run after
	// returning, so its AWS calls and other service jobs can make progress.
	go func() { defer s.work.Done(); s.runProcessing(claim, buffer, stream, records) }()
	return nil
}

func (s *Service) runProcessing(claim ProcessingRecord, buffer BufferRecord, stream StreamRecord, records []RecordRecord) {
	ctx := awsctx.WithMetadata(s.lifetime, awsctx.Metadata{Partition: buffer.Stream.Partition, AccountID: buffer.Stream.AccountID, Region: buffer.Stream.Region, RequestID: uuid.NewString(), ParentEventID: buffer.ParentEventID})
	options, lambdaEnabled := lambdaProcessing(*buffer.Configuration)
	ready, sourceFailures := prepareSourceRecords(*buffer.Configuration, records)
	var results []processingResult
	var failure *processingFailure
	if lambdaEnabled && len(ready) != 0 {
		results, failure = s.invokeProcessing(ctx, stream, options, ready)
	} else {
		results = make([]processingResult, len(ready))
		for i, record := range ready {
			results[i] = processingResult{record: record, result: "Ok"}
		}
	}
	if s.lifetime.Err() != nil {
		return
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Processing(claim.BufferID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.State != ProcessingInFlight || current.Attempts != claim.Attempts {
			return nil
		}
		if failure != nil && current.Attempts <= options.retries {
			// Retry pacing is deterministic local policy, not a measured AWS cadence.
			current.State, current.Due = ProcessingQueued, s.clock.Now().Add(deliveryRetryInterval)
			return tx.PutProcessing(current)
		}
		if failure != nil {
			results = make([]processingResult, len(ready))
			for i, record := range ready {
				results[i] = processingResult{record: record, failure: failure, kind: BufferFailed}
			}
		}
		return s.completeProcessing(tx, current, buffer, records, append(sourceFailures, results...), options.functionARN)
	})
	if err != nil {
		slog.Error("complete Firehose processing", "stream", stream.Key.ARN(), "error", err)
		return
	}
	s.jobs.Wake()
	diagnostic := failure
	if diagnostic == nil && len(sourceFailures) != 0 {
		diagnostic = sourceFailures[0].failure
	}
	if diagnostic != nil && s.diagnostics != nil {
		stream.Destination, stream.Version = *buffer.Configuration, buffer.StreamVersion
		if err := s.diagnostics.Report(ctx, stream, diagnostic.Code, diagnostic.Message); err != nil {
			slog.Error("publish Firehose processing diagnostic", "stream", stream.Key.ARN(), "error", err)
		}
	}
}

func (s *Service) invokeProcessing(ctx context.Context, stream StreamRecord, options lambdaProcessorOptions, records []RecordRecord) ([]processingResult, *processingFailure) {
	if s.processor == nil {
		return nil, &processingFailure{"Lambda.InternalServerError", "The Lambda processor is not configured."}
	}
	invokeContext, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	output, rejected := s.processor.Invoke(invokeContext, stream.Key, options.functionARN, options.roleARN, processingPayload(stream, records))
	if errors.Is(invokeContext.Err(), context.DeadlineExceeded) {
		return nil, &processingFailure{"Lambda.FunctionRequestTimedOut", "The Lambda invocation request did not complete before the request timeout."}
	}
	if failure := invocationFailure(output, rejected); failure != nil {
		return nil, failure
	}
	return processingResults(output.Payload, records)
}
