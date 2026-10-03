package cloudtrail

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type deliveryJobs struct{ service *Service }

func (j deliveryJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	var found bool
	err := j.service.repository.View(ctx, func(r Reader) error {
		var err error
		job, found, err = r.NextDelivery()
		if err != nil {
			return err
		}
		digest, digestErr := r.NextDigest()
		if digestErr != nil && !errors.Is(digestErr, ErrNotFound) {
			return digestErr
		}
		if digestErr == nil && (!found || digest.Due.Before(job.Due)) {
			job, found = scheduler.Job{Key: "digest:" + digest.ID, Due: digest.Due, Version: digest.Version}, true
		}
		return nil
	})
	return job, found, err
}
func (j deliveryJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.service
	if strings.HasPrefix(job.Key, "digest:") {
		return s.runDigest(ctx, job)
	}
	var batch DeliveryRecord
	var eventIDs []string
	var keyID, topicARN string
	eligible := false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		batch, err = tx.Delivery(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if batch.Version != job.Version || batch.Due.After(s.clock.Now()) {
			return nil
		}
		if !s.clock.Now().Before(batch.Expires) {
			return tx.DeleteDelivery(batch.ID)
		}
		if batch.Destination == DestinationS3 || batch.Destination == DestinationSNS {
			trail, err := tx.Trail(batch.Trail)
			if err != nil {
				return err
			}
			// Native retries adopt a later trail key, even for an event
			// accepted before the original key failed.
			keyID = trail.KMSKeyID
			topicARN = trail.SNSTopicARN()
			if batch.Destination == DestinationSNS && topicARN == "" {
				return tx.DeleteDelivery(batch.ID)
			}
		}
		batch.Sealed = true
		batch.Version++
		if err := tx.PutDelivery(batch); err != nil {
			return err
		}
		eventIDs, err = tx.DeliveryEventIDs(batch.ID)
		eligible = err == nil
		return err
	})
	if err != nil || !eligible {
		return err
	}
	var log DigestLog
	result, err := s.sendDelivery(ctx, batch, eventIDs, keyID, topicARN, &log)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.finishDelivery(ctx, batch, result, log)
}

func (s *Service) sendDelivery(ctx context.Context, batch DeliveryRecord, eventIDs []string, keyID, topicARN string, log *DigestLog) (*awswire.Error, error) {
	parent := ""
	if len(eventIDs) > 0 {
		parent = eventIDs[0]
	}
	if batch.Destination == DestinationSNS {
		if s.notifications == nil {
			return unsupported("No SNS notification destination is configured."), nil
		}
		return s.notifications.Write(ctx, batch, topicARN, parent), nil
	}
	events, err := s.journal.ReadAPICalls(ctx, eventIDs)
	if err != nil {
		return nil, err
	}
	records := make([]json.RawMessage, 0, len(events))
	for _, event := range events {
		data, err := apievents.CloudTrailRecord(event)
		if err != nil {
			return nil, err
		}
		records = append(records, data)
		if log.Oldest.IsZero() || event.At.Before(log.Oldest) {
			log.Oldest = event.At
		}
		if log.Newest.IsZero() || event.At.After(log.Newest) {
			log.Newest = event.At
		}
	}
	var result *awswire.Error
	switch batch.Destination {
	case DestinationLogs:
		if s.logsDestination == nil {
			result = unsupported("No CloudWatch Logs destination is configured.")
		} else {
			result = s.logsDestination.Write(ctx, batch, records, parent)
		}
	case DestinationS3:
		if s.destination == nil {
			result = unsupported("No S3 log destination is configured.")
		} else {
			var body bytes.Buffer
			compressed := gzip.NewWriter(&body)
			hash := sha256.New()
			if err := json.NewEncoder(io.MultiWriter(compressed, hash)).Encode(struct {
				Records []json.RawMessage `json:"Records"`
			}{Records: records}); err != nil {
				return nil, err
			}
			if err := compressed.Close(); err != nil {
				return nil, err
			}
			log.Hash = hex.EncodeToString(hash.Sum(nil))
			result = s.destination.Write(ctx, batch, keyID, body.Bytes(), parent)
		}
	default:
		return nil, errors.New("unknown CloudTrail delivery destination")
	}
	return result, nil
}
func (s *Service) finishDelivery(ctx context.Context, selected DeliveryRecord, result *awswire.Error, log DigestLog) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Delivery(selected.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != selected.Version {
			return nil
		}
		now := s.clock.Now()
		status, err := tx.DeliveryStatus(current.TrailID, current.Destination)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		status.TrailID, status.Destination, status.LastAttempt = current.TrailID, current.Destination, new(now)
		if result == nil {
			status.LastSuccess, status.LastError = new(now), ""
		} else if current.Destination != DestinationLogs {
			status.LastError = result.Code
		} else {
			status.LastError = result.Error()
		}
		if err := tx.PutDeliveryStatus(status); err != nil {
			return err
		}
		if current.Destination == DestinationSNS {
			// A restored topic did not recover old failed notifications in the
			// native capture. Do not apply S3's redelivery budget to SNS Publish;
			// SNS owns subscriber retries after a successful publication.
			// TODO: Comeback: establish CloudTrail producer retry semantics for
			// transient failures and beyond the captured recovery window.
			return tx.DeleteDelivery(current.ID)
		}
		if result == nil {
			if current.Destination == DestinationS3 {
				if err := s.retainDigestLog(tx, current, log); err != nil {
					return err
				}
				trail, err := tx.Trail(current.Trail)
				if err != nil {
					return err
				}
				if trail.SNSTopicName != "" {
					current.Destination = DestinationSNS
					current.Attempts, current.Due = 0, now
					current.Version++
					return tx.PutDelivery(current)
				}
			}
			return tx.DeleteDelivery(current.ID)
		}
		current.Attempts++
		current.Version++
		// Retry retained work in service time, within the batch's admission
		// expiry. Native captures do not define a deterministic retry cadence.
		delay := min(time.Minute*time.Duration(1<<min(current.Attempts-1, 6)), time.Hour)
		current.Due = now.Add(delay)
		if current.Due.After(current.Expires) {
			current.Due = current.Expires
		}
		return tx.PutDelivery(current)
	})
}
