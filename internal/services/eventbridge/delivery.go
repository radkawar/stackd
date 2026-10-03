package eventbridge

import (
	"context"
	"errors"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type deliveryJobs struct{ s *Service }

func (j deliveryJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var v DeliveryRecord
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error { var err error; v, found, err = r.NextDelivery(); return err })
	return scheduler.Job{Key: v.ID, Version: v.Version, Due: v.Due}, found, err
}
func (j deliveryJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	var d DeliveryRecord
	var event EventRecord
	eligible := false
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		d, err = r.Delivery(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.Version != job.Version || (d.State != "pending" && d.State != "dead-letter") || d.Due.After(s.clock.Now()) {
			return nil
		}
		event, err = r.Event(d.EventID)
		eligible = err == nil
		return err
	})
	if err != nil || !eligible {
		return err
	}
	now := s.clock.Now()
	if d.BusProcessing {
		return s.processBusEvent(ctx, d, event, now)
	}
	if len(event.Payload.DataKey) != 0 || len(d.TargetConfiguration) != 0 {
		var rejected *awswire.Error
		if d.State == "dead-letter" && d.LastErrorCode == "TARGET_DECRYPTION_FAILURE" {
			if len(event.Payload.DataKey) != 0 {
				event, err = encryptedBusDeadLetter(event)
			}
			d.Input, d.HasInput = "", false
			if err != nil {
				return err
			}
		} else {
			event, d, rejected = s.openBusEvent(ctx, event, d)
			if rejected != nil && !(d.State == "dead-letter" && rejected.Code == "INVALID_JSON") {
				if retryable(rejected) {
					return s.finishDelivery(ctx, d, event, rejected, false, now)
				}
				if rejected.Code == "INVALID_JSON" {
					return s.finishDelivery(ctx, d, event, rejected, false, now)
				}
				return s.finishDelivery(ctx, d, event, failure("TARGET_DECRYPTION_FAILURE", "Unable to decrypt event using the Kms key."), false, now)
			}
		}
	}
	if d.State == "pending" && !now.Before(event.Accepted.Add(time.Duration(d.MaxAgeSeconds)*time.Second)) {
		return s.finishDelivery(ctx, d, event, nil, true, now)
	}
	if d.ArchiveID != "" {
		return s.deliverArchive(ctx, d, event, now)
	}
	request := DeliveryRequest{Delivery: d, Event: event}
	if d.State == "dead-letter" {
		request.Delivery.TargetARN = d.DeadLetterARN
		request.Delivery.RoleARN = ""
		request.Delivery.MessageGroupID = ""
		request.Attributes = deadLetterAttributes(d)
	}
	var result *awswire.Error
	if s.delivery == nil {
		result = failure("InternalException", "No target delivery adapter is configured.", 500)
	} else {
		result = s.delivery.Send(ctx, request)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.finishDelivery(ctx, d, event, result, false, now)
}
func (s *Service) finishDelivery(ctx context.Context, selected DeliveryRecord, event EventRecord, result *awswire.Error, expired bool, started time.Time) error {
	var destinationAttempt *APIDestinationAttempt
	if result != nil {
		errors.As(result, &destinationAttempt)
	}
	admission := destinationAttempt != nil && destinationAttempt.Admission
	return s.repository.Update(ctx, func(tx Transaction) (err error) {
		current, err := tx.Delivery(selected.ID)
		if err != nil {
			return err
		}
		if current.Version != selected.Version {
			return nil
		}
		defer func() {
			if err == nil {
				err = s.stageDeliveryMetrics(tx, selected, current, event, started, !expired && !admission)
			}
		}()
		now := s.clock.Now()
		current.Version++
		if admission && !expired && current.State == "pending" {
			current.Due = now.Add(destinationAttempt.RetryAfter)
			deadline := event.Accepted.Add(time.Duration(current.MaxAgeSeconds) * time.Second)
			if current.Due.After(deadline) {
				current.Due = deadline
			}
			return tx.PutDelivery(current)
		}
		if current.State == "dead-letter" {
			if result == nil {
				current.State = "dead-lettered"
			} else {
				current.State = "failed-dead-letter"
				current.LastErrorMessage = result.Message
			}
			return tx.PutDelivery(current)
		}
		if !expired {
			current.Attempts++
		}
		if result == nil && !expired {
			current.State = "delivered"
			return tx.PutDelivery(current)
		}
		if result != nil {
			current.LastErrorCode, current.LastErrorMessage = deliveryErrorCode(result), result.Message
		}
		if expired && current.LastErrorCode == "" {
			current.LastErrorCode, current.LastErrorMessage = "ERROR_FROM_TARGET", "Event delivery expired before invocation."
		}
		deadline := event.Accepted.Add(time.Duration(current.MaxAgeSeconds) * time.Second)
		if !expired && retryable(result) && current.Attempts <= current.MaxRetries && now.Before(deadline) {
			delay := retryDelay(current.ID, current.Attempts)
			if destinationAttempt != nil && destinationAttempt.RetryAfter > delay {
				delay = destinationAttempt.RetryAfter
			}
			current.Due = now.Add(delay)
			if current.Due.After(deadline) {
				current.Due = deadline
			}
			return tx.PutDelivery(current)
		}
		if expired || !now.Before(deadline) {
			current.ExhaustedRetryCondition = "MaximumEventAgeInSeconds"
		} else if retryable(result) && current.Attempts > current.MaxRetries {
			current.ExhaustedRetryCondition = "MaximumRetryAttempts"
		}
		if current.DeadLetterARN != "" {
			current.State = "dead-letter"
			current.Due = now
		} else {
			current.State = "failed"
		}
		return tx.PutDelivery(current)
	})
}
func retryable(err *awswire.Error) bool {
	if err == nil {
		return false
	}
	var attempt *APIDestinationAttempt
	if errors.As(err, &attempt) && attempt.StopRetry {
		return false
	}
	return err.StatusCode >= 500 || strings.Contains(strings.ToLower(err.Code), "throttl") || err.Code == "ProvisionedThroughputExceededException" || err.Code == "RequestTimeout" || err.Code == "ServiceUnavailable"
}
func deliveryErrorCode(err *awswire.Error) string {
	// TODO: Comeback complete native delivery-error and retry/expiry conformance for empty projections, target outages and remaining KMS failures.
	switch {
	case err.Code == "TARGET_DECRYPTION_FAILURE", err.Code == "INVALID_JSON":
		return err.Code
	case err.Code == "FAILED_TO_ASSUME_ROLE", err.Code == "THIRD_ACCOUNT_HOP_DETECTED", err.Code == "THIRD_REGION_HOP_DETECTED":
		return err.Code
	case err.Code == "INVALID_PARAMETER", err.Code == "InvalidParameterException":
		return "INVALID_PARAMETER"
	case err.Code == "AuthorizationError", err.Code == "KMSDisabled", strings.Contains(strings.ToLower(err.Code), "accessdenied"), strings.Contains(strings.ToLower(err.Code), "permission"):
		return "NO_PERMISSIONS"
	case err.Code == "KmsDisabled", strings.Contains(strings.ToLower(err.Code), "notfound"), strings.Contains(strings.ToLower(err.Code), "doesnotexist"):
		return "NO_RESOURCE"
	case strings.Contains(strings.ToLower(err.Code), "throttl"), err.Code == "ProvisionedThroughputExceededException":
		return "THROTTLING"
	default:
		return "ERROR_FROM_TARGET"
	}
}
func deadLetterAttributes(d DeliveryRecord) map[string]string {
	out := map[string]string{"RULE_ARN": d.RuleARN, "TARGET_ARN": d.TargetARN, "ERROR_CODE": d.LastErrorCode, "ERROR_MESSAGE": d.LastErrorMessage}
	if d.ExhaustedRetryCondition != "" {
		out["EXHAUSTED_RETRY_CONDITION"] = d.ExhaustedRetryCondition
		retries := 0
		if d.Attempts > 0 {
			retries = d.Attempts - 1
		}
		out["RETRY_ATTEMPTS"] = strconv.Itoa(retries)
	}
	return out
}

// Retained IDs seed jitter so reopening a database cannot change retry timing.
func retryDelay(id string, attempt int) time.Duration {
	ceiling := time.Second * time.Duration(1<<min(attempt, 12))
	h := fnv.New64a()
	_, _ = h.Write([]byte(id + ":" + strconv.Itoa(attempt)))
	return time.Second + time.Duration(h.Sum64()%uint64(ceiling))
}
