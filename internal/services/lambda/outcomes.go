package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// OutcomeFunctionARN makes the unpublished target explicit while preserving a
// requested alias or numeric version in destination records and event resources.
func (v InvocationRecord) OutcomeFunctionARN() string {
	arn := v.FunctionARN
	if v.Reference().Qualifier == "" {
		arn += ":$LATEST"
	}
	return arn
}

// DestinationPayload projects the retained invocation, not a second stored copy.
// An event that never reached a runtime has no fabricated response payload.
func (v InvocationRecord) DestinationPayload() ([]byte, error) {
	type requestContext struct {
		RequestID   string `json:"requestId"`
		FunctionARN string `json:"functionArn"`
		Condition   string `json:"condition"`
		InvokeCount int    `json:"approximateInvokeCount"`
	}
	type responseContext struct {
		StatusCode      int    `json:"statusCode,omitempty"`
		ExecutedVersion string `json:"executedVersion,omitempty"`
		FunctionError   string `json:"functionError,omitempty"`
	}
	type deliveryError struct {
		StatusCode   int    `json:"statusCode"`
		ErrorCode    string `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
	}
	var invalidResponse *deliveryError
	var response json.RawMessage
	var responseInfo *responseContext
	if v.ResponseStatus != 0 {
		responseInfo = &responseContext{v.ResponseStatus, v.ResponseVersion, v.ResponseError}
		response = json.RawMessage(v.ResponsePayload)
		if len(response) != 0 && !json.Valid(response) {
			response = nil
			invalidResponse = &deliveryError{
				StatusCode:   400,
				ErrorCode:    "InvalidRequestContentException",
				ErrorMessage: "The function response payload could not be parsed as JSON.",
			}
		}
	}
	// Native successful destinations report one even after observed retries,
	// within one version or after retargeting. Queue retry accounting stays intact.
	count := v.InvokeCount
	if v.Completion == "Success" {
		count = 1
	}
	return json.Marshal(struct {
		Version         string           `json:"version"`
		Timestamp       string           `json:"timestamp"`
		RequestContext  requestContext   `json:"requestContext"`
		RequestPayload  json.RawMessage  `json:"requestPayload"`
		ResponseContext *responseContext `json:"responseContext,omitempty"`
		ResponsePayload json.RawMessage  `json:"responsePayload,omitempty"`
		DeliveryError   *deliveryError   `json:"deliveryError,omitempty"`
	}{
		Version: "1.0", Timestamp: v.Completed.UTC().Format("2006-01-02T15:04:05.000Z"),
		RequestContext:  requestContext{v.RequestID, v.OutcomeFunctionARN(), v.Completion, count},
		RequestPayload:  json.RawMessage(v.Payload),
		ResponseContext: responseInfo,
		ResponsePayload: response,
		DeliveryError:   invalidResponse,
	})
}

// completeInvocation freezes the result and both independent routes in the same
// transaction, using the queue-owned settings and delivery authority last applied
// to this request rather than reloading a potentially deleted resource.
func (s *Service) completeInvocation(tx Transaction, v InvocationRecord, condition string, now time.Time) error {
	missingAlias := false
	if condition == "EventAgeExceeded" {
		var err error
		missingAlias, err = missingAliasBeforeEntry(tx, v)
		if err != nil {
			return err
		}
		if deadline := v.Accepted.Add(time.Duration(v.Settings.MaxAgeSeconds) * time.Second); missingAlias && now.Before(deadline) {
			// Another preparation failure may have reached this path because
			// its next retry crosses the age limit. Alias disappearance must
			// not retire the accepted request before that limit.
			v.State, v.Due = "queued", deadline
			v.Version++
			return tx.PutInvocation(v)
		}
	}
	v.State, v.Completion, v.Completed = "completed", condition, now
	v.Version++
	dropped := int64(0)
	if condition != "Success" {
		dropped = 1
	}
	if err := s.stageMetric(tx, v.Reference(), now, metricAsyncDropped, dropped); err != nil {
		return err
	}
	destination, deadLetter := v.Settings.OnSuccessARN, ""
	if condition != "Success" {
		destination, deadLetter = v.Settings.OnFailureARN, v.DeadLetterARN
	}
	if missingAlias {
		// Destination-only native alias metrics prove a drop near the age
		// deadline, with no OnFailure record through 6h16m. Do not invent a
		// condition/count/status404 destination record.
		destination = ""
		// TODO: Comeback resolve retry-enabled deleted-alias legacy DLQ fate.
		// The separate DLQ-enabled capture has no terminal record or additional
		// measured drop through 903s; this local age-based route is uncalibrated.
	}
	if destination == "" && deadLetter == "" {
		return tx.DeleteInvocation(v.ID)
	}
	if err := tx.PutInvocation(v); err != nil {
		return err
	}
	if destination != "" {
		if err := tx.PutOutcomeDelivery(OutcomeDeliveryRecord{ID: uuid.NewString(), InvocationID: v.ID, DestinationARN: destination}); err != nil {
			return err
		}
	}
	if deadLetter != "" {
		return tx.PutOutcomeDelivery(OutcomeDeliveryRecord{ID: uuid.NewString(), InvocationID: v.ID, DestinationARN: deadLetter, DeadLetter: true})
	}
	return nil
}

func invocationCondition(v InvocationRecord, now time.Time) string {
	if v.InvokeCount > v.Settings.MaxRetries {
		return "RetriesExhausted"
	}
	if !now.Before(v.Accepted.Add(time.Duration(v.Settings.MaxAgeSeconds) * time.Second)) {
		return "EventAgeExceeded"
	}
	return ""
}

type outcomeJobs struct{ s *Service }

func (j outcomeJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	if j.s.targets == nil {
		return
	}
	err = j.s.repository.View(ctx, func(r Reader) error {
		var err error
		job, found, err = r.NextOutcomeDelivery()
		return err
	})
	return
}

func (j outcomeJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	var delivery OutcomeDeliveryRecord
	var invocation InvocationRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		delivery, err = r.OutcomeDelivery(job.Key)
		if err != nil {
			return err
		}
		invocation, err = r.Invocation(delivery.InvocationID)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if invocation.State != "completed" || invocation.Completed.After(s.clock.Now()) {
		return nil
	}
	parent := invocation.ParentEventID
	if s.events != nil {
		parent = invocation.ID
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: invocation.Key.Partition, AccountID: invocation.Key.Account, Region: invocation.Key.Region, RequestID: uuid.NewString(), ParentEventID: parent})
	// Send is outside the source transaction. Acceptance is the complete source
	// effect even for Lambda targets; later target execution belongs to the target.
	wire := s.targets.Send(ctx, invocation, delivery)
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		if _, err := tx.OutcomeDelivery(delivery.ID); errors.Is(err, ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		if wire != nil {
			name := metricDestinationFailures
			if delivery.DeadLetter {
				name = metricDeadLetterErrors
			}
			if err := s.stageMetric(tx, invocation.Reference(), s.clock.Now(), name, 1); err != nil {
				return err
			}
		}
		return tx.DeleteOutcomeDelivery(delivery.ID)
	})
}
