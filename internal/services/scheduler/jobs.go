package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/awsschedule"
	"stackd/internal/awswire"
	jobs "stackd/internal/scheduler"
)

type occurrenceJobs struct {
	s *Service
}

func (j occurrenceJobs) Next(ctx context.Context) (jobs.Job, bool, error) {
	var v ScheduleRecord
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		v, found, err = r.NextSchedule()
		return err
	})
	if err != nil || !found {
		return jobs.Job{}, false, err
	}
	return jobs.Job{
		Key:     v.Key.ARN(),
		Version: v.Revision,
		Due:     *v.Next,
	}, true, nil
}

func (j occurrenceJobs) Run(ctx context.Context, job jobs.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		v, found, err := tx.NextSchedule()
		if err != nil || !found {
			return err
		}
		if v.Key.ARN() != job.Key || v.Revision != job.Version || !v.Next.Equal(job.Due) {
			return nil
		}
		calendar, err := awsschedule.ParseScheduler(v.Expression, v.Timezone)
		if err != nil {
			return err
		}
		d := DeliveryRecord{
			ID:         uuid.NewString(),
			Schedule:   v.Key,
			Revision:   v.Revision,
			Scheduled:  job.Due,
			Due:        job.Due,
			Target:     v.Target,
			KmsKeyARN:  v.KmsKeyARN,
			Ciphertext: v.Ciphertext,
			DataKey:    v.DataKey,
			Phase:      "TARGET",
		}
		if v.WindowMode == "FLEXIBLE" {
			hash := sha256.Sum256([]byte(d.ID))
			d.Due = d.Due.Add(time.Duration(binary.BigEndian.Uint64(hash[:8])%uint64(v.WindowMinutes*60)) * time.Second)
		}
		// A flexible admission window precedes the target's retry-age window.
		d.Expires = d.Due.Add(time.Duration(v.Target.MaxAgeSeconds) * time.Second)
		if err = tx.PutDelivery(d); err != nil {
			return err
		}
		next, ok := calendar.Next(job.Due)
		v.Next = nil
		if ok && (strings.HasPrefix(v.Expression, "at(") || v.End == nil || !next.After(*v.End)) {
			v.Next = &next
		}
		if v.Next == nil && v.ActionAfterCompletion == "DELETE" {
			return tx.DeleteSchedule(v.Key)
		}
		return tx.PutSchedule(v)
	})
}

type deliveryJobs struct {
	s *Service
}

func (j deliveryJobs) Next(ctx context.Context) (jobs.Job, bool, error) {
	var v DeliveryRecord
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		v, found, err = r.NextDelivery()
		return err
	})
	if err != nil || !found {
		return jobs.Job{}, false, err
	}
	return jobs.Job{
		Key:     v.ID,
		Version: uint64(v.Attempts),
		Due:     v.Due,
	}, true, nil
}

func serviceContext(ctx context.Context, k ScheduleKey) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: k.Group.Partition,
		AccountID: k.Group.Account,
		Region:    k.Group.Region,
		ServicePrincipal: awsctx.ServicePrincipal{
			Name:      "scheduler.amazonaws.com",
			SourceARN: k.Group.ARN(),
			Type:      "AWSService",
		},
	})
}

func (j deliveryJobs) Run(ctx context.Context, job jobs.Job) error {
	var v DeliveryRecord
	found := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		var e error
		v, e = r.Delivery(job.Key)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		found = v.Attempts == int(job.Version) && v.Due.Equal(job.Due)
		return nil
	})
	if err != nil || !found {
		return err
	}
	ctx = serviceContext(ctx, v.Schedule)
	now := j.s.clock.Now()
	var rejected *awswire.Error
	payload := v.Target.Input
	if v.Phase == "TARGET" && !now.Before(v.Expires) {
		rejected = failure("EVENT_AGE_EXCEEDED", "The event exceeded its maximum age.")
	}
	if rejected == nil && v.KmsKeyARN != "" {
		if j.s.keys == nil {
			rejected = unsupported("Scheduler encryption is not configured.")
		} else {
			var plain []byte
			plain, rejected = j.s.keys.Open(ctx, v.Schedule, v.Target.RoleARN, v.Ciphertext, v.DataKey)
			payload = string(plain)
			clear(plain)
		}
	}
	if !v.Target.HasInput {
		payload = defaultNotification(v)
	}
	if strings.Contains(payload, "<aws.scheduler.") {
		payload = strings.NewReplacer(
			"<aws.scheduler.schedule-arn>", v.Schedule.ARN(),
			"<aws.scheduler.scheduled-time>", v.Scheduled.UTC().Format(time.RFC3339),
			"<aws.scheduler.execution-id>", v.ExecutionID(),
			"<aws.scheduler.attempt-number>", strconv.Itoa(v.AttemptNumber()),
		).Replace(payload)
	}
	attempted := false
	if rejected == nil {
		attempted = true
		if j.s.delivery == nil {
			rejected = unsupported("Scheduler target delivery is not configured.")
		} else {
			rejected = j.s.delivery.Send(ctx, v, payload, v.Phase == "DLQ")
		}
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Delivery(v.ID)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if current.Attempts != v.Attempts || current.Phase != v.Phase || !current.Due.Equal(v.Due) {
			return nil
		}
		if attempted && v.Phase == "TARGET" {
			if e = j.s.metric(tx.Context(), v, "InvocationAttemptCount"); e != nil {
				return e
			}
		}
		if v.Phase == "DLQ" {
			name := "InvocationsSentToDeadLetterCount"
			if rejected != nil {
				name = "InvocationsFailedToBeSentToDeadLetterCount"
			}
			if e = j.s.metric(tx.Context(), v, name); e != nil {
				return e
			}
			return tx.DeleteDelivery(v.ID)
		}
		if rejected == nil {
			return tx.DeleteDelivery(v.ID)
		}
		v.Attempts++
		v.LastErrorCode, v.LastErrorMessage = rejected.Code, rejected.Message
		if e = j.s.metric(tx.Context(), v, "TargetErrorCount"); e != nil {
			return e
		}
		if rejected.StatusCode == 429 {
			if e = j.s.metric(tx.Context(), v, "TargetErrorThrottledCount"); e != nil {
				return e
			}
		}
		delay := time.Second << min(v.Attempts-1, 12)
		if delay > time.Hour {
			delay = time.Hour
		}
		hash := sha256.Sum256([]byte(v.ID + ":" + strconv.Itoa(v.Attempts)))
		delay = delay/2 + time.Duration(binary.BigEndian.Uint64(hash[:8])%uint64(max(delay/2, time.Nanosecond)))
		due := now.Add(delay)
		expires := v.Expires
		retryable := rejected.StatusCode >= 500 || rejected.StatusCode == 429
		if retryable && v.Attempts <= v.Target.MaxRetries && due.Before(expires) {
			v.Due = due
			return tx.PutDelivery(v)
		}
		if e = j.s.metric(tx.Context(), v, "InvocationDroppedCount"); e != nil {
			return e
		}
		if v.Target.DeadLetterARN != "" {
			v.Phase = "DLQ"
			v.Due = now
			return tx.PutDelivery(v)
		}
		return tx.DeleteDelivery(v.ID)
	})
}

func (s *Service) metric(ctx context.Context, d DeliveryRecord, name string) error {
	if s.metrics == nil {
		return nil
	}
	ctx = serviceContext(ctx, d.Schedule)
	return s.metrics.Publish(ctx, "AWS/Scheduler", []metricsapi.MetricDatum{{
		MetricName: new(metricsapi.MetricName(name)),
		Timestamp:  new(s.clock.Now()),
		Value:      new(metricsapi.DatapointValue(1)),
		Unit:       new(metricsapi.StandardUnit("None")),
		Dimensions: metricsapi.Dimensions{{
			Name:  new(metricsapi.DimensionName("ScheduleGroup")),
			Value: new(metricsapi.DimensionValue(d.Schedule.Group.Name)),
		}},
	}})
}

// AttemptNumber identifies the target attempt, including its subsequent DLQ
// handoff. Dead-letter delivery must not invent another target invocation.
func (d DeliveryRecord) AttemptNumber() int {
	if d.Phase == "DLQ" {
		return max(1, d.Attempts)
	}
	return d.Attempts + 1
}

// ExecutionID is unique per target attempt and stable across crash replay of
// that admitted attempt. The delivery ID itself identifies the whole occurrence.
func (d DeliveryRecord) ExecutionID() string {
	return d.ID + "-" + strconv.Itoa(d.AttemptNumber())
}
