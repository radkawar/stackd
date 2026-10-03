package sns

import (
	"context"
	"errors"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"stackd/internal/services/sns/filterpolicy"
)

type replayJobs struct{ s *Service }

func (j replayJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	err = j.s.repository.View(ctx, func(r Reader) error {
		sub, exists, readErr := r.NextReplay()
		found = exists
		job = scheduler.Job{Key: sub.Key.ARN(), Version: sub.Version, Due: sub.Replay.Due}
		return readErr
	})
	return
}

func (j replayJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	var sub SubscriptionRecord
	var entry ArchiveEntry
	var message MessageRecord
	var selected, found bool
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		sub, selected, err = r.NextReplay()
		if err != nil || !selected {
			return err
		}
		selected = sub.Key.ARN() == job.Key && sub.Version == job.Version && !sub.Replay.Due.After(s.clock.Now())
		if !selected || sub.Replay.Status == "Pending" {
			return nil
		}
		topic, err := r.Topic(sub.Key.Topic)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil || topic.Archive == nil {
			return err
		}
		entry, found, err = r.NextArchiveEntry(topic.ID, sub.Replay.Start, sub.Replay.Cursor)
		if err != nil || !found || !entry.Expires.After(s.clock.Now()) || !sub.Replay.End.IsZero() && !entry.Published.Before(sub.Replay.End) {
			return err
		}
		message, err = r.Message(entry.Message)
		return err
	})
	if err != nil || !selected {
		return err
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: sub.Key.Topic.Partition, AccountID: sub.Key.Topic.AccountID, Region: sub.Key.Topic.Region, RequestID: identifier(), ParentEventID: message.ParentEventID, ServicePrincipal: awsctx.ServicePrincipal{Name: "sns.amazonaws.com", SourceARN: sub.Key.Topic.ARN(), Type: "AWSService"}})
	next := sub.Replay
	match := filterpolicy.Matched
	inspected := false
	switch {
	case next.Status == "Pending":
		next.Status = "In Progress"
	case !found:
		// Native EOF resumes live delivery, even when an explicit EndingPoint
		// was later than every archived message. Encountering that boundary
		// while scanning, below, is a distinct terminal transition.
		next.Status, next.Paused = "Completed", false
	case !next.End.IsZero() && !entry.Published.Before(next.End):
		next.Status, next.Paused = "Completed", true
	default:
		next.Cursor = entry.Sequence
		if entry.Expires.After(s.clock.Now()) {
			// Native unreadable encrypted entries produce no receipt, but the
			// archive scan still advances and reaches Completed.
			// TODO: Comeback isolate disabled-key replay recovery, failed-call audit and native cache lifetime.
			if rejected := s.openMessage(ctx, &message, true); rejected != nil {
				break
			}
			policy, err := filterpolicy.Compile(sub.FilterPolicy, sub.FilterScope)
			if err != nil {
				return err
			}
			match, inspected = policy.Match(message.Body, message.Attributes), true
		}
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Subscription(sub.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil || current.Version != job.Version {
			return err
		}
		if inspected {
			// Retention or archive disable can release this source while KMS
			// executes. Never admit a delivery from the removed archive entry.
			retained, err := tx.ArchiveEntry(entry.Message)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if err == nil && retained.Expires.After(s.clock.Now()) {
				var results [filterpolicy.MatchResultCount]int64
				results[match] = 1
				if err := s.stageFilterMetrics(tx, sub.Key.Topic, s.clock.Now(), results); err != nil {
					return err
				}
				if match == filterpolicy.Matched {
					if s.delivery == nil {
						return unsupported("SNS endpoint delivery is not configured.")
					}
					if err := enqueueDelivery(tx, DeliveryRecord{Message: entry.Message, Subscription: sub.Key, Due: s.clock.Now(), FIFOGroup: message.MessageGroupID, Replayed: true}); err != nil {
						return err
					}
				}
			}
		}
		current.Replay = next
		current.Replay.Due = s.clock.Now()
		current.Version++
		return tx.PutSubscription(current)
	})
}
