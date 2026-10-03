package eventbridge

import (
	"context"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awsschedule"
	"stackd/internal/scheduler"
)

// scheduledRuleJobs commits each retained occurrence with its target work and
// next deadline. Destination effects remain owned by deliveryJobs.
type scheduledRuleJobs struct{ s *Service }

func (j scheduledRuleJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var rule RuleRecord
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		rule, found, err = r.NextScheduledRule()
		return err
	})
	if err != nil || !found {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: rule.Key.ARN(), Due: *rule.NextSchedule}, true, nil
}

func (j scheduledRuleJobs) Run(ctx context.Context, job scheduler.Job) error {
	// Advancing a clock or draining jobs does not make that caller the producer.
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{ServicePrincipal: awsctx.ServicePrincipal{Name: "events.amazonaws.com"}})
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		rule, found, err := tx.NextScheduledRule()
		if err != nil || !found {
			return err
		}
		if rule.Key.ARN() != job.Key || !rule.NextSchedule.Equal(job.Due) {
			return nil
		}
		schedule, err := awsschedule.ParseEventBridge(rule.ScheduleExpression)
		if err != nil {
			return err
		}
		id := identifier()
		event := EventRecord{
			ID: id, WireID: id, Bus: rule.Key.Bus,
			Source: "aws.events", DetailType: "Scheduled Event", Detail: "{}",
			Time: job.Due, Accepted: j.s.clock.Now(),
			Account: rule.Key.Bus.Account, Region: rule.Key.Bus.Region,
			Resources: []string{job.Key},
		}
		if err := commitEvent(tx, event, j.s.events, j.s.metrics, eventSelection{Scheduled: &rule.Key}); err != nil {
			return err
		}
		var deadline *time.Time
		if next, ok := schedule.Next(job.Due); ok {
			deadline = &next
		}
		return tx.UpdateRuleSchedule(rule.Key, deadline)
	})
}
