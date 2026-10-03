package sqs

import (
	"context"
	"errors"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

const (
	metricVisible         = "ApproximateNumberOfMessagesVisible"
	metricNotVisible      = "ApproximateNumberOfMessagesNotVisible"
	metricDelayed         = "ApproximateNumberOfMessagesDelayed"
	metricInflightGroups  = "ApproximateNumberOfGroupsWithInflightMessages"
	metricNoisyGroups     = "ApproximateNumberOfNoisyGroups"
	metricQuietVisible    = "ApproximateNumberOfMessagesVisibleInQuietGroups"
	metricQuietNotVisible = "ApproximateNumberOfMessagesNotVisibleInQuietGroups"
	metricQuietDelayed    = "ApproximateNumberOfMessagesDelayedInQuietGroups"
	metricOldestAge       = "ApproximateAgeOfOldestMessage"
	metricQuietOldestAge  = "ApproximateAgeOfOldestMessageInQuietGroups"
)

// queueDepth is shared by GetQueueAttributes and CloudWatch sampling. Visibility
// determines backlog, not FIFO delivery eligibility behind an in-flight group.
type queueDepth struct{ visible, inflight, delayed int }

func (d *queueDepth) add(m *message, now time.Time) {
	if !now.Before(m.available) {
		d.visible++
	} else if m.receives == 0 {
		d.delayed++
	} else {
		d.inflight++
	}
}

type queueAge struct {
	oldest  time.Time
	unknown bool
}

func (a *queueAge) add(entered time.Time) {
	if entered.IsZero() {
		a.unknown = true
	} else if a.oldest.IsZero() || entered.Before(a.oldest) {
		a.oldest = entered
	}
}

func (a queueAge) sample(name string, now time.Time) MetricSample {
	var seconds int64
	if !a.oldest.IsZero() {
		seconds = int64(now.Sub(a.oldest) / time.Second)
	}
	return MetricSample{Name: name, Value: seconds, SampleCount: 1}
}

func activateQueueMetrics(activeUntil, next *time.Time, now time.Time) {
	*activeUntil = now.Add(6 * time.Hour)
	if next.IsZero() {
		*next = now.UTC().Truncate(time.Minute).Add(time.Minute)
	}
}

func (q *queue) metricSamples(now time.Time) []MetricSample {
	var all, quiet queueDepth
	var age, quietAge queueAge
	var inflightGroups map[string]struct{}
	if q.config.fifo {
		inflightGroups = make(map[string]struct{})
	}
	q.updateFairness(now)
	for _, m := range q.messages {
		all.add(m, now)
		_, noisy := q.noisyGroups[m.group]
		if !noisy {
			quiet.add(m, now)
		}
		if q.config.fifo && m.receives > 0 && now.Before(m.available) {
			inflightGroups[m.group] = struct{}{}
		}
		// Native age includes in-flight work but excludes initial delay.
		// The captured standard poison message remained eligible after three
		// deliveries and was excluded on its fourth. Source-queue deliveries
		// do not poison the newly entered DLQ's age.
		if (m.receives == 0 && now.Before(m.available)) || (!q.config.fifo && m.queueReceives > 3) {
			continue
		}
		age.add(m.ageStarted)
		if !noisy {
			quietAge.add(m.ageStarted)
		}
	}
	samples := []MetricSample{
		{Name: metricVisible, Value: int64(all.visible), SampleCount: 1},
		{Name: metricNotVisible, Value: int64(all.inflight), SampleCount: 1},
		{Name: metricDelayed, Value: int64(all.delayed), SampleCount: 1},
		// Native active queues publish periodic zero counter samples in
		// addition to request observations; size has no idle sample.
		{Name: metricMessagesSent, SampleCount: 1},
		{Name: metricMessagesReceived, SampleCount: 1},
		{Name: metricMessagesDeleted, SampleCount: 1},
		{Name: metricEmptyReceives, SampleCount: 1},
	}
	// Older messages may lack initial-delay or transfer history. Omit that
	// age until their unknown records leave instead of inventing an origin.
	if !age.unknown {
		samples = append(samples, age.sample(metricOldestAge, now))
	}
	if q.config.fifo {
		return append(samples,
			MetricSample{Name: metricInflightGroups, Value: int64(len(inflightGroups)), SampleCount: 1},
			MetricSample{Name: metricDeduplicated, SampleCount: 1},
		)
	}
	if !quietAge.unknown {
		samples = append(samples, quietAge.sample(metricQuietOldestAge, now))
	}
	return append(samples,
		MetricSample{Name: metricNoisyGroups, Value: int64(len(q.noisyGroups)), SampleCount: 1},
		MetricSample{Name: metricQuietVisible, Value: int64(quiet.visible), SampleCount: 1},
		MetricSample{Name: metricQuietNotVisible, Value: int64(quiet.inflight), SampleCount: 1},
		MetricSample{Name: metricQuietDelayed, Value: int64(quiet.delayed), SampleCount: 1},
	)
}

type queueMetricJobs struct{ s *Service }

func (j queueMetricJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	if j.s.metrics == nil {
		return
	}
	err = j.s.repository.View(ctx, func(r Reader) error {
		queue, err := r.NextMetricQueue()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		job, found = scheduler.Job{Key: privateKey(queue.Key).arn(), Due: queue.NextMetricSample}, true
		return nil
	})
	return
}

func (j queueMetricJobs) Run(ctx context.Context, job scheduler.Job) error {
	key, _ := parseQueueARN(job.Key)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.partition, AccountID: key.account, Region: key.region})
	j.s.mu.Lock()
	defer j.s.mu.Unlock()
	defer func() { j.s.reader = nil }()
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		if err := j.s.prepare(tx); err != nil {
			return err
		}
		q := j.s.lookupQueue(key)
		if j.s.stateErr != nil {
			return j.s.stateErr
		}
		if q == nil || !q.nextMetricSample.Equal(job.Due) {
			return nil
		}
		j.s.loadMessages(q)
		if j.s.stateErr != nil {
			return j.s.stateErr
		}
		now := j.s.now()
		// A clock jump can pass retention without an intervening API call.
		// Retain the known end of message activity, not invented gauge history.
		for _, m := range q.messages {
			expires := m.retentionStarted.Add(time.Duration(q.config.retention) * time.Second)
			activity := now
			if expires.Before(activity) {
				activity = expires
			}
			if until := activity.Add(6 * time.Hour); until.After(q.metricActiveUntil) {
				q.metricActiveUntil = until
			}
		}
		j.s.prune(q, now)
		if !now.Before(q.metricActiveUntil) {
			q.nextMetricSample = time.Time{}
			return j.s.flush(tx)
		}
		// This store retains current resource state, not historical snapshots.
		// Sample the actual service instant once after a jump or restart; never
		// backdate the current backlog into skipped minute buckets.
		minute := now.UTC().Truncate(time.Minute)
		if err := j.s.publishMetrics(tx.Context(), MetricPublicationKey{Queue: publicKey(key), Minute: minute}, q.metricSamples(now)); err != nil {
			return err
		}
		q.nextMetricSample = minute.Add(time.Minute)
		return j.s.flush(tx)
	})
}
