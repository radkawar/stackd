package glue

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

func configureCrawlerSchedule(row *CrawlerRecord, expression string, now time.Time) error {
	if expression == "" {
		row.NextScheduled = nil
		row.Crawler.Schedule = nil
		return nil
	}
	next, err := triggerSchedule(expression, now)
	if err != nil {
		return err
	}
	state := api.ScheduleStateSCHEDULED
	if row.Crawler.Schedule != nil && value(row.Crawler.Schedule.State) == "NOT_SCHEDULED" {
		state = api.ScheduleStateNOT_SCHEDULED
		next = nil
	}
	row.Crawler.Schedule = &api.Schedule{ScheduleExpression: new(api.CronExpression(expression)), State: &state}
	row.NextScheduled = next
	return nil
}
func (s *Service) startCrawlerSchedule(ctx context.Context, tx Transaction, in *api.StartCrawlerScheduleInput) (*api.StartCrawlerScheduleOutput, error) {
	row, err := s.loadCrawler(ctx, tx, value(in.CrawlerName), "StartCrawlerSchedule")
	if err != nil {
		return nil, err
	}
	if row.Crawler.Schedule == nil || value(row.Crawler.Schedule.ScheduleExpression) == "" {
		return nil, failure("SchedulerNotRunningException", "Crawler has no schedule.")
	}
	if value(row.Crawler.Schedule.State) == "SCHEDULED" {
		return nil, failure("SchedulerRunningException", "Crawler schedule is already running.")
	}
	row.NextScheduled, err = triggerSchedule(value(row.Crawler.Schedule.ScheduleExpression), s.clock.Now())
	if err != nil {
		return nil, err
	}
	row.Crawler.Schedule.State = new(api.ScheduleStateSCHEDULED)
	if err := tx.PutCrawler(row); err != nil {
		return nil, err
	}
	return &api.StartCrawlerScheduleOutput{}, nil
}
func (s *Service) stopCrawlerSchedule(ctx context.Context, tx Transaction, in *api.StopCrawlerScheduleInput) (*api.StopCrawlerScheduleOutput, error) {
	row, err := s.loadCrawler(ctx, tx, value(in.CrawlerName), "StopCrawlerSchedule")
	if err != nil {
		return nil, err
	}
	if row.Crawler.Schedule == nil || value(row.Crawler.Schedule.State) != "SCHEDULED" {
		return nil, failure("SchedulerNotRunningException", "Crawler schedule is not running.")
	}
	row.NextScheduled = nil
	row.Crawler.Schedule.State = new(api.ScheduleStateNOT_SCHEDULED)
	if err := tx.PutCrawler(row); err != nil {
		return nil, err
	}
	return &api.StopCrawlerScheduleOutput{}, nil
}
func (s *Service) updateCrawlerSchedule(ctx context.Context, tx Transaction, in *api.UpdateCrawlerScheduleInput) (*api.UpdateCrawlerScheduleOutput, error) {
	row, err := s.loadCrawler(ctx, tx, value(in.CrawlerName), "UpdateCrawlerSchedule")
	if err != nil {
		return nil, err
	}
	if err := configureCrawlerSchedule(&row, value(in.Schedule), s.clock.Now()); err != nil {
		return nil, err
	}
	row.Crawler.LastUpdated = new(s.clock.Now().UTC())
	row.Crawler.Version = new(*row.Crawler.Version + 1)
	if err := tx.PutCrawler(row); err != nil {
		return nil, err
	}
	return &api.UpdateCrawlerScheduleOutput{}, nil
}
func (s *Service) runScheduledCrawler(ctx context.Context, job scheduler.Job) error {
	s.mu.Lock()
	enabled := s.started && !s.closed
	s.mu.Unlock()
	if !enabled {
		return nil
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.ScheduledCrawlers()
		if err != nil {
			return err
		}
		for _, row := range rows {
			if "schedule:"+row.Key.ARN("crawler") != job.Key || row.NextScheduled == nil || row.NextScheduled.After(s.clock.Now()) || uint64(*row.Crawler.Version) != job.Version {
				continue
			}
			row.NextScheduled, err = triggerSchedule(value(row.Crawler.Schedule.ScheduleExpression), s.clock.Now())
			if err != nil {
				return err
			}
			if err := tx.PutCrawler(row); err != nil {
				return err
			}
			if value(row.Crawler.State) != "READY" {
				return nil
			}
			metadata := awsctx.Metadata{Partition: row.Key.Partition, AccountID: row.Key.AccountID, Region: row.Key.Region, RequestID: uuid.NewString(), ServicePrincipal: awsctx.ServicePrincipal{Name: "glue.amazonaws.com", SourceARN: row.Key.ARN("crawler")}}
			commandCtx := awsctx.WithMetadata(tx.Context(), metadata)
			if _, err = s.admitCrawl(commandCtx, tx, row, "", "", ""); err != nil {
				// A dependency boundary is a retained failed scheduled attempt, never
				// a success or an endlessly retried, unconsumed calendar deadline.
				run := CrawlRecord{ID: uuid.NewString(), Crawler: row.Key, State: "RUNNING", Phase: "QUEUED", Started: s.clock.Now().UTC()}
				row.RunID = run.ID
				row.Crawler.State = new(api.CrawlerStateRUNNING)
				if writeErr := tx.PutCrawl(run); writeErr != nil {
					return writeErr
				}
				if writeErr := tx.PutCrawler(row); writeErr != nil {
					return writeErr
				}
				return s.completeCrawl(commandCtx, run, err)
			}
			return nil
		}
		return nil
	})
}
func (r memoryReader) ScheduledCrawlers() ([]CrawlerRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []CrawlerRecord{}
	for _, row := range r.s.crawlers {
		if row.NextScheduled != nil {
			out = append(out, cloneCrawlerRecord(row))
		}
	}
	slices.SortFunc(out, func(a, b CrawlerRecord) int {
		return cmp.Or(a.NextScheduled.Compare(*b.NextScheduled), cmp.Compare(a.Key.ARN("crawler"), b.Key.ARN("crawler")))
	})
	return out, nil
}
