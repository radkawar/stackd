package glue

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

func (s *Service) recoverCrawlers(ctx context.Context) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.PendingCrawls()
		if err != nil {
			return err
		}
		for _, row := range rows {
			row.Phase = "QUEUED"
			if err := tx.PutCrawl(row); err != nil {
				return err
			}
		}
		return nil
	})
}

type crawlerJobs struct{ s *Service }

func (j crawlerJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	s := j.s
	s.mu.Lock()
	enabled := s.started && !s.closed
	s.mu.Unlock()
	if !enabled {
		return
	}
	err = s.repository.View(ctx, func(r Reader) error {
		rows, err := r.PendingCrawls()
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Phase == "QUEUED" || row.State == "CANCELLING" && row.Phase == "RUNNING" {
				job = scheduler.Job{Key: row.ID, Due: row.Started}
				found = true
				break
			}
		}
		scheduled, err := r.ScheduledCrawlers()
		if err != nil {
			return err
		}
		for _, row := range scheduled {
			if row.NextScheduled != nil && (!found || row.NextScheduled.Before(job.Due)) {
				job = scheduler.Job{Key: "schedule:" + row.Key.ARN("crawler"), Due: *row.NextScheduled, Version: uint64(*row.Crawler.Version)}
				found = true
			}
		}
		return nil
	})
	return
}
func (j crawlerJobs) Run(ctx context.Context, job scheduler.Job) error {
	if strings.HasPrefix(job.Key, "schedule:") {
		return j.s.runScheduledCrawler(ctx, job)
	}
	s := j.s
	s.mu.Lock()
	if !s.started || s.closed {
		s.mu.Unlock()
		return nil
	}
	s.work.Add(1)
	s.mu.Unlock()
	var run CrawlRecord
	var crawler CrawlerRecord
	launch, cancelRun := false, false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		run, err = tx.Crawl(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		crawler, err = tx.Crawler(run.Crawler)
		if err != nil {
			return err
		}
		if crawler.RunID != run.ID {
			return nil
		}
		if run.State == "CANCELLING" && (run.Phase == "QUEUED" || run.Phase == "RUNNING") {
			run.Phase = "CANCELLING"
			cancelRun = true
			return tx.PutCrawl(run)
		}
		if run.State != "RUNNING" || run.Phase != "QUEUED" {
			return nil
		}
		run.Phase = "RUNNING"
		launch = true
		return tx.PutCrawl(run)
	})
	if err != nil {
		s.work.Done()
		return err
	}
	if cancelRun {
		s.crawlerMu.Lock()
		cancel := s.crawlerActive[run.Crawler]
		if cancel != nil {
			cancel()
		}
		s.crawlerMu.Unlock()
		s.work.Done()
		if cancel == nil {
			return s.completeCrawl(ctx, run, context.Canceled)
		}
		return nil
	}
	if !launch {
		s.work.Done()
		return nil
	}
	runCtx, cancel := context.WithCancel(s.lifetime)
	s.crawlerMu.Lock()
	s.crawlerActive[run.Crawler] = cancel
	s.crawlerMu.Unlock()
	go func() { defer s.work.Done(); defer cancel(); s.runCrawler(runCtx, run, crawler) }()
	return nil
}
func (s *Service) runCrawler(ctx context.Context, run CrawlRecord, row CrawlerRecord) {
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: row.Key.Partition, AccountID: row.Key.AccountID, Region: row.Key.Region, RequestID: uuid.NewString(), ParentEventID: run.ParentEventID})
	var roleCtx context.Context
	var err error
	roleCtx, err = s.crawlerSource.RoleContext(ctx, row.Key.Scope, crawlerRole(row.Key.Scope, value(row.Crawler.Role)), row.Key.ARN("crawler"))
	var classifiers []ClassifierRecord
	if err == nil {
		err = s.repository.View(roleCtx, func(r Reader) error {
			for _, name := range row.Crawler.Classifiers {
				record, e := r.Classifier(ResourceKey{Scope: row.Key.Scope, Name: string(name)})
				if e != nil {
					return e
				}
				classifiers = append(classifiers, record)
			}
			return nil
		})
	}
	var tables []crawlerDerivedTable
	if err == nil {
		tables, err = s.crawlS3(roleCtx, row, classifiers)
	}
	if err == nil {
		var jdbc []crawlerDerivedTable
		jdbc, err = s.crawlJDBC(roleCtx, row)
		tables = append(tables, jdbc...)
	}
	if err == nil {
		err = s.publishCrawl(roleCtx, row, tables, &run)
	}
	s.crawlerMu.Lock()
	delete(s.crawlerActive, run.Crawler)
	s.crawlerMu.Unlock()
	if s.lifetime.Err() != nil {
		return
	}
	if err := s.completeCrawl(context.WithoutCancel(ctx), run, err); err != nil {
		slog.Error("Complete Glue crawler", "crawler", row.Key.ARN("crawler"), "error", err)
	}
	s.jobs.Wake()
}
func crawlerFailure(err error) string {
	if errors.Is(err, ErrNotFound) {
		return "EntityNotFoundException: a crawler dependency was not found."
	}
	if errors.Is(err, context.Canceled) {
		return "Crawler was cancelled."
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Crawler source operation timed out."
	}
	if err == nil {
		return ""
	}
	// External database/library errors may include source values or credentials.
	// Only modeled, service-owned failure messages cross this diagnostic boundary.
	wire := wireError(err)
	if wire.Code == "InternalServiceException" {
		return "InternalServiceException: crawler execution failed."
	}
	return wire.Code + ": " + wire.Message
}
func (s *Service) completeCrawl(ctx context.Context, claim CrawlRecord, executionErr error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Crawl(claim.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.State != "RUNNING" && current.State != "CANCELLING" {
			return nil
		}
		row, err := tx.Crawler(current.Crawler)
		if err != nil {
			return err
		}
		if row.RunID != claim.ID {
			return nil
		}
		state, eventState := "SUCCEEDED", "Succeeded"
		if current.State == "CANCELLING" || errors.Is(executionErr, context.Canceled) {
			state, eventState = "CANCELLED", "Cancelled"
		} else if executionErr != nil {
			state, eventState = "FAILED", "Failed"
		}
		current.State, current.Phase = state, "COMPLETE"
		current.Completed = new(s.clock.Now().UTC())
		current.ErrorMessage = crawlerFailure(executionErr)
		current.TablesCreated, current.TablesUpdated, current.PartitionsCreated = claim.TablesCreated, claim.TablesUpdated, claim.PartitionsCreated
		row.Crawler.State = new(api.CrawlerStateREADY)
		row.Crawler.CrawlElapsedTime = new(api.MillisecondsCount(max(0, current.Completed.Sub(current.Started).Milliseconds())))
		row.Crawler.LastCrawl = &api.LastCrawlInfo{Status: new(api.LastCrawlStatus(state)), StartTime: &current.Started}
		if current.ErrorMessage != "" {
			row.Crawler.LastCrawl.ErrorMessage = new(api.DescriptionString(current.ErrorMessage))
		}
		if err := tx.PutCrawl(current); err != nil {
			return err
		}
		if err := tx.PutCrawler(row); err != nil {
			return err
		}
		return s.crawlerEvent(tx.Context(), row, eventState, current.ErrorMessage)
	})
}

// StartTriggeredCrawler is retained admission only. Trigger authorization belongs
// to the trigger command; actual execution still assumes the current crawler role.
func (s *Service) StartTriggeredCrawler(ctx context.Context, scope Scope, name, trigger, workflow, workflowRun string) (string, error) {
	if awsctx.FromContext(ctx).ServicePrincipal.Name != "glue.amazonaws.com" {
		return "", failure("AccessDeniedException", "Only the Glue trigger controller may use internal crawler admission.")
	}
	var id string
	err := s.repository.Update(ctx, func(tx Transaction) error {
		row, err := tx.Crawler(ResourceKey{Scope: scope, Name: name})
		if err != nil {
			return err
		}
		id, err = s.admitCrawl(tx.Context(), tx, row, trigger, workflow, workflowRun)
		return err
	})
	if err == nil {
		s.jobs.Wake()
	}
	return id, err
}
func (s *Service) CrawlerRunState(ctx context.Context, scope Scope, name, id string) (string, error) {
	var state string
	err := s.repository.View(ctx, func(r Reader) error {
		run, err := r.Crawl(id)
		if err != nil {
			return err
		}
		if run.Crawler != (ResourceKey{Scope: scope, Name: name}) {
			return ErrNotFound
		}
		state = run.State
		return nil
	})
	return state, err
}
func (s *Service) StopTriggeredCrawler(ctx context.Context, scope Scope, name, id string) error {
	if awsctx.FromContext(ctx).ServicePrincipal.Name != "glue.amazonaws.com" {
		return failure("AccessDeniedException", "Only the Glue trigger controller may use internal crawler cancellation.")
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		row, err := tx.Crawler(ResourceKey{Scope: scope, Name: name})
		if err != nil {
			return err
		}
		if row.RunID != id {
			return ErrNotFound
		}
		return s.stopCrawl(tx, row)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return err
}
