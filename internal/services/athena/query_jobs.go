package athena

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	api "stackd/internal/awsapi/athena"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// Start fails interrupted native execution instead of replaying potentially
// mutating SQL. Retained handles remain scheduled until cancellation succeeds.
func (s *Service) Start() error {
	err := s.repository.Update(s.lifetime, func(tx Transaction) error {
		rows, err := tx.ActiveQueries()
		if err != nil {
			return err
		}
		for _, v := range rows {
			if queryState(v) != "RUNNING" {
				continue
			}
			previous := queryState(v)
			markFailure(&v, s.clock.Now(), "Query execution was interrupted by controller restart.", 1)
			if err := s.putTransition(tx, v, previous); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("athena service is closed")
	}
	s.started = true
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
func queryJobKey(key ResourceKey) string {
	return key.Partition + "/" + key.AccountID + "/" + key.Region + "/" + key.Name
}
func parseQueryJobKey(key string) (ResourceKey, error) {
	v := strings.SplitN(key, "/", 4)
	if len(v) != 4 {
		return ResourceKey{}, errors.New("invalid Athena query job key")
	}
	return ResourceKey{Scope: Scope{v[0], v[1], v[2]}, Name: v[3]}, nil
}

type queryJobs struct{ s *Service }

func (j queryJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	s := j.s
	s.mu.Lock()
	enabled := s.started && !s.closed
	s.mu.Unlock()
	if !enabled {
		return
	}
	err = s.repository.View(ctx, func(r Reader) error {
		v, err := r.NextQuery()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		job = scheduler.Job{Key: queryJobKey(v.Key), Version: uint64(v.Version), Due: v.Due}
		found = true
		return nil
	})
	return
}
func (j queryJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	key, err := parseQueryJobKey(job.Key)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if !s.started || s.closed {
		s.mu.Unlock()
		return nil
	}
	s.work.Add(1)
	s.mu.Unlock()
	var request ExecutionRequest
	launch, cleanup := false, false
	err = s.repository.Update(ctx, func(tx Transaction) error {
		v, err := tx.Query(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if uint64(v.Version) != job.Version || v.Due.After(s.clock.Now()) {
			return nil
		}
		state := queryState(v)
		if (state == "CANCELLED" || state == "FAILED") && v.EngineID != "" {
			v.Due = s.clock.Now().Add(time.Second)
			s.mu.Lock()
			busy := s.cleaning[v.Key]
			if !busy {
				s.cleaning[v.Key] = true
				cleanup = true
			}
			s.mu.Unlock()
			if busy {
				return tx.PutQuery(v)
			}
			v.Version++
			if err := tx.PutQuery(v); err != nil {
				return err
			}
			request.Query = v
			launch = true
			return nil
		}
		if state != "QUEUED" {
			return nil
		}
		caller := awsctx.WithMetadata(tx.Context(), v.Caller)
		_, rejected := s.loadWorkGroup(caller, tx, value(v.Data.WorkGroup), "StartQueryExecution")
		if rejected != nil {
			markFailure(&v, s.clock.Now(), wireError(rejected).Message, 2)
			return s.putTransition(tx, v, state)
		}
		catalogName := "AwsDataCatalog"
		if v.Data.QueryExecutionContext != nil && value(v.Data.QueryExecutionContext.Catalog) != "" {
			catalogName = value(v.Data.QueryExecutionContext.Catalog)
		}
		var catalog CatalogRecord
		if strings.EqualFold(catalogName, "AwsDataCatalog") {
			catalog = defaultCatalog(ResourceKey{Scope: v.Key.Scope, Name: "AwsDataCatalog"})
		} else {
			catalog, rejected = s.loadCatalog(caller, tx, catalogName, "GetDataCatalog")
			if rejected != nil {
				markFailure(&v, s.clock.Now(), wireError(rejected).Message, 2)
				return s.putTransition(tx, v, state)
			}
		}
		prepared, err := tx.PreparedStatements(ResourceQuery{Scope: v.Key.Scope, WorkGroup: value(v.Data.WorkGroup)})
		if err != nil {
			return err
		}
		request.PreparedStatements = make([]api.PreparedStatement, len(prepared))
		for i, p := range prepared {
			request.PreparedStatements[i] = p.Data
		}
		request.Catalog = catalog.Data
		now := s.clock.Now()
		v.Started = &now
		v.Version++
		v.Data.Status.State = new(api.QueryExecutionState("RUNNING"))
		v.Data.Statistics = &api.QueryExecutionStatistics{QueryQueueTimeInMillis: new(api.Long(now.Sub(*v.Data.Status.SubmissionDateTime).Milliseconds())), ResultReuseInformation: &api.ResultReuseInformation{ReusedPreviousResult: new(api.Boolean(false))}}
		if err := s.putTransition(tx, v, state); err != nil {
			return err
		}
		request.Query = v
		launch = true
		return nil
	})
	if err != nil || !launch {
		if cleanup {
			s.mu.Lock()
			delete(s.cleaning, key)
			s.mu.Unlock()
		}
		s.work.Done()
		return err
	}
	go func() {
		defer s.work.Done()
		if cleanup {
			s.cleanupExecution(request.Query)
			return
		}
		s.executeQuery(request)
	}()
	return nil
}
func (s *Service) cleanupExecution(v QueryRecord) {
	defer func() { s.mu.Lock(); delete(s.cleaning, v.Key); s.mu.Unlock(); s.jobs.Wake() }()
	s.mu.Lock()
	cancel := s.running[v.Key]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if s.engine == nil {
		return
	}
	if err := s.engine.Cancel(s.lifetime, v.EngineID); err != nil {
		if s.lifetime.Err() == nil {
			slog.Error("cancel Athena native execution", "query", v.Key.Name, "error", err)
		}
		return
	}
	err := s.repository.Update(s.lifetime, func(tx Transaction) error {
		current, err := tx.Query(v.Key)
		if err != nil {
			return err
		}
		if current.EngineID != v.EngineID {
			return nil
		}
		state := queryState(current)
		if state != "CANCELLED" && state != "FAILED" {
			return nil
		}
		current.EngineID = ""
		current.Version++
		return tx.PutQuery(current)
	})
	if err != nil && s.lifetime.Err() == nil {
		slog.Error("retain Athena cancellation", "query", v.Key.Name, "error", err)
	}
	s.jobs.Wake()
}
func (s *Service) executeQuery(request ExecutionRequest) {
	v := request.Query
	ctx, cancel := context.WithCancel(s.lifetime)
	defer cancel()
	ctx = awsctx.WithMetadata(ctx, v.Caller)
	s.mu.Lock()
	s.running[v.Key] = cancel
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.running, v.Key); s.mu.Unlock() }()
	started := func(id string) error {
		if id == "" {
			return errors.New("athena runtime returned an empty execution handle")
		}
		return s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Query(v.Key)
			if err != nil {
				return err
			}
			if queryState(current) != "RUNNING" || current.Version != v.Version {
				return context.Canceled
			}
			current.EngineID = id
			return tx.PutQuery(current)
		})
	}
	var result ExecutionResult
	var executionError error
	if s.engine == nil {
		executionError = errors.New("athena SQL engine is not configured")
	} else {
		result, executionError = s.engine.Execute(ctx, request, started)
	}
	if s.lifetime.Err() != nil {
		return
	}
	// Recheck cancellation after native completion and before any result writes.
	var current QueryRecord
	err := s.repository.View(s.lifetime, func(r Reader) error { var err error; current, err = r.Query(v.Key); return err })
	if err != nil {
		slog.Error("read Athena completion state", "query", v.Key.Name, "error", err)
		return
	}
	if queryState(current) == "CANCELLED" {
		s.completeCancelled(v, result)
		s.jobs.Wake()
		return
	}
	if queryState(current) != "RUNNING" || current.Version != v.Version {
		s.jobs.Wake()
		return
	}
	if executionError == nil && v.BytesCutoff > 0 && result.DataScannedBytes > v.BytesCutoff {
		executionError = &ExecutionFailure{Message: fmt.Sprintf("Query exceeded the workgroup data scan limit of %d bytes", v.BytesCutoff), Cancelled: true}
	}
	if executionError == nil && result.StatementType == "DDL" {
		configuration := api.CloneResultConfiguration(*v.Data.ResultConfiguration)
		configuration.OutputLocation = new(api.ResultOutputLocation(strings.TrimSuffix(value(configuration.OutputLocation), ".csv") + ".txt"))
		v.Data.ResultConfiguration = &configuration
	}
	if executionError == nil {
		if s.results == nil {
			executionError = errors.New("athena S3 results adapter is not configured")
		} else if rejected := s.results.Write(ctx, v, result.CSV); rejected != nil {
			executionError = rejected
		}
	}
	if s.lifetime.Err() != nil {
		return
	}
	err = s.repository.Update(s.lifetime, func(tx Transaction) error {
		current, err := tx.Query(v.Key)
		if err != nil {
			return err
		}
		if queryState(current) == "CANCELLED" {
			return s.retainCancelled(tx, current, result)
		}
		if queryState(current) != "RUNNING" || current.Version != v.Version {
			return nil
		}
		previous := queryState(current)
		now := s.clock.Now()
		if executionError != nil {
			var classified *ExecutionFailure
			if errors.As(executionError, &classified) && classified.Cancelled {
				current.Version++
				current.Due = now
				current.Data.Status.State = new(api.QueryExecutionState("CANCELLED"))
				current.Data.Status.StateChangeReason = new(api.String(classified.Message))
				current.Data.Status.CompletionDateTime = &now
			} else {
				markFailure(&current, now, executionError.Error(), 2)
				if classified != nil {
					current.Data.Status.AthenaError = &api.AthenaError{ErrorCategory: new(api.ErrorCategory(classified.Category)), ErrorType: new(api.ErrorType(classified.Type)), Retryable: new(api.Boolean(classified.Retryable)), ErrorMessage: new(api.String(classified.Message))}
				}
			}
		} else {
			current.Version++
			current.Due = now
			current.EngineID = ""
			current.Data.Status.State = new(api.QueryExecutionState("SUCCEEDED"))
			current.Data.Status.CompletionDateTime = &now
			current.Columns = result.Columns
			current.UpdateCount = result.UpdateCount
			current.Data.ResultConfiguration = v.Data.ResultConfiguration
		}
		if result.StatementType != "" {
			current.Data.StatementType = new(api.StatementType(result.StatementType))
		}
		if result.SubstatementType != "" {
			current.Data.SubstatementType = new(api.String(result.SubstatementType))
		}
		if current.Data.Statistics == nil {
			current.Data.Statistics = &api.QueryExecutionStatistics{}
		}
		stats := current.Data.Statistics
		stats.EngineExecutionTimeInMillis = new(api.Long(result.EngineMillis))
		stats.DataScannedInBytes = new(api.Long(result.DataScannedBytes))
		queueMillis := int64(0)
		if stats.QueryQueueTimeInMillis != nil {
			queueMillis = int64(*stats.QueryQueueTimeInMillis)
		}
		// Native elapsed work can exceed a frozen manual service-clock interval.
		// Do not report a total smaller than its measured engine and queue components.
		totalMillis := max(now.Sub(*current.Data.Status.SubmissionDateTime).Milliseconds(), queueMillis+result.EngineMillis)
		stats.TotalExecutionTimeInMillis = new(api.Long(totalMillis))
		stats.ResultReuseInformation = &api.ResultReuseInformation{ReusedPreviousResult: new(api.Boolean(false))}
		if result.ManifestLocation != "" {
			stats.DataManifestLocation = new(api.String(result.ManifestLocation))
		}
		return s.putTransition(tx, current, previous)
	})
	if err != nil {
		slog.Error("commit Athena execution result", "query", v.Key.Name, "error", err)
	}
	s.jobs.Wake()
}
func markFailure(v *QueryRecord, now time.Time, reason string, category int32) {
	v.Version++
	v.Due = now
	if v.Data.Status == nil {
		v.Data.Status = &api.QueryExecutionStatus{}
	}
	v.Data.Status.State = new(api.QueryExecutionState("FAILED"))
	v.Data.Status.StateChangeReason = new(api.String(reason))
	v.Data.Status.CompletionDateTime = &now
	v.Data.Status.AthenaError = &api.AthenaError{ErrorCategory: new(api.ErrorCategory(category)), ErrorType: new(api.ErrorType(1000)), Retryable: new(api.Boolean(false)), ErrorMessage: new(api.String(reason))}
}
func (s *Service) putTransition(tx Transaction, v QueryRecord, previous string) error {
	if err := tx.PutQuery(v); err != nil {
		return err
	}
	ctx := awsctx.WithMetadata(tx.Context(), v.Caller)
	m := awsctx.FromContext(ctx)
	m.ParentEventID = v.ParentEventID
	ctx = awsctx.WithMetadata(ctx, m)
	if s.events != nil {
		if err := s.events.Publish(ctx, QueryEvent{Query: v, PreviousState: previous}); err != nil {
			return err
		}
	}
	if queryState(v) == "CANCELLED" && v.Started != nil && (v.Data.Statistics == nil || v.Data.Statistics.EngineExecutionTimeInMillis == nil) {
		return nil
	}
	return s.publishQueryMetrics(ctx, v)
}
