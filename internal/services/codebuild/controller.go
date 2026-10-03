package codebuild

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	runtime "stackd/compute/codebuild"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"strings"
	"sync"
	"time"
)

type controller struct {
	s        *Service
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	started  bool
	closed   bool
	wakeups  chan struct{}
	active   map[BuildKey]bool
	sessions map[BuildKey]buildSession
	work     sync.WaitGroup
}

func newController(s *Service) *controller {
	ctx, cancel := context.WithCancel(context.Background())
	return &controller{s: s, ctx: ctx, cancel: cancel, wakeups: make(chan struct{}, 1), active: map[BuildKey]bool{}, sessions: map[BuildKey]buildSession{}}
}
func (s *Service) Start() error {
	c := s.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("CodeBuild controller is closed")
	}
	if c.started {
		return nil
	}
	c.started = true
	c.work.Add(1)
	go c.run()
	return nil
}
func (s *Service) Close() error {
	c := s.controller
	c.mu.Lock()
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	c.work.Wait()
	s.jobs.Close()
	return nil
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (c *controller) wake() {
	select {
	case c.wakeups <- struct{}{}:
	default:
	}
}
func (c *controller) run() {
	defer c.work.Done()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := c.scan(); err != nil && c.ctx.Err() == nil {
			slog.Error("CodeBuild controller reconciliation failed", "error", err)
		}
		select {
		case <-c.ctx.Done():
			return
		case <-c.wakeups:
		case <-ticker.C:
		}
	}
}
func (c *controller) scan() error {
	if c.s.executor == nil {
		return nil
	}
	if err := c.reconcileFleets(); err != nil {
		return err
	}
	var rows []BuildRecord
	if err := c.s.repository.View(c.ctx, func(r Reader) error { var err error; rows, err = r.ActiveBuilds(); return err }); err != nil {
		return err
	}
	for _, r := range rows {
		c.mu.Lock()
		running := c.active[r.Key]
		c.mu.Unlock()
		if running {
			continue
		}
		if !complete(r) && !r.StopRequested && r.Deadline.IsZero() {
			ready, err := c.claim(r.Key)
			if err != nil {
				return err
			}
			if !ready {
				continue
			}
		}
		c.mu.Lock()
		c.active[r.Key] = true
		c.work.Add(1)
		c.mu.Unlock()
		go func(key BuildKey) {
			defer c.work.Done()
			defer func() { c.mu.Lock(); delete(c.active, key); c.mu.Unlock() }()
			if err := c.execute(key); err != nil && c.ctx.Err() == nil {
				slog.Error("CodeBuild execution reconciliation failed", "build", key.ARN(), "error", err)
			}
		}(r.Key)
	}
	return nil
}
func (c *controller) claim(key BuildKey) (bool, error) {
	ready := false
	finished := false
	err := c.s.repository.Update(c.ctx, func(tx Transaction) error {
		r, err := tx.Build(key)
		if err != nil {
			return err
		}
		if !r.Deadline.IsZero() || r.StopRequested || complete(r) {
			ready = true
			return nil
		}
		all, err := tx.Builds(key.Scope)
		if err != nil {
			return err
		}
		project, err := tx.Project(ProjectKey{key.Scope, value(r.Data.ProjectName)})
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		limit := int32(0)
		if project.Data.ConcurrentBuildLimit != nil {
			limit = int32(*project.Data.ConcurrentBuildLimit)
		}
		projectActive, fleetActive := int32(0), int32(0)
		for _, b := range all {
			if b.Key == key || b.Deadline.IsZero() {
				continue
			}
			if !complete(b) && value(b.Data.ProjectName) == value(r.Data.ProjectName) {
				projectActive++
			}
			if b.FleetARN == r.FleetARN && (!complete(b) || b.CleanupPending) {
				fleetActive++
			}
		}
		if limit > 0 && projectActive >= limit {
			return nil
		}
		if r.FleetARN != "" {
			fleet, err := fleetFor(tx, key.Scope, r.FleetARN)
			if errors.Is(err, ErrNotFound) {
				finished = true
				return c.finishBuild(tx, r, "FAILED", "The build's compute fleet no longer exists.")
			}
			if err != nil {
				return err
			}
			if value(fleet.Data.Status.StatusCode) != "ACTIVE" {
				return nil
			}
			if fleetActive >= int32(*fleet.Data.BaseCapacity) {
				if value(fleet.Data.OverflowBehavior) != "ON_DEMAND" {
					return nil
				}
				r.FleetARN = ""
			}
		}
		now := c.s.clock.Now()
		r.Deadline = now.Add(time.Duration(*r.Data.TimeoutInMinutes) * time.Minute)
		finishPhase(&r, "QUEUED", "SUCCEEDED", "", now)
		startPhase(&r, "DOWNLOAD_SOURCE", now)
		ready = true
		return c.s.putBuild(tx.Context(), tx, r, true)
	})
	if err == nil && (ready || finished) {
		c.s.jobs.Wake()
	}
	return ready, err
}
func ownerContext(ctx context.Context, r BuildRecord) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: r.Key.Partition, AccountID: r.Key.AccountID, Region: r.Key.Region, ParentEventID: r.AcceptedEventID, InvokedBy: "codebuild.amazonaws.com", SourceIP: "codebuild.amazonaws.com", UserAgent: "codebuild.amazonaws.com"})
}
func (c *controller) load(key BuildKey) (BuildRecord, error) {
	var r BuildRecord
	err := c.s.repository.View(c.ctx, func(rd Reader) error { var err error; r, err = rd.Build(key); return err })
	return r, err
}
func (c *controller) execute(key BuildKey) error {
	r, err := c.load(key)
	if err != nil {
		return err
	}
	if complete(r) {
		return c.cleanup(r)
	}
	ctx := ownerContext(c.ctx, r)
	execution, err := c.s.executor.Open(ctx, key.ARN())
	if err != nil && !errors.Is(err, runtime.ErrNotFound) {
		return err
	}
	if execution == nil && r.StopRequested {
		return c.finish(r, terminalStop(r), "Build was stopped before execution.")
	}
	if execution == nil && value(r.Data.CurrentPhase) != "PROVISIONING" && value(r.Data.CurrentPhase) != "DOWNLOAD_SOURCE" {
		return c.finish(r, "FAILED", "The retained build container no longer exists; commands were not replayed.")
	}
	if execution == nil {
		if err = c.phase(key, "DOWNLOAD_SOURCE"); err != nil {
			return err
		}
		prepareCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go c.watchPreparation(prepareCtx, key, cancel, done)
		spec, prepareErr := c.s.specification(prepareCtx, r)
		if prepareErr == nil {
			execution, prepareErr = c.s.executor.Prepare(prepareCtx, spec)
		}
		close(done)
		cancel()
		if c.ctx.Err() != nil {
			return nil
		}
		latest, loadErr := c.load(key)
		if loadErr != nil {
			return loadErr
		}
		r = latest
		if prepareErr != nil {
			if r.StopRequested {
				return c.stopAndFinish(r, execution)
			}
			return c.fail(r, prepareErr.Error())
		}
		if r.StopRequested {
			return c.stopAndFinish(r, execution)
		}
		if err = c.prepared(key); err != nil {
			execution.Close()
			return err
		}
	}
	defer execution.Close()
	if err = execution.Start(ctx); err != nil {
		if c.ctx.Err() != nil {
			return nil
		}
		return c.fail(r, err.Error())
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		r, err = c.load(key)
		if err != nil {
			return err
		}
		if r.StopRequested {
			return c.stopAndFinish(r, execution)
		}
		status, inspectErr := execution.Inspect(ctx)
		if inspectErr != nil {
			if c.ctx.Err() != nil {
				return nil
			}
			return inspectErr
		}
		if err = c.observe(r, status); err != nil {
			return err
		}
		if err = c.publishLogs(ctx, r, execution); err != nil {
			if c.ctx.Err() != nil {
				return nil
			}
			if stopErr := execution.Stop(ctx); stopErr != nil {
				return stopErr
			}
			return c.finish(r, "FAILED", "CloudWatch Logs delivery failed: "+err.Error())
		}
		if status.State == "exited" {
			r, err = c.load(key)
			if err != nil {
				return err
			}
			if err = c.phase(key, "UPLOAD_ARTIFACTS"); err != nil {
				return err
			}
			publicationErr := c.publishOutputs(ctx, r, execution, status.ArtifactNames)
			if c.ctx.Err() != nil {
				return nil
			}
			if err = c.completeUpload(key, publicationErr); err != nil {
				return err
			}
			latest, e := c.load(key)
			if e != nil {
				return e
			}
			if latest.StopRequested {
				return c.stopAndFinish(latest, execution)
			}
			result, message := "SUCCEEDED", ""
			if status.ExitCode != 0 {
				result = "FAILED"
				message = status.Error
				if message == "" {
					message = "Build command exited with a non-zero status."
				}
			}
			if publicationErr != nil {
				result = "FAILED"
				message = "Artifact or cache upload failed: " + publicationErr.Error()
			}
			return c.finish(latest, result, message)
		}
		select {
		case <-c.ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (c *controller) watchPreparation(ctx context.Context, key BuildKey, cancel context.CancelFunc, done <-chan struct{}) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			r, err := c.load(key)
			if err == nil && r.StopRequested {
				cancel()
				return
			}
		}
	}
}
func terminalStop(r BuildRecord) string {
	if r.Failure == "BUILD_TIMED_OUT" {
		return "TIMED_OUT"
	}
	return "STOPPED"
}
func (c *controller) stopAndFinish(r BuildRecord, e runtime.Execution) error {
	message := "Build execution was terminated."
	if e == nil {
		var err error
		e, err = c.s.executor.Open(c.ctx, r.Key.ARN())
		if err != nil && !errors.Is(err, runtime.ErrNotFound) {
			return err
		}
	}
	if e != nil {
		defer e.Close()
		if err := e.Stop(c.ctx); err != nil {
			return err
		}
		if err := c.publishLogs(ownerContext(c.ctx, r), r, e); err != nil {
			message += " Final CloudWatch Logs delivery failed: " + wireError(err).Code + "."
		}
	}
	return c.finish(r, terminalStop(r), message)
}
func (c *controller) finish(r BuildRecord, status, message string) error {
	err := c.s.repository.Update(c.ctx, func(tx Transaction) error {
		current, err := tx.Build(r.Key)
		if err != nil {
			return err
		}
		return c.finishBuild(tx, current, status, message)
	})
	if err != nil {
		return err
	}
	c.s.jobs.Wake()
	return nil
}
func (c *controller) finishBuild(tx Transaction, current BuildRecord, status, message string) error {
	if complete(current) {
		return nil
	}
	if current.StopRequested {
		status = terminalStop(current)
	}
	phaseStatus := status
	if status == "TIMED_OUT" {
		message = "Build has timed out. "
		if value(current.Data.CurrentPhase) != "QUEUED" {
			status = "FAILED"
		}
	}
	now := c.s.clock.Now()
	finishPhase(&current, value(current.Data.CurrentPhase), phaseStatus, message, now)
	current.Data.BuildStatus = new(api.StatusType(status))
	current.Data.BuildComplete = new(api.Boolean(true))
	current.Data.EndTime = &now
	current.Data.CurrentPhase = new(api.String("COMPLETED"))
	current.Data.Phases = append(current.Data.Phases, api.BuildPhase{PhaseType: new(api.BuildPhaseType("COMPLETED")), StartTime: &now})
	current.CleanupPending = true
	current.Failure = message
	return c.s.putBuild(ownerContext(tx.Context(), current), tx, current, true)
}
func (c *controller) cleanup(r BuildRecord) error {
	if !r.DeleteRequested && !r.CleanupPending {
		return nil
	}
	if err := c.s.executor.Remove(c.ctx, r.Key.ARN()); err != nil {
		return err
	}
	return c.s.repository.Update(c.ctx, func(tx Transaction) error {
		latest, err := tx.Build(r.Key)
		if err != nil {
			return err
		}
		if latest.DeleteRequested {
			return tx.DeleteBuild(r.Key)
		}
		latest.CleanupPending = false
		latest.CredentialToken = ""
		return tx.PutBuild(latest)
	})
}
func startPhase(r *BuildRecord, name string, now time.Time) {
	r.Data.CurrentPhase = new(api.String(name))
	for _, p := range r.Data.Phases {
		if value(p.PhaseType) == name {
			return
		}
	}
	r.Data.Phases = append(r.Data.Phases, api.BuildPhase{PhaseType: new(api.BuildPhaseType(name)), StartTime: &now})
}
func finishPhase(r *BuildRecord, name, status, message string, now time.Time) {
	for i := range r.Data.Phases {
		p := &r.Data.Phases[i]
		if value(p.PhaseType) != name || p.EndTime != nil {
			continue
		}
		p.PhaseStatus = new(api.StatusType(status))
		p.EndTime = &now
		if p.StartTime != nil {
			p.DurationInSeconds = new(api.WrapperLong(max(0, int64(now.Sub(*p.StartTime)/time.Second))))
		}
		code := status
		if status == "TIMED_OUT" {
			code = "BUILD_TIMED_OUT"
		}
		if status == "FAILED" && (name == "INSTALL" || name == "PRE_BUILD" || name == "BUILD" || name == "POST_BUILD") {
			code = "COMMAND_EXECUTION_ERROR"
		}
		if message != "" {
			p.Contexts = api.PhaseContexts{{Message: new(api.String(message)), StatusCode: new(api.String(code))}}
		}
	}
}
func (c *controller) phase(key BuildKey, name string) error {
	return c.s.repository.Update(c.ctx, func(tx Transaction) error {
		r, err := tx.Build(key)
		if err != nil {
			return err
		}
		if value(r.Data.CurrentPhase) == name {
			return nil
		}
		now := c.s.clock.Now()
		finishPhase(&r, value(r.Data.CurrentPhase), "SUCCEEDED", "", now)
		startPhase(&r, name, now)
		return c.s.putBuild(ownerContext(tx.Context(), r), tx, r, true)
	})
}
func (c *controller) observe(r BuildRecord, status runtime.Status) error {
	return c.s.repository.Update(c.ctx, func(tx Transaction) error {
		current, err := tx.Build(r.Key)
		if err != nil {
			return err
		}
		now := c.s.clock.Now()
		changed := false
		for _, phase := range status.Phases {
			name := strings.ToUpper(phase.Name)
			if name != "PRE_BUILD" && name != "BUILD" && name != "POST_BUILD" && name != "INSTALL" {
				continue
			}
			done := false
			for _, old := range current.Data.Phases {
				if value(old.PhaseType) == name && old.EndTime != nil {
					done = true
					break
				}
			}
			if done {
				continue
			}
			if value(current.Data.CurrentPhase) != name {
				finishPhase(&current, value(current.Data.CurrentPhase), "SUCCEEDED", "", now)
				startPhase(&current, name, now)
				changed = true
			}
			if phase.Status != "RUNNING" {
				finishPhase(&current, name, phase.Status, phase.Message, now)
				changed = true
			}
		}
		if len(status.ExportedVariables) > 0 {
			current.Data.ExportedEnvironmentVariables = nil
			for name, value := range status.ExportedVariables {
				current.Data.ExportedEnvironmentVariables = append(current.Data.ExportedEnvironmentVariables, api.ExportedEnvironmentVariable{Name: new(api.NonEmptyString(name)), Value: new(api.String(value))})
			}
			slices.SortFunc(current.Data.ExportedEnvironmentVariables, func(a, b api.ExportedEnvironmentVariable) int { return strings.Compare(value(a.Name), value(b.Name)) })
		}
		return c.s.putBuild(ownerContext(tx.Context(), current), tx, current, changed)
	})
}
func (c *controller) completeUpload(key BuildKey, uploadErr error) error {
	return c.s.repository.Update(c.ctx, func(tx Transaction) error {
		r, err := tx.Build(key)
		if err != nil {
			return err
		}
		status, message := "SUCCEEDED", ""
		if uploadErr != nil {
			status, message = "FAILED", uploadErr.Error()
		}
		finishPhase(&r, "UPLOAD_ARTIFACTS", status, message, c.s.clock.Now())
		return tx.PutBuild(r)
	})
}
func (c *controller) fail(r BuildRecord, message string) error {
	execution, err := c.s.executor.Open(c.ctx, r.Key.ARN())
	if err != nil && !errors.Is(err, runtime.ErrNotFound) {
		return err
	}
	if execution != nil {
		defer execution.Close()
		if err = execution.Stop(c.ctx); err != nil {
			return err
		}
	}
	return c.finish(r, "FAILED", message)
}

// Native Prepare includes source materialization and image/container readiness.
// Do not fabricate a separate successful PROVISIONING phase before it returns.
func (c *controller) prepared(key BuildKey) error {
	return c.s.repository.Update(c.ctx, func(tx Transaction) error {
		r, err := tx.Build(key)
		if err != nil {
			return err
		}
		finishPhase(&r, "DOWNLOAD_SOURCE", "SUCCEEDED", "", c.s.clock.Now())
		return c.s.putBuild(ownerContext(tx.Context(), r), tx, r, true)
	})
}
