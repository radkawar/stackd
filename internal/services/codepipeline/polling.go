package codepipeline

import (
	"context"
	"fmt"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"strings"
	"time"
)

// AWS does not specify a polling cadence. The emulator uses one minute of
// service time, independently of the recoverable in-flight observation lease.
const sourcePollInterval = time.Minute
const sourcePollLease = 30 * time.Second
const sourcePollInactive = 30 * 24 * time.Hour

func pollingEnabled(a api.ActionDeclaration) bool {
	flag, present := a.Configuration["PollForSourceChanges"]
	// Native admits nonempty strings: true is case-insensitive, while values
	// such as "yes" and "1" disable polling. Omission defaults to enabled.
	return a.ActionTypeId != nil && text(a.ActionTypeId.Category) == "Source" &&
		text(a.ActionTypeId.Provider) == "S3" && (!present || strings.EqualFold(string(flag), "true"))
}

func sourcePollJob(p SourcePoll) scheduler.Job {
	return scheduler.Job{Key: ARN(p.Scope, p.PipelineName) + "/" + p.Incarnation + "/source/" + p.StageName + "/" + p.ActionName, Version: uint64(p.Generation), Due: p.Due}
}
func nextSourcePoll(r Reader) (SourcePoll, bool, error) {
	rows, err := r.PendingSourcePolls()
	if err != nil {
		return SourcePoll{}, false, err
	}
	var selected SourcePoll
	found := false
	for _, p := range rows {
		if !found || scheduler.Compare(sourcePollJob(p), sourcePollJob(selected)) < 0 {
			selected, found = p, true
		}
	}
	return selected, found, nil
}
func nextPipelineJob(r Reader) (scheduler.Job, bool, error) {
	e, hasExecution, err := nextExecution(r)
	if err != nil {
		return scheduler.Job{}, false, err
	}
	p, hasPoll, err := nextSourcePoll(r)
	if err != nil {
		return scheduler.Job{}, false, err
	}
	if hasPoll && (!hasExecution || scheduler.Compare(sourcePollJob(p), executionJob(e)) < 0) {
		return sourcePollJob(p), true, nil
	}
	return executionJob(e), hasExecution, nil
}

// Reconcile in the definition transaction. Versions fence every old observation;
// surviving source identities retain their independently consumed revisions.
func (s *Service) reconcileSourcePolls(tx Transaction, v Pipeline, d Definition) error {
	old, err := tx.SourcePolls(v.Scope, v.Incarnation)
	if err != nil {
		return err
	}
	if err = tx.DeleteSourcePolls(v.Scope, v.Incarnation); err != nil {
		return err
	}
	for _, stage := range d.Declaration.Stages {
		for _, a := range stage.Actions {
			if a.ActionTypeId == nil || text(a.ActionTypeId.Category) != "Source" || text(a.ActionTypeId.Provider) != "S3" {
				continue
			}
			p := SourcePoll{Scope: v.Scope, PipelineName: v.Name, Incarnation: v.Incarnation, PipelineVersion: v.Version,
				StageName: text(stage.Name), ActionName: text(a.Name), Bucket: string(a.Configuration["S3Bucket"]), ObjectKey: string(a.Configuration["S3ObjectKey"]),
				Generation: 1, ParentEventID: apievents.EventID(tx.Context())}
			if p.ParentEventID == "" {
				p.ParentEventID = awsctx.FromContext(tx.Context()).ParentEventID
			}
			for _, previous := range old {
				if previous.StageName == p.StageName && previous.ActionName == p.ActionName {
					p.Generation = previous.Generation + 1
					if previous.Bucket == p.Bucket && previous.ObjectKey == p.ObjectKey {
						p.RevisionID = previous.RevisionID
					}
					break
				}
			}
			// TODO: Comeback — calibrate native reactivation after automatic
			// inactivity disable before clearing retained pollingDisabledAt.
			if pollingEnabled(a) && v.PollingDisabledAt.IsZero() {
				p.Due = s.clock.Now().UTC()
			}
			if err = tx.PutSourcePoll(p); err != nil {
				return err
			}
		}
	}
	return nil
}

func sourcePollAction(d Definition, p SourcePoll) (api.ActionDeclaration, bool) {
	for _, stage := range d.Declaration.Stages {
		if text(stage.Name) != p.StageName {
			continue
		}
		for _, a := range stage.Actions {
			if text(a.Name) == p.ActionName {
				return a, pollingEnabled(a) && string(a.Configuration["S3Bucket"]) == p.Bucket && string(a.Configuration["S3ObjectKey"]) == p.ObjectKey
			}
		}
	}
	return api.ActionDeclaration{}, false
}

func (s *Service) disableInactivePolling(tx Transaction, v Pipeline, now time.Time) (bool, error) {
	rows, err := tx.Executions(v.Scope, v.Incarnation)
	if err != nil {
		return false, err
	}
	last := v.CreatedAt
	for _, e := range rows {
		if e.StartedAt.After(last) {
			last = e.StartedAt
		}
	}
	if v.PollingDisabledAt.IsZero() && !now.After(last.Add(sourcePollInactive)) {
		return false, nil
	}
	if v.PollingDisabledAt.IsZero() {
		v.PollingDisabledAt = now
		if err = tx.PutPipeline(v); err != nil {
			return false, err
		}
	}
	polls, err := tx.SourcePolls(v.Scope, v.Incarnation)
	if err != nil {
		return false, err
	}
	for _, p := range polls {
		p.Due, p.PollID = time.Time{}, ""
		p.Generation++
		if err = tx.PutSourcePoll(p); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (s *Service) runSourcePoll(ctx context.Context, selected scheduler.Job) error {
	var claim SourcePoll
	var request *SourcePollRequest
	err := s.repository.Update(ctx, func(tx Transaction) error {
		job, found, err := nextPipelineJob(tx)
		if err != nil || !found || job != selected {
			return err
		}
		p, found, err := nextSourcePoll(tx)
		if err != nil || !found || sourcePollJob(p) != selected || p.Due.After(s.clock.Now()) {
			return err
		}
		v, err := findPipeline(tx, p.Scope, p.PipelineName)
		if err != nil {
			if wireError(err).Code == "PipelineNotFoundException" {
				return tx.DeleteSourcePolls(p.Scope, p.Incarnation)
			}
			return err
		}
		if v.Incarnation != p.Incarnation || v.Version != p.PipelineVersion {
			p.Due = time.Time{}
			p.Generation++
			return tx.PutSourcePoll(p)
		}
		if disabled, err := s.disableInactivePolling(tx, v, s.clock.Now().UTC()); err != nil || disabled {
			return err
		}
		d, err := findDefinition(tx, v, v.Version)
		if err != nil {
			return err
		}
		a, enabled := sourcePollAction(d, p)
		if !enabled {
			p.Due = time.Time{}
			p.Generation++
			return tx.PutSourcePoll(p)
		}
		if p.PollID == "" {
			p.PollID, err = newID()
			if err != nil {
				return err
			}
		}
		p.Generation++
		p.Due = s.clock.Now().UTC().Add(sourcePollLease)
		if err = tx.PutSourcePoll(p); err != nil {
			return err
		}
		claim = p
		request = &SourcePollRequest{Scope: p.Scope, PipelineName: p.PipelineName, PipelineARN: ARN(p.Scope, p.PipelineName),
			Incarnation: p.Incarnation, PipelineVersion: p.PipelineVersion, RoleARN: text(d.Declaration.RoleArn),
			PollID: p.PollID, ParentEventID: p.ParentEventID, Action: a}
		return nil
	})
	if err != nil || request == nil {
		return err
	}
	effectCtx := awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: claim.Partition, AccountID: claim.AccountID, Region: claim.Region,
		ParentEventID: claim.ParentEventID, ServicePrincipal: awsctx.ServicePrincipal{Name: "codepipeline.amazonaws.com", SourceARN: request.PipelineARN, Type: "AWSService"}})
	var revision string
	if s.sources == nil {
		err = failure("NotImplementedException", "Source observer is not configured")
	} else {
		revision, err = s.sources.LatestSourceRevision(effectCtx, *request)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil && revision == "" {
		err = fmt.Errorf("source observer returned an empty revision")
	}
	observationErr := err
	return s.repository.Update(effectCtx, func(tx Transaction) error {
		v, err := findPipeline(tx, claim.Scope, claim.PipelineName)
		if err != nil {
			if wireError(err).Code == "PipelineNotFoundException" {
				return nil
			}
			return err
		}
		if v.Incarnation != claim.Incarnation || v.Version != claim.PipelineVersion || !v.PollingDisabledAt.IsZero() {
			return nil
		}
		rows, err := tx.SourcePolls(claim.Scope, claim.Incarnation)
		if err != nil {
			return err
		}
		for _, p := range rows {
			if p.StageName != claim.StageName || p.ActionName != claim.ActionName || p.Generation != claim.Generation || p.PollID != claim.PollID {
				continue
			}
			p.LastAttempt = s.clock.Now().UTC()
			p.ErrorCode, p.ErrorMessage = "", ""
			if observationErr == nil {
				if p.RevisionID != revision {
					d, err := findDefinition(tx, v, v.Version)
					if err != nil {
						return err
					}
					overrides := api.SourceRevisionOverrideList{{ActionName: new(api.ActionName(p.ActionName)), RevisionType: new(api.SourceRevisionType("S3_OBJECT_VERSION_ID")), RevisionValue: new(api.Revision(revision))}}
					if _, err = s.startExecution(tx, v, d, "", overrides, nil, "PollForSourceChanges"); err != nil {
						return err
					}
				}
				p.RevisionID = revision
			} else {
				rejected := wireError(observationErr)
				p.ErrorCode, p.ErrorMessage = rejected.Code, rejected.Message
			}
			p.Generation++
			p.PollID = ""
			p.Due = s.clock.Now().UTC().Add(sourcePollInterval)
			return tx.PutSourcePoll(p)
		}
		return nil
	})
}
