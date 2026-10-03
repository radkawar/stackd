package codepipeline

import (
	"context"
	"fmt"
	"slices"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"strings"
	"time"
)

type pipelineJobs struct{ s *Service }

func executionJob(e Execution) scheduler.Job {
	return scheduler.Job{Key: ARN(e.Scope, e.PipelineName) + "/" + e.Incarnation + fmt.Sprintf("/%020d/", e.Sequence) + e.ID, Version: uint64(e.Generation), Due: e.Due}
}
func nextExecution(r Reader) (Execution, bool, error) {
	rows, err := r.PendingExecutions()
	if err != nil {
		return Execution{}, false, err
	}
	var selected Execution
	found := false
	for _, e := range rows {
		if !found || scheduler.Compare(executionJob(e), executionJob(selected)) < 0 {
			selected = e
			found = true
		}
	}
	return selected, found, nil
}
func (j pipelineJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var selected scheduler.Job
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error { var err error; selected, found, err = nextPipelineJob(r); return err })
	return selected, found, err
}
func (j pipelineJobs) Run(ctx context.Context, selected scheduler.Job) error {
	if strings.Contains(selected.Key, "/source/") {
		return j.s.runSourcePoll(ctx, selected)
	}
	var request *ActionRequest
	var claim Execution
	var actionID string
	err := j.s.repository.Update(ctx, func(tx Transaction) error {
		job, found, err := nextPipelineJob(tx)
		if err != nil || !found || job != selected {
			return err
		}
		e, found, err := nextExecution(tx)
		if err != nil || !found || executionJob(e) != selected {
			return err
		}
		now := j.s.clock.Now().UTC()
		if e.Due.After(now) {
			return nil
		}
		v, err := findPipeline(tx, e.Scope, e.PipelineName)
		if err != nil || v.Incarnation != e.Incarnation {
			e.Due = time.Time{}
			e.Generation++
			return tx.PutExecution(e)
		}
		d, err := findDefinition(tx, v, e.Version)
		if err != nil {
			return err
		}
		before := e.Status
		req, err := j.s.advance(tx, v, d, &e)
		if err != nil {
			return err
		}
		if req != nil {
			e.Generation++
			e.Due = now.Add(30 * time.Second)
			if !req.ApprovalExpiresAt.IsZero() && req.ApprovalExpiresAt.Before(e.Due) {
				e.Due = req.ApprovalExpiresAt
			}
			if req.InvocationJob != nil && req.InvocationJob.ExpiresAt.Before(e.Due) &&
				(req.InvocationJob.Status == "Ready" || req.InvocationJob.Status == "Running") {
				e.Due = req.InvocationJob.ExpiresAt
			}
			request = req
			claim = e
			actionID = req.ActionExecutionID
		}
		if err = tx.PutExecution(e); err != nil {
			return err
		}
		if before != e.Status {
			if j.s.events != nil {
				if err = j.s.events.PipelineStateChanged(tx.Context(), v, e); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil || request == nil {
		return err
	}
	effectCtx := scopedContext(ctx, request.Scope)
	principal := "codepipeline.amazonaws.com"
	effectCtx = awsctx.WithServicePrincipal(effectCtx, awsctx.ServicePrincipal{Name: principal, SourceARN: request.PipelineARN, Type: "AWSService"})
	var result ActionResult
	if j.s.executor == nil {
		err = failure("NotImplementedException", "Action executor is not configured")
	} else {
		result, err = j.s.executor.Execute(effectCtx, *request)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		rejected := wireError(err)
		result = ActionResult{Status: "Failed", ErrorCode: rejected.Code, ErrorMessage: rejected.Message}
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		v, err := findPipeline(tx, claim.Scope, claim.PipelineName)
		if err != nil || v.Incarnation != claim.Incarnation {
			return nil
		}
		e, err := findExecution(tx, v, claim.ID)
		if err != nil {
			return err
		}
		if terminal(e.Status) {
			return nil
		}
		index := slices.IndexFunc(e.Actions, func(a ActionExecution) bool { return a.ID == actionID })
		if index < 0 || e.Actions[index].Status != "InProgress" {
			return nil
		}
		a := &e.Actions[index]
		if request.InvocationJob != nil {
			current, err := latestInvocationJob(tx, e.Scope, a.ID)
			if err != nil {
				return err
			}
			if current == nil || current.ID != request.InvocationJob.ID || current.Generation != request.InvocationJob.Generation || e.UpdatedDefinition {
				// A callback can arrive before the asynchronous Invoke returns.
				// Its result and any continuation always outrank this dispatch.
				return nil
			}
			if result.Status == "Succeeded" && current.Status != "Succeeded" {
				return fmt.Errorf("lambda invocation cannot succeed without a job callback")
			}
			if result.InvocationAccepted {
				if current.Status != "Ready" || result.Status != "InProgress" {
					return fmt.Errorf("invalid Lambda invocation acceptance")
				}
				current.Status = "Running"
				current.Generation++
				if err := tx.PutInvocationJob(*current); err != nil {
					return err
				}
			}
		}
		if e.Generation != claim.Generation && request.InvocationJob == nil {
			// Stop-and-wait and scheduler wakes keep the same approval alive.
			// Retain its successful publication even when those mutations move
			// the job generation; invalidation and a prior completion still fence it.
			if a.ApprovalToken == "" || e.UpdatedDefinition || a.ApprovalNotificationID != "" ||
				result.Status != "InProgress" || result.ApprovalNotificationID == "" {
				return nil
			}
		}
		now := j.s.clock.Now().UTC()
		if result.Status != "InProgress" && result.Status != "Succeeded" && result.Status != "Failed" {
			return fmt.Errorf("invalid provider action status %q", result.Status)
		}
		if a.ApprovalToken != "" {
			if result.Status == "Succeeded" || (result.Status == "InProgress" && result.ApprovalNotificationID == "") {
				return fmt.Errorf("approval notification did not return publication completion")
			}
			a.ApprovalNotificationID = result.ApprovalNotificationID
			if !now.Before(request.ApprovalExpiresAt) {
				result.Status = "Failed"
				result.Summary = ""
				result.ErrorCode = "ApprovalTimedOut"
				result.ErrorMessage = "Approval timed out"
			}
			if result.Status == "Failed" && result.ErrorCode != "ApprovalTimedOut" {
				if result.Summary == "" {
					result.Summary = result.ErrorMessage
				}
				// Manual history identifies the approval attempt, never the SNS
				// publication. The failed status keeps its token undiscoverable.
				a.ExternalExecutionID = a.ID
			}
		} else if result.ExternalExecutionID != "" {
			a.ExternalExecutionID = result.ExternalExecutionID
		}
		a.ExternalExecutionURL = result.ExternalExecutionURL
		a.Summary = result.Summary
		a.ErrorCode = result.ErrorCode
		a.ErrorMessage = result.ErrorMessage
		if result.OutputVariables != nil {
			a.OutputVariables = result.OutputVariables
		}
		// Native accepts source-stage rollbacks despite the guide's restriction:
		// the source reads its current revision, while execution lineage still
		// reports the target's revisions. The action retains the actual revision.
		if result.Revision != nil && e.RollbackTargetID == "" {
			revision := *result.Revision
			revision.ActionName = a.ActionName
			if len(a.OutputArtifacts) > 0 {
				revision.ArtifactName = a.OutputArtifacts[0].Name
			}
			if revision.RevisionID == "" {
				return fmt.Errorf("source provider returned an empty revision")
			}
			found := false
			for i := range e.Revisions {
				if e.Revisions[i].ActionName == a.ActionName {
					if e.Revisions[i].RevisionID != revision.RevisionID {
						return fmt.Errorf("source revision changed during action execution")
					}
					found = true
				}
			}
			if !found {
				e.Revisions = append(e.Revisions, revision)
			}
		}
		if result.Status == "Succeeded" {
			if len(result.Artifacts) != len(a.OutputArtifacts) {
				return fmt.Errorf("provider returned %d artifacts for %d reserved outputs", len(result.Artifacts), len(a.OutputArtifacts))
			}
			for i, reserved := range a.OutputArtifacts {
				found := false
				for _, artifact := range result.Artifacts {
					if artifact.Name == reserved.Name && artifact.Bucket == reserved.Bucket && artifact.Key == reserved.Key {
						artifact.ActionExecutionID = a.ID
						a.OutputArtifacts[i] = artifact
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("provider changed reserved artifact ownership")
				}
			}
		}
		previous := a.Status
		a.Status = result.Status
		a.UpdatedAt = now
		e.UpdatedAt = now
		e.Generation++
		e.Due = now
		if result.Status == "InProgress" {
			e.Due = now.Add(time.Second)
		}
		if previous != a.Status {
			if err = j.s.actionEvent(tx, v, e, *a, request.Action); err != nil {
				return err
			}
		}
		return tx.PutExecution(e)
	})
}
func (s *Service) advance(tx Transaction, v Pipeline, d Definition, e *Execution) (*ActionRequest, error) {
	now := s.clock.Now().UTC()
	e.Generation++
	e.Due = now.Add(time.Second)
	if terminal(e.Status) {
		e.Due = time.Time{}
		return nil, nil
	}
	stages := d.Declaration.Stages
	if e.StageIndex >= int32(len(stages)) {
		finish(e, "Succeeded", "", now)
		return nil, s.wakeOtherExecutions(tx, v, e.ID)
	}
	stage := stages[e.StageIndex]
	// Stop-and-wait finishes admitted actions. Updates invalidate approval
	// responses but do not establish a historical terminal outcome.
	active, activeProvider := false, false
	for _, a := range e.Actions {
		if a.StageIndex == e.StageIndex && a.Status == "InProgress" {
			active = true
			activeProvider = activeProvider || a.ApprovalToken == ""
		}
	}
	if e.UpdatedDefinition && e.Status != "Stopping" && !activeProvider {
		// Native update observations retain the old execution as InProgress.
		// Natural terminal settlement is not owned yet; explicit stop remains
		// available and admitted external work is still polled.
		e.Due = time.Time{}
		return nil, nil
	}
	if e.Status == "Stopping" && !active {
		if err := s.stageEvent(tx, v, e, text(stage.Name), "STOPPED"); err != nil {
			return nil, err
		}
		finish(e, "Stopped", e.StopReason, now)
		return nil, s.wakeOtherExecutions(tx, v, e.ID)
	}
	if !e.StageEntered {
		rows, err := tx.Executions(v.Scope, v.Incarnation)
		if err != nil {
			return nil, err
		}
		blocked := transitionDisabled(v, text(stage.Name), "Inbound")
		if e.Mode != "PARALLEL" {
			for _, other := range rows {
				if other.ID == e.ID || terminal(other.Status) {
					continue
				}
				if other.StageIndex == e.StageIndex && other.StageEntered {
					blocked = true
				}
				if other.StageIndex == e.StageIndex && !other.StageEntered {
					if e.Mode == "SUPERSEDED" && other.Sequence > e.Sequence {
						finish(e, "Superseded", "Superseded by a newer execution", now)
						return nil, nil
					}
					if e.Mode == "QUEUED" && other.Sequence < e.Sequence {
						blocked = true
					}
				}
			}
		}
		if blocked {
			return nil, nil
		}
		e.StageEntered = true
		e.StageStartedAt = now
		e.UpdatedAt = now
		if err := s.stageEvent(tx, v, e, text(stage.Name), "STARTED"); err != nil {
			return nil, err
		}
	}
	// The lowest unfinished runOrder is a parallel action group. All actions in
	// that group are admitted before polling; later groups never pass failures.
	minOrder := int32(1000)
	failed := false
	for i, a := range stage.Actions {
		latest := latestAction(*e, e.StageIndex, int32(i))
		if latest != nil && latest.Status == "Succeeded" {
			continue
		}
		minOrder = min(minOrder, int32(value(a.RunOrder)))
		if latest != nil && (latest.Status == "Failed" || latest.Status == "Abandoned") {
			failed = true
		}
	}
	if failed && !active {
		if err := s.stageEvent(tx, v, e, text(stage.Name), "FAILED"); err != nil {
			return nil, err
		}
		finish(e, "Failed", "Stage failed: "+text(stage.Name), now)
		return nil, s.wakeOtherExecutions(tx, v, e.ID)
	}
	if minOrder == 1000 {
		if err := s.stageEvent(tx, v, e, text(stage.Name), "SUCCEEDED"); err != nil {
			return nil, err
		}
		// A manual rollback is a stage execution, not a new traversal of the
		// pipeline. Native leaves downstream ownership and deployed bytes intact.
		if e.RollbackTargetID != "" {
			finish(e, "Succeeded", "", now)
			return nil, s.wakeOtherExecutions(tx, v, e.ID)
		}
		if transitionDisabled(v, text(stage.Name), "Outbound") {
			return nil, nil
		}
		e.StageIndex++
		e.StageEntered = false
		e.StageStatus = ""
		e.StageStartedAt = time.Time{}
		e.StageLastRetryAt = time.Time{}
		e.UpdatedAt = now
		e.Due = now
		if e.StageIndex == int32(len(stages)) {
			finish(e, "Succeeded", "", now)
		}
		return nil, s.wakeOtherExecutions(tx, v, e.ID)
	}
	if !failed && e.Status != "Stopping" && !e.UpdatedDefinition {
		var target *Execution
		if e.RollbackTargetID != "" {
			retained, err := findExecution(tx, v, e.RollbackTargetID)
			if err != nil {
				return nil, err
			}
			target = &retained
		}
		for i, decl := range stage.Actions {
			if int32(value(decl.RunOrder)) != minOrder {
				continue
			}
			latest := latestAction(*e, e.StageIndex, int32(i))
			if latest != nil && latest.Status != "Pending" {
				continue
			}
			var a ActionExecution
			if latest != nil {
				a = *latest
			} else {
				id, err := newID()
				if err != nil {
					return nil, err
				}
				a = ActionExecution{ID: id, StageName: text(stage.Name), ActionName: text(decl.Name), StageIndex: e.StageIndex, ActionIndex: int32(i), Attempt: 1}
			}
			a.Status = "InProgress"
			a.StartedAt = now
			a.UpdatedAt = now
			resolved, resolveErr := resolveConfiguration(d, *e, decl, target)
			a.ResolvedConfiguration = resolved
			if resolveErr != nil {
				a.Status = "Failed"
				a.ErrorCode = "InvalidActionConfiguration"
				a.ErrorMessage = resolveErr.Error()
			}
			for _, input := range decl.InputArtifacts {
				artifact, ok := executionArtifact(*e, text(input.Name))
				if !ok && target != nil {
					artifact, ok = rollbackArtifact(*target, e.RollbackStageIndex, text(input.Name))
				}
				if !ok {
					return nil, fmt.Errorf("missing admitted input artifact %s", text(input.Name))
				}
				a.InputArtifacts = append(a.InputArtifacts, artifact)
			}
			for _, output := range decl.OutputArtifacts {
				name := text(output.Name)
				a.OutputArtifacts = append(a.OutputArtifacts, Artifact{Name: name, Bucket: text(d.Declaration.ArtifactStore.Location), Key: prefix(v.Name, 20) + "/" + prefix(name, 10) + "/" + a.ID, ActionExecutionID: a.ID})
			}
			if text(decl.ActionTypeId.Provider) == "Manual" && resolveErr == nil {
				a.ApprovalToken = a.ID
			}
			if text(decl.ActionTypeId.Provider) == "Lambda" && resolveErr == nil {
				if err := s.admitInvocationJob(tx, *e, a, decl); err != nil {
					return nil, err
				}
			}
			if latest != nil {
				*latest = a
			} else {
				e.Actions = append(e.Actions, a)
			}
			e.UpdatedAt = now
			if err := s.actionEvent(tx, v, *e, a, decl); err != nil {
				return nil, err
			}
			// Persist the whole parallel group's admitted work before returning
			// any provider effect, so one synchronous failure cannot erase peers.
			e.Due = now
		}
	}
	var poll *ActionExecution
	for i := range e.Actions {
		a := &e.Actions[i]
		if a.StageIndex != e.StageIndex || a.Status != "InProgress" {
			continue
		}
		decl := stage.Actions[a.ActionIndex]
		if a.ApprovalToken != "" {
			if e.UpdatedDefinition {
				continue
			}
			if !now.Before(approvalDeadline(*a, decl)) {
				a.Status = "Failed"
				a.ErrorCode = "ApprovalTimedOut"
				a.ErrorMessage = "Approval timed out"
				a.UpdatedAt = now
				e.Due = now
				if err := s.actionEvent(tx, v, *e, *a, decl); err != nil {
					return nil, err
				}
			} else if a.ApprovalNotificationID == "" && a.ResolvedConfiguration["NotificationArn"] != "" {
				// An interrupted publication recovers after the execution claim
				// expires. A committed publication never polls SNS again.
				if poll == nil || a.UpdatedAt.Before(poll.UpdatedAt) {
					poll = a
				}
			}
			continue
		}
		if decl.TimeoutInMinutes != nil && !now.Before(a.StartedAt.Add(time.Duration(*decl.TimeoutInMinutes)*time.Minute)) {
			a.Status = "Failed"
			a.ErrorCode = "ActionTimedOut"
			a.ErrorMessage = "Action timed out"
			a.UpdatedAt = now
			e.Due = now
			if err := s.actionEvent(tx, v, *e, *a, decl); err != nil {
				return nil, err
			}
			continue
		}
		if text(decl.ActionTypeId.Provider) == "Lambda" {
			if e.UpdatedDefinition {
				continue
			}
			job, err := latestInvocationJob(tx, e.Scope, a.ID)
			if err != nil {
				return nil, err
			}
			if job == nil {
				return nil, fmt.Errorf("lambda action %s has no retained invocation job", a.ID)
			}
			if (job.Status == "Ready" || job.Status == "Running") && !now.Before(job.ExpiresAt) {
				a.Status = "Failed"
				a.ErrorCode = "ActionTimedOut"
				a.ErrorMessage = "Lambda action timed out waiting for a job result"
				a.UpdatedAt = now
				e.Due = now
				if err := s.actionEvent(tx, v, *e, *a, decl); err != nil {
					return nil, err
				}
				continue
			}
		}
		if poll == nil || a.UpdatedAt.Before(poll.UpdatedAt) {
			poll = a
		}
	}
	if poll != nil {
		req := actionRequest(v, d, *e, *poll)
		if text(req.Action.ActionTypeId.Provider) == "Lambda" {
			var err error
			req.InvocationJob, err = latestInvocationJob(tx, e.Scope, poll.ID)
			if err != nil {
				return nil, err
			}
		}
		return &req, nil
	}
	return nil, nil
}
func (s *Service) wakeOtherExecutions(tx Transaction, v Pipeline, id string) error {
	rows, err := tx.Executions(v.Scope, v.Incarnation)
	if err != nil {
		return err
	}
	for _, e := range rows {
		if e.ID == id || terminal(e.Status) {
			continue
		}
		e.Due = s.clock.Now().UTC()
		e.Generation++
		if err = tx.PutExecution(e); err != nil {
			return err
		}
	}
	return nil
}
func prefix(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
func transitionDisabled(v Pipeline, stage, kind string) bool {
	for _, t := range v.Transitions {
		if t.Stage == stage && t.Type == kind {
			return t.Disabled
		}
	}
	return false
}
func executionArtifact(e Execution, name string) (Artifact, bool) {
	for i := len(e.Actions) - 1; i >= 0; i-- {
		a := e.Actions[i]
		if a.Status != "Succeeded" {
			continue
		}
		for _, artifact := range a.OutputArtifacts {
			if artifact.Name == name {
				return artifact, true
			}
		}
	}
	return Artifact{}, false
}
func actionRequest(v Pipeline, d Definition, e Execution, a ActionExecution) ActionRequest {
	decl := d.Declaration.Stages[a.StageIndex].Actions[a.ActionIndex]
	decl.Configuration = a.ResolvedConfiguration
	role := text(d.Declaration.RoleArn)
	overrides := slices.Clone(e.SourceOverrides)
	for _, r := range e.Revisions {
		if r.ActionName != a.ActionName || e.RollbackTargetID != "" {
			continue
		}
		overrides = slices.DeleteFunc(overrides, func(o api.SourceRevisionOverride) bool {
			return text(o.ActionName) == a.ActionName && text(o.RevisionType) == "S3_OBJECT_VERSION_ID"
		})
		overrides = append(overrides, api.SourceRevisionOverride{ActionName: new(api.ActionName(a.ActionName)), RevisionType: new(api.SourceRevisionType("S3_OBJECT_VERSION_ID")), RevisionValue: new(api.Revision(r.RevisionID))})
	}
	request := ActionRequest{Scope: e.Scope, PipelineName: v.Name, PipelineARN: ARN(v.Scope, v.Name), Incarnation: v.Incarnation, PipelineExecutionID: e.ID, ActionExecutionID: a.ID, PipelineVersion: e.Version, RoleARN: role, Action: decl, ArtifactStore: *d.Declaration.ArtifactStore, InputArtifacts: a.InputArtifacts, OutputArtifacts: a.OutputArtifacts, SourceRevisionOverrides: overrides, ExternalExecutionID: a.ExternalExecutionID, ParentEventID: e.ParentEventID}
	request.StageName = a.StageName
	if a.ApprovalToken != "" {
		request.ApprovalToken = a.ApprovalToken
		request.ApprovalExpiresAt = approvalDeadline(a, decl)
	}
	return request
}

// ResolveAction resolves current admitted ownership inside a borrowed repository
// transaction. The provider must still authorize its real effects.
func ResolveAction(ctx context.Context, repository Repository, sc Scope, id string) (ActionRequest, bool, error) {
	var request ActionRequest
	found := false
	err := repository.View(ctx, func(r Reader) error {
		rows, err := r.Executions(sc, "")
		if err != nil {
			return err
		}
		for _, e := range rows {
			for _, a := range e.Actions {
				if a.ID != id || a.Status != "InProgress" {
					continue
				}
				v, err := findPipeline(r, sc, e.PipelineName)
				if err != nil || v.Incarnation != e.Incarnation {
					return nil
				}
				d, err := findDefinition(r, v, e.Version)
				if err != nil {
					return err
				}
				request = actionRequest(v, d, e, a)
				if text(request.Action.ActionTypeId.Provider) == "Lambda" {
					request.InvocationJob, err = latestInvocationJob(r, sc, a.ID)
					if err != nil {
						return err
					}
				}
				found = true
				return nil
			}
		}
		return nil
	})
	return request, found, err
}

// ResolveDeployment retains exact artifact and resolved ZIP-member references
// after pipeline deletion. The consumer separately authorizes the caller's S3 read.
func ResolveDeployment(ctx context.Context, repository Repository, sc Scope, name, id string) (ActionRequest, bool, error) {
	var request ActionRequest
	found := false
	err := repository.View(ctx, func(r Reader) error {
		rows, err := r.Executions(sc, "")
		if err != nil {
			return err
		}
		for _, e := range rows {
			if e.PipelineName != name {
				continue
			}
			for _, a := range e.Actions {
				if a.ID != id || len(a.InputArtifacts) != 1 {
					continue
				}
				d, ok, err := r.Definition(sc, e.Incarnation, e.Version)
				if err != nil {
					return err
				}
				if !ok {
					return nil
				}
				if text(d.Declaration.Stages[a.StageIndex].Actions[a.ActionIndex].ActionTypeId.Provider) != "AppConfig" {
					return nil
				}
				request = actionRequest(Pipeline{Scope: sc, Name: name, Incarnation: e.Incarnation}, d, e, a)
				found = true
				return nil
			}
		}
		return nil
	})
	return request, found, err
}
