package glue

import (
	"context"
	"errors"
	"maps"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
)

func (s *Service) startJobRun(ctx context.Context, tx Transaction, in *api.StartJobRunInput) (*api.StartJobRunOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.JobName)}
	job, err := tx.GetJob(key)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, tx, "StartJobRun", key.Scope, key.ARN("job"), job.Tags); err != nil {
		return nil, err
	}
	return s.admitJobRun(ctx, tx, job, in, "", "", "")
}
func (s *Service) admitJobRun(ctx context.Context, tx Transaction, job JobRecord, in *api.StartJobRunInput, trigger, workflow, workflowRun string) (*api.StartJobRunOutput, error) {
	if s.jobRuntime == nil || s.jobDependencies == nil {
		return nil, unsupported("Glue job execution is not configured.")
	}
	if in.ExecutionRoleSessionPolicy != nil || (in.AllocatedCapacity != nil && *in.AllocatedCapacity != 0) || in.NotificationProperty != nil || (in.JobRunQueuingEnabled != nil && bool(*in.JobRunQueuingEnabled)) {
		return nil, unsupported("This run requires unsupported execution features.")
	}
	if in.Timeout != nil {
		job.Timeout = int32(*in.Timeout)
	}
	if in.WorkerType != nil {
		job.WorkerType = value(in.WorkerType)
	}
	if in.NumberOfWorkers != nil {
		job.NumberOfWorkers = int32(*in.NumberOfWorkers)
	}
	if in.MaxCapacity != nil {
		job.MaxCapacity = float64(*in.MaxCapacity)
	}
	if in.ExecutionClass != nil {
		job.ExecutionClass = value(in.ExecutionClass)
	}
	if in.SecurityConfiguration != nil {
		job.SecurityConfiguration = value(in.SecurityConfiguration)
	}
	if err := validateJob(&job); err != nil {
		return nil, err
	}
	var s3Mode, s3Key, logsKey string
	if job.SecurityConfiguration != "" {
		config, err := s.ResolveSecurityConfiguration(ctx, job.Key.Scope, job.SecurityConfiguration)
		if err != nil {
			return nil, err
		}
		for _, v := range config.S3Encryption {
			s3Mode = value(v.S3EncryptionMode)
			s3Key = value(v.KmsKeyArn)
		}
		// TODO: Comeback capture native Python-shell S3 security-configuration semantics.
		if s3Mode != "" && s3Mode != "DISABLED" && job.Command == "pythonshell" {
			return nil, unsupported("Python shell S3 encryption configuration is not supported; use explicit SDK S3 encryption parameters.")
		}
		if v := config.CloudWatchEncryption; v != nil && value(v.CloudWatchEncryptionMode) == "SSE-KMS" {
			logsKey = value(v.KmsKeyArn)
		}
		// TODO: Comeback implement bookmark encryption with real bookmark state.
		if v := config.JobBookmarksEncryption; v != nil && value(v.JobBookmarksEncryptionMode) != "DISABLED" {
			return nil, unsupported("Encrypted Glue bookmarks are not supported by this runtime.")
		}
	}
	runs, err := tx.ListJobRuns(job.Key)
	if err != nil {
		return nil, err
	}
	active := 0
	for _, run := range runs {
		if run.Active() {
			active++
		}
	}
	if active >= int(job.MaxConcurrentRuns) {
		return nil, failure("ConcurrentRunsExceededException", "Concurrent runs exceeded for job.")
	}
	args := maps.Clone(job.DefaultArguments)
	if args == nil {
		args = map[string]string{}
	}
	attempt := int32(0)
	previous := value(in.JobRunId)
	if previous != "" {
		old, err := tx.GetJobRun(job.Key, previous)
		if err != nil {
			return nil, err
		}
		if old.Active() || old.State == "SUCCEEDED" {
			return nil, failure("InvalidInputException", "Only failed, stopped or timed out runs may be retried.")
		}
		maps.Copy(args, old.Arguments)
		attempt = old.Attempt + 1
	}
	maps.Copy(args, jobArguments(in.Arguments))
	maps.Copy(args, job.NonOverridableArguments)
	for key, v := range args {
		if err := validateJobArgument(key, v); err != nil {
			return nil, err
		}
	}
	now := s.clock.Now()
	run := JobRunRecord{Key: job.Key, ID: "jr_" + strings.ReplaceAll(uuid.NewString(), "-", ""), State: "STARTING", Role: job.Role, Command: job.Command, ScriptLocation: job.ScriptLocation, PythonVersion: job.PythonVersion, GlueVersion: job.GlueVersion, WorkerType: job.WorkerType, ExecutionClass: job.ExecutionClass, SecurityConfiguration: job.SecurityConfiguration, Timeout: job.Timeout, NumberOfWorkers: job.NumberOfWorkers, MaxCapacity: job.MaxCapacity, Attempt: attempt, PreviousRunID: previous, Arguments: args, StartedAt: now, UpdatedAt: now, NextAttempt: now, Version: 1, TriggerName: trigger, WorkflowName: workflow, WorkflowRunID: workflowRun}
	run.S3EncryptionMode, run.S3KMSKeyARN, run.LogsKMSKeyARN = s3Mode, s3Key, logsKey
	run.MaxRetries = job.MaxRetries
	run.RunArguments = jobArguments(in.Arguments)
	if err := tx.PutJobRun(run); err != nil {
		return nil, err
	}
	return &api.StartJobRunOutput{JobRunId: new(api.IdString(run.ID))}, nil
}
func jobRunWire(r JobRunRecord, now time.Time) api.JobRun {
	seconds := int64(r.ExecutionSeconds)
	if r.Active() && !r.RetryPending {
		seconds = max(int64(0), int64(now.Sub(r.StartedAt)/time.Second))
	}
	group := "/aws-glue/jobs"
	if r.Command == "pythonshell" {
		group = "/aws-glue/python-jobs"
	}
	out := api.JobRun{Id: new(api.IdString(r.ID)), JobName: new(api.NameString(r.Key.Name)), JobRunState: new(api.JobRunState(r.State)), StartedOn: &r.StartedAt, LastModifiedOn: &r.UpdatedAt, Arguments: jobWireArguments(r.RunArguments), Attempt: new(api.AttemptCount(r.Attempt)), Timeout: new(api.Timeout(r.Timeout)), ExecutionTime: new(api.ExecutionTime(seconds)), ExecutionClass: new(api.ExecutionClass(r.ExecutionClass)), LogGroupName: new(api.GenericString(group)), JobMode: new(api.JobMode("SCRIPT")), AllocatedCapacity: new(api.IntegerValue(0))}
	if !r.CompletedAt.IsZero() {
		out.CompletedOn = &r.CompletedAt
	}
	if r.Error != "" {
		out.ErrorMessage = new(api.ErrorString(r.Error))
	}
	if r.GlueVersion != "" {
		out.GlueVersion = new(api.GlueVersionString(r.GlueVersion))
	}
	if r.WorkerType != "" {
		out.WorkerType = new(api.WorkerType(r.WorkerType))
		out.NumberOfWorkers = new(api.NullableInteger(r.NumberOfWorkers))
	}
	if r.MaxCapacity != 0 {
		out.MaxCapacity = new(api.NullableDouble(r.MaxCapacity))
	}
	if r.PreviousRunID != "" {
		out.PreviousRunId = new(api.IdString(r.PreviousRunID))
	}
	if r.TriggerName != "" {
		out.TriggerName = new(api.NameString(r.TriggerName))
	}
	if r.SecurityConfiguration != "" {
		out.SecurityConfiguration = new(api.NameString(r.SecurityConfiguration))
	}
	return out
}
func (s *Service) authorizeJobRun(ctx context.Context, tx Reader, action string, key ResourceKey) error {
	job, err := tx.GetJob(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	// Runs intentionally outlive job deletion. A deleted definition has no
	// current resource tags, but the retained run still requires authorization.
	return s.authorize(ctx, tx, action, key.Scope, key.ARN("job"), job.Tags)
}
func (s *Service) getJobRun(ctx context.Context, tx Transaction, in *api.GetJobRunInput) (*api.GetJobRunOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.JobName)}
	if err := s.authorizeJobRun(ctx, tx, "GetJobRun", key); err != nil {
		return nil, err
	}
	run, err := tx.GetJobRun(key, value(in.RunId))
	if err != nil {
		return nil, err
	}
	out := jobRunWire(run, s.clock.Now())
	return &api.GetJobRunOutput{JobRun: &out}, nil
}
func (s *Service) getJobRuns(ctx context.Context, tx Transaction, in *api.GetJobRunsInput) (*api.GetJobRunsOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.JobName)}
	if err := s.authorizeJobRun(ctx, tx, "GetJobRuns", key); err != nil {
		return nil, err
	}
	after, err := jobPageStart(key.Scope, "GetJobRuns", key.Name, value(in.NextToken))
	if err != nil {
		return nil, err
	}
	limit := 100
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	if limit < 1 || limit > 200 {
		return nil, failure("InvalidInputException", "Invalid MaxResults.")
	}
	runs, err := tx.ListJobRuns(key)
	if err != nil {
		return nil, err
	}
	out := &api.GetJobRunsOutput{JobRuns: api.JobRunList{}}
	found := after == ""
	for _, run := range runs {
		if !found {
			found = run.ID == after
			continue
		}
		if len(out.JobRuns) == limit {
			out.NextToken = jobPageToken(key.Scope, "GetJobRuns", key.Name, value(out.JobRuns[len(out.JobRuns)-1].Id))
			break
		}
		out.JobRuns = append(out.JobRuns, jobRunWire(run, s.clock.Now()))
	}
	if !found {
		return nil, failure("InvalidInputException", "Invalid pagination token.")
	}
	return out, nil
}
func (s *Service) batchStopJobRun(ctx context.Context, tx Transaction, in *api.BatchStopJobRunInput) (*api.BatchStopJobRunOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.JobName)}
	if err := s.authorizeJobRun(ctx, tx, "BatchStopJobRun", key); err != nil {
		return nil, err
	}
	if len(in.JobRunIds) < 1 || len(in.JobRunIds) > 25 {
		return nil, failure("InvalidInputException", "JobRunIds must contain between 1 and 25 entries.")
	}
	out := &api.BatchStopJobRunOutput{SuccessfulSubmissions: api.BatchStopJobRunSuccessfulSubmissionList{}, Errors: api.BatchStopJobRunErrorList{}}
	for _, id := range in.JobRunIds {
		run, err := tx.GetJobRun(key, string(id))
		code, message := "", ""
		if errors.Is(err, ErrNotFound) {
			code, message = "EntityNotFoundException", "Job run not found."
		} else if err != nil {
			return nil, err
		} else if !run.Active() {
			code, message = "JobRunCannotBeStoppedException", "Job run cannot be stopped."
		}
		if code != "" {
			out.Errors = append(out.Errors, api.BatchStopJobRunError{JobName: in.JobName, JobRunId: new(id), ErrorDetail: &api.ErrorDetail{ErrorCode: new(api.NameString(code)), ErrorMessage: new(api.DescriptionString(message))}})
			continue
		}
		run.State = "STOPPING"
		run.Version++
		run.UpdatedAt = s.clock.Now()
		run.NextAttempt = run.UpdatedAt
		if err := tx.PutJobRun(run); err != nil {
			return nil, err
		}
		out.SuccessfulSubmissions = append(out.SuccessfulSubmissions, api.BatchStopJobRunSuccessfulSubmission{JobName: in.JobName, JobRunId: new(id)})
	}
	return out, nil
}

// StartTriggeredJob admits only from the service's already-authorized trigger
// transition. Job execution still uses current IAM role trust and S3 policies.
func (s *Service) StartTriggeredJob(ctx context.Context, scope Scope, jobName, triggerName, workflowName, workflowRunID string, args map[string]string, securityConfig string, timeout int32) (string, error) {
	ctx = jobTriggerContext(ctx, scope)
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return "", err
	}
	var id string
	err = s.repository.Update(ctx, func(tx Transaction) error {
		job, err := tx.GetJob(ResourceKey{scope, jobName})
		if err != nil {
			return err
		}
		in := &api.StartJobRunInput{JobName: new(api.NameString(jobName)), Arguments: jobWireArguments(args)}
		if timeout != 0 {
			in.Timeout = new(api.Timeout(timeout))
		}
		if securityConfig != "" {
			in.SecurityConfiguration = new(api.NameString(securityConfig))
		}
		out, err := s.admitJobRun(tx.Context(), tx, job, in, triggerName, workflowName, workflowRunID)
		if err != nil {
			return err
		}
		id = value(out.JobRunId)
		return s.recordCall(tx.Context(), "StartJobRun", in, out, nil)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return id, err
}
func (s *Service) StopTriggeredJob(ctx context.Context, scope Scope, jobName, runID string) error {
	ctx = jobTriggerContext(ctx, scope)
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return err
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		run, err := tx.GetJobRun(ResourceKey{scope, jobName}, runID)
		if err != nil {
			return err
		}
		if !run.Active() {
			return nil
		}
		run.State = "STOPPING"
		run.Version++
		run.NextAttempt = s.clock.Now()
		if err := tx.PutJobRun(run); err != nil {
			return err
		}
		in := &api.BatchStopJobRunInput{JobName: new(api.NameString(jobName)), JobRunIds: api.BatchStopJobRunJobRunIdList{api.IdString(runID)}}
		out := &api.BatchStopJobRunOutput{SuccessfulSubmissions: api.BatchStopJobRunSuccessfulSubmissionList{{JobName: in.JobName, JobRunId: new(api.IdString(runID))}}}
		return s.recordCall(tx.Context(), "BatchStopJobRun", in, out, nil)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return err
}
func jobTriggerContext(ctx context.Context, scope Scope) context.Context {
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = scope.Partition, scope.AccountID, scope.Region
	m.InvokedBy = "glue.amazonaws.com"
	return awsctx.WithMetadata(ctx, m)
}
