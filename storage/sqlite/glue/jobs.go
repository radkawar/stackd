package glue

import (
	"database/sql"
	"encoding/json"
	"errors"
	domain "stackd/internal/services/glue"
	"stackd/storage/sqlite/glue/internal/sqlcgen"
	"time"
)

func jobSQLError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func jobSQLTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}
func jobDomainTime(t int64) time.Time {
	if t == 0 {
		return time.Time{}
	}
	return time.Unix(0, t).UTC()
}
func jobSQLBool(v bool) int64 {
	if v {
		return 1
	}
	return 0
}

func (r reader) decodeJob(v sqlcgen.GlueJob) (domain.JobRecord, error) {
	out := domain.JobRecord{Key: domain.ResourceKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}}
	out.Description = v.Description
	out.Role = v.Role
	out.Command = v.Command
	out.ScriptLocation = v.ScriptLocation
	out.PythonVersion = v.PythonVersion
	out.GlueVersion = v.GlueVersion
	out.WorkerType = v.WorkerType
	out.ExecutionClass = v.ExecutionClass
	out.SecurityConfiguration = v.SecurityConfiguration
	out.MaxConcurrentRuns = int32(v.MaxConcurrentRuns)
	out.MaxRetries = int32(v.MaxRetries)
	out.Timeout = int32(v.Timeout)
	out.NumberOfWorkers = int32(v.NumberOfWorkers)
	out.MaxCapacity = v.MaxCapacity
	out.CreatedAt = jobDomainTime(v.CreatedAt)
	out.UpdatedAt = jobDomainTime(v.UpdatedAt)
	if err := json.Unmarshal([]byte(v.DefaultArguments), &out.DefaultArguments); err != nil {
		return out, err
	}
	if err := json.Unmarshal([]byte(v.NonOverridableArguments), &out.NonOverridableArguments); err != nil {
		return out, err
	}
	if err := json.Unmarshal([]byte(v.Tags), &out.Tags); err != nil {
		return out, err
	}
	return out, nil
}

func (w writer) PutJob(v domain.JobRecord) error {
	DefaultArguments, err := json.Marshal(v.DefaultArguments)
	if err != nil {
		return err
	}
	NonOverridableArguments, err := json.Marshal(v.NonOverridableArguments)
	if err != nil {
		return err
	}
	Tags, err := json.Marshal(v.Tags)
	if err != nil {
		return err
	}
	if err := w.q.PutGlueJob(w.ctx, sqlcgen.PutGlueJobParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name,
		Description:             v.Description,
		Role:                    v.Role,
		Command:                 v.Command,
		ScriptLocation:          v.ScriptLocation,
		PythonVersion:           v.PythonVersion,
		GlueVersion:             v.GlueVersion,
		WorkerType:              v.WorkerType,
		ExecutionClass:          v.ExecutionClass,
		SecurityConfiguration:   v.SecurityConfiguration,
		MaxConcurrentRuns:       int64(v.MaxConcurrentRuns),
		MaxRetries:              int64(v.MaxRetries),
		Timeout:                 int64(v.Timeout),
		NumberOfWorkers:         int64(v.NumberOfWorkers),
		MaxCapacity:             v.MaxCapacity,
		DefaultArguments:        string(DefaultArguments),
		NonOverridableArguments: string(NonOverridableArguments),
		Tags:                    string(Tags),
		CreatedAt:               jobSQLTime(v.CreatedAt),
		UpdatedAt:               jobSQLTime(v.UpdatedAt),
	}); err != nil {
		return err
	}
	return nil
}

func (r reader) decodeJobRun(v sqlcgen.GlueJobRun) (domain.JobRunRecord, error) {
	out := domain.JobRunRecord{Key: domain.ResourceKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}}
	out.ID = v.ID
	out.State = v.State
	out.Role = v.Role
	out.Command = v.Command
	out.ScriptLocation = v.ScriptLocation
	out.PythonVersion = v.PythonVersion
	out.GlueVersion = v.GlueVersion
	out.WorkerType = v.WorkerType
	out.ExecutionClass = v.ExecutionClass
	out.SecurityConfiguration = v.SecurityConfiguration
	out.PreviousRunID = v.PreviousRunID
	out.TriggerName = v.TriggerName
	out.WorkflowName = v.WorkflowName
	out.WorkflowRunID = v.WorkflowRunID
	out.Timeout = int32(v.Timeout)
	out.NumberOfWorkers = int32(v.NumberOfWorkers)
	out.Attempt = int32(v.Attempt)
	out.MaxCapacity = v.MaxCapacity
	out.StartedAt = jobDomainTime(v.StartedAt)
	out.UpdatedAt = jobDomainTime(v.UpdatedAt)
	out.CompletedAt = jobDomainTime(v.CompletedAt)
	out.NextAttempt = jobDomainTime(v.NextAttempt)
	out.Version = uint64(v.Version)
	out.LaunchAttempted = v.LaunchAttempted != 0
	out.CleanupPending = v.CleanupPending != 0
	out.Published = v.Published != 0
	out.Error = v.Error
	out.Output = v.Output
	out.ErrorOutput = v.ErrorOutput
	out.S3EncryptionMode = v.S3EncryptionMode
	out.S3KMSKeyARN = v.S3KmsKey
	out.LogsKMSKeyARN = v.LogsKmsKey
	out.MaxRetries = int32(v.MaxRetries)
	out.ExecutionSeconds = int32(v.ExecutionSeconds)
	out.RetryPending = v.RetryPending != 0
	out.MetricsPublished = v.MetricsPublished != 0
	out.LogError = v.LogError
	out.SparkMetrics.Observed = v.MetricsObserved != 0
	out.SparkMetrics.CompletedTasks = v.MetricsCompletedTasks
	out.SparkMetrics.FailedTasks = v.MetricsFailedTasks
	out.SparkMetrics.KilledTasks = v.MetricsKilledTasks
	out.SparkMetrics.CompletedStages = v.MetricsCompletedStages
	out.SparkMetrics.BytesRead = v.MetricsBytesRead
	out.SparkMetrics.RecordsRead = v.MetricsRecordsRead
	if err := json.Unmarshal([]byte(v.Arguments), &out.Arguments); err != nil {
		return out, err
	}
	if err := json.Unmarshal([]byte(v.RunArguments), &out.RunArguments); err != nil {
		return out, err
	}
	attempts, err := r.q.ListGlueJobAttempts(r.ctx, sqlcgen.ListGlueJobAttemptsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Name: v.Name, ID: v.ID})
	if err != nil {
		return out, err
	}
	for _, a := range attempts {
		out.Attempts = append(out.Attempts, domain.JobAttemptRecord{Attempt: int32(a.Attempt), State: a.State, Error: a.Error, Output: a.Output, ErrorOutput: a.ErrorOutput, StartedAt: jobDomainTime(a.StartedAt), CompletedAt: jobDomainTime(a.CompletedAt)})
	}
	return out, nil
}

func (w writer) PutJobRun(v domain.JobRunRecord) error {
	Arguments, err := json.Marshal(v.Arguments)
	if err != nil {
		return err
	}
	RunArguments, err := json.Marshal(v.RunArguments)
	if err != nil {
		return err
	}
	if err := w.q.PutGlueJobRun(w.ctx, sqlcgen.PutGlueJobRunParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name,
		ID:                     v.ID,
		State:                  v.State,
		Role:                   v.Role,
		Command:                v.Command,
		ScriptLocation:         v.ScriptLocation,
		PythonVersion:          v.PythonVersion,
		GlueVersion:            v.GlueVersion,
		WorkerType:             v.WorkerType,
		ExecutionClass:         v.ExecutionClass,
		SecurityConfiguration:  v.SecurityConfiguration,
		PreviousRunID:          v.PreviousRunID,
		TriggerName:            v.TriggerName,
		WorkflowName:           v.WorkflowName,
		WorkflowRunID:          v.WorkflowRunID,
		Timeout:                int64(v.Timeout),
		NumberOfWorkers:        int64(v.NumberOfWorkers),
		Attempt:                int64(v.Attempt),
		MaxCapacity:            v.MaxCapacity,
		Arguments:              string(Arguments),
		StartedAt:              jobSQLTime(v.StartedAt),
		UpdatedAt:              jobSQLTime(v.UpdatedAt),
		CompletedAt:            jobSQLTime(v.CompletedAt),
		NextAttempt:            jobSQLTime(v.NextAttempt),
		Version:                int64(v.Version),
		LaunchAttempted:        jobSQLBool(v.LaunchAttempted),
		CleanupPending:         jobSQLBool(v.CleanupPending),
		Published:              jobSQLBool(v.Published),
		Error:                  v.Error,
		Output:                 v.Output,
		ErrorOutput:            v.ErrorOutput,
		S3EncryptionMode:       v.S3EncryptionMode,
		S3KmsKey:               v.S3KMSKeyARN,
		LogsKmsKey:             v.LogsKMSKeyARN,
		MaxRetries:             int64(v.MaxRetries),
		ExecutionSeconds:       int64(v.ExecutionSeconds),
		RunArguments:           string(RunArguments),
		RetryPending:           jobSQLBool(v.RetryPending),
		MetricsPublished:       jobSQLBool(v.MetricsPublished),
		LogError:               v.LogError,
		MetricsObserved:        jobSQLBool(v.SparkMetrics.Observed),
		MetricsCompletedTasks:  v.SparkMetrics.CompletedTasks,
		MetricsFailedTasks:     v.SparkMetrics.FailedTasks,
		MetricsKilledTasks:     v.SparkMetrics.KilledTasks,
		MetricsCompletedStages: v.SparkMetrics.CompletedStages,
		MetricsBytesRead:       v.SparkMetrics.BytesRead,
		MetricsRecordsRead:     v.SparkMetrics.RecordsRead,
	}); err != nil {
		return err
	}
	for _, a := range v.Attempts {
		if err := w.q.PutGlueJobAttempt(w.ctx, sqlcgen.PutGlueJobAttemptParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name, ID: v.ID, Attempt: int64(a.Attempt), State: a.State, Error: a.Error, Output: a.Output, ErrorOutput: a.ErrorOutput, StartedAt: jobSQLTime(a.StartedAt), CompletedAt: jobSQLTime(a.CompletedAt)}); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) GetJob(k domain.ResourceKey) (domain.JobRecord, error) {
	v, err := r.q.GetGlueJob(r.ctx, sqlcgen.GetGlueJobParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.JobRecord{}, jobSQLError(err)
	}
	return r.decodeJob(v)
}
func (r reader) GetJobRun(k domain.ResourceKey, id string) (domain.JobRunRecord, error) {
	v, err := r.q.GetGlueJobRun(r.ctx, sqlcgen.GetGlueJobRunParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ID: id})
	if err != nil {
		return domain.JobRunRecord{}, jobSQLError(err)
	}
	return r.decodeJobRun(v)
}
func (w writer) DeleteJob(k domain.ResourceKey) error {
	return w.q.DeleteGlueJob(w.ctx, sqlcgen.DeleteGlueJobParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
func (r reader) ListJobs(scope domain.Scope) ([]domain.JobRecord, error) {
	rows, err := r.q.ListGlueJobs(r.ctx, sqlcgen.ListGlueJobsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.JobRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.decodeJob(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) ListJobRuns(k domain.ResourceKey) ([]domain.JobRunRecord, error) {
	rows, err := r.q.ListGlueJobRuns(r.ctx, sqlcgen.ListGlueJobRunsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.JobRunRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.decodeJobRun(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) PendingJobRuns() ([]domain.JobRunRecord, error) {
	rows, err := r.q.PendingGlueJobRuns(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.JobRunRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.decodeJobRun(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
