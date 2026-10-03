package glue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"reflect"
	"strings"

	api "stackd/internal/awsapi/glue"
)

func registerJobs(s *Service) {
	registerControl(s, "CreateJob", s.createJob)
	registerControl(s, "UpdateJob", s.updateJob)
	registerControl(s, "DeleteJob", s.deleteJob)
	registerControl(s, "GetJob", s.getJob)
	registerControl(s, "GetJobs", s.getJobs)
	registerControl(s, "ListJobs", s.listJobs)
	registerControl(s, "StartJobRun", s.startJobRun)
	registerControl(s, "GetJobRun", s.getJobRun)
	registerControl(s, "GetJobRuns", s.getJobRuns)
	registerControl(s, "BatchStopJobRun", s.batchStopJobRun)
}
func jobArguments(in api.GenericMap) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[string(k)] = string(v)
	}
	return out
}
func jobWireArguments(in map[string]string) api.GenericMap {
	out := make(api.GenericMap, len(in))
	for k, v := range in {
		out[api.GenericString(k)] = api.GenericString(v)
	}
	return out
}

func (s *Service) createJob(ctx context.Context, tx Transaction, in *api.CreateJobInput) (*api.CreateJobOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	job := JobRecord{Key: key, Description: value(in.Description), Role: value(in.Role), GlueVersion: value(in.GlueVersion), WorkerType: value(in.WorkerType), ExecutionClass: value(in.ExecutionClass), SecurityConfiguration: value(in.SecurityConfiguration), DefaultArguments: jobArguments(in.DefaultArguments), NonOverridableArguments: jobArguments(in.NonOverridableArguments), Tags: map[string]string{}, MaxConcurrentRuns: 1, Timeout: 2880}
	if in.Command != nil {
		job.Command = value(in.Command.Name)
		job.ScriptLocation = value(in.Command.ScriptLocation)
		job.PythonVersion = value(in.Command.PythonVersion)
		if in.Command.Runtime != nil {
			return nil, unsupported("Job runtime selection is not supported.")
		}
	}
	if in.ExecutionProperty != nil && in.ExecutionProperty.MaxConcurrentRuns != nil {
		job.MaxConcurrentRuns = int32(*in.ExecutionProperty.MaxConcurrentRuns)
	}
	if in.MaxRetries != nil {
		job.MaxRetries = int32(*in.MaxRetries)
	}
	if in.Timeout != nil {
		job.Timeout = int32(*in.Timeout)
	}
	if in.NumberOfWorkers != nil {
		job.NumberOfWorkers = int32(*in.NumberOfWorkers)
	}
	if in.MaxCapacity != nil {
		job.MaxCapacity = float64(*in.MaxCapacity)
	}
	for k, v := range in.Tags {
		job.Tags[string(k)] = string(v)
	}
	// The Smithy decoder supplies zero for omitted deprecated AllocatedCapacity.
	// A zero default does not select the legacy capacity deployment mode.
	if (in.AllocatedCapacity != nil && *in.AllocatedCapacity != 0) || in.CodeGenConfigurationNodes != nil || in.Connections != nil || in.SourceControlDetails != nil || in.MaintenanceWindow != nil || in.LogUri != nil || in.NotificationProperty != nil || (in.JobRunQueuingEnabled != nil && bool(*in.JobRunQueuingEnabled)) || (in.JobMode != nil && value(in.JobMode) != "SCRIPT") {
		return nil, unsupported("This job requires an unsupported deployment or scheduling feature.")
	}
	if err := validateJob(&job); err != nil {
		return nil, err
	}
	if err := s.authorizeCreate(ctx, tx, "CreateJob", key.Scope, key.ARN("job"), job.Tags); err != nil {
		return nil, err
	}
	if err := s.passRole(ctx, job.Role, key.ARN("job")); err != nil {
		return nil, err
	}
	if existing, err := tx.GetJob(key); err == nil {
		job.CreatedAt, job.UpdatedAt = existing.CreatedAt, existing.UpdatedAt
		if reflect.DeepEqual(job, existing) {
			return &api.CreateJobOutput{Name: in.Name}, nil
		}
		return nil, failure("IdempotentParameterMismatchException", "Job with the same name already exists with different parameters.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	job.CreatedAt = s.clock.Now()
	job.UpdatedAt = job.CreatedAt
	if err := tx.PutJob(job); err != nil {
		return nil, err
	}
	return &api.CreateJobOutput{Name: in.Name}, nil
}
func validateJob(job *JobRecord) error {
	if job.Key.Name == "" || job.Role == "" {
		return failure("InvalidInputException", "Job name and role are required.")
	}
	if !strings.HasPrefix(job.Role, "arn:") {
		job.Role = "arn:" + job.Key.Partition + ":iam::" + job.Key.AccountID + ":role/" + job.Role
	}
	if !strings.HasPrefix(job.Role, "arn:"+job.Key.Partition+":iam::"+job.Key.AccountID+":role/") {
		return failure("InvalidInputException", "Job role must belong to the current account.")
	}
	u, err := url.Parse(job.ScriptLocation)
	if err != nil || u.Scheme != "s3" || u.Host == "" || strings.TrimPrefix(u.Path, "/") == "" || u.RawQuery != "" || u.Fragment != "" {
		return failure("InvalidInputException", "ScriptLocation must identify an S3 object.")
	}
	if job.Timeout < 1 || job.Timeout > 10080 || job.MaxConcurrentRuns < 1 || job.MaxRetries < 0 {
		return failure("InvalidInputException", "Invalid execution limits.")
	}
	if job.ExecutionClass == "" {
		job.ExecutionClass = "STANDARD"
	}
	if job.ExecutionClass != "STANDARD" {
		return unsupported("FLEX execution is not supported.")
	}
	switch job.Command {
	case "glueetl":
		if job.GlueVersion == "" {
			job.GlueVersion = "5.0"
		}
		if job.GlueVersion != "5.0" {
			return unsupported("The installed Glue Spark runtime supports GlueVersion 5.0 only.")
		}
		if job.PythonVersion == "" {
			job.PythonVersion = "3"
		}
		if job.PythonVersion != "3" {
			return unsupported("Glue Spark requires Python 3.")
		}
		if job.WorkerType == "" {
			job.WorkerType = "G.1X"
		}
		if job.WorkerType != "G.1X" {
			return unsupported("Only G.1X local Spark execution is supported.")
		}
		if job.NumberOfWorkers == 0 {
			job.NumberOfWorkers = 2
		}
		if job.NumberOfWorkers != 2 {
			return unsupported("Local Spark execution requires two workers.")
		}
	case "pythonshell":
		job.GlueVersion = "6.0" // Native Python shell ignores this runtime selector.
		if job.PythonVersion == "" || job.PythonVersion == "3" {
			job.PythonVersion = "3.9"
		}
		if job.PythonVersion != "3.9" {
			return unsupported("The installed Python shell runtime supports PythonVersion 3.9 only.")
		}
		if job.WorkerType != "" || job.NumberOfWorkers != 0 {
			return failure("InvalidInputException", "Python shell does not support WorkerType or NumberOfWorkers.")
		}
		if job.MaxCapacity == 0 {
			job.MaxCapacity = 0.0625
		}
		if job.MaxCapacity != 0.0625 && job.MaxCapacity != 1 {
			return failure("InvalidInputException", "Python shell MaxCapacity must be 0.0625 or 1.")
		}
	default:
		return unsupported("Only glueetl and pythonshell commands are executable.")
	}
	// TODO: Comeback implement Glue bookmarks, connections, extra files/modules,
	// streaming/Ray and distributed workers with native owners.
	for key, v := range job.DefaultArguments {
		if err := validateJobArgument(key, v); err != nil {
			return err
		}
	}
	for key, v := range job.NonOverridableArguments {
		if err := validateJobArgument(key, v); err != nil {
			return err
		}
	}
	return nil
}
func validateJobArgument(key, val string) error {
	if !strings.HasPrefix(key, "--") {
		return failure("InvalidInputException", "Job argument names must begin with --.")
	}
	switch key {
	case "--job-bookmark-option":
		if val != "job-bookmark-disable" {
			return unsupported("Job bookmarks are not supported by the local Glue runtime.")
		}
	case "--library-set":
		if val != "none" {
			return unsupported("The installed Python shell image does not include the native analytics library bundle.")
		}
	case "--additional-python-modules", "--extra-py-files", "--extra-jars", "--extra-files", "--connections", "--enable-glue-datacatalog", "--conf":
		return unsupported("Runtime dependency/configuration argument is not supported: " + key)
	}
	return nil
}
func (s *Service) updateJob(ctx context.Context, tx Transaction, in *api.UpdateJobInput) (*api.UpdateJobOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.JobName)}
	old, err := tx.GetJob(key)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, tx, "UpdateJob", key.Scope, key.ARN("job"), old.Tags); err != nil {
		return nil, err
	}
	if in.JobUpdate == nil {
		return nil, failure("InvalidInputException", "JobUpdate is required.")
	}
	u := in.JobUpdate
	// AWS UpdateJob replaces the definition, rather than patching omitted fields.
	job := JobRecord{Key: key, Description: value(u.Description), Role: value(u.Role), GlueVersion: value(u.GlueVersion), WorkerType: value(u.WorkerType), ExecutionClass: value(u.ExecutionClass), SecurityConfiguration: value(u.SecurityConfiguration), DefaultArguments: jobArguments(u.DefaultArguments), NonOverridableArguments: jobArguments(u.NonOverridableArguments), Tags: old.Tags, CreatedAt: old.CreatedAt, UpdatedAt: s.clock.Now(), MaxConcurrentRuns: 1, Timeout: 2880}
	if u.Command != nil {
		job.Command = value(u.Command.Name)
		job.ScriptLocation = value(u.Command.ScriptLocation)
		job.PythonVersion = value(u.Command.PythonVersion)
	}
	if u.ExecutionProperty != nil && u.ExecutionProperty.MaxConcurrentRuns != nil {
		job.MaxConcurrentRuns = int32(*u.ExecutionProperty.MaxConcurrentRuns)
	}
	if u.Timeout != nil {
		job.Timeout = int32(*u.Timeout)
	}
	if u.MaxRetries != nil {
		job.MaxRetries = int32(*u.MaxRetries)
	}
	if u.MaxCapacity != nil {
		job.MaxCapacity = float64(*u.MaxCapacity)
	}
	if u.NumberOfWorkers != nil {
		job.NumberOfWorkers = int32(*u.NumberOfWorkers)
	}
	if (u.AllocatedCapacity != nil && *u.AllocatedCapacity != 0) || u.CodeGenConfigurationNodes != nil || u.Connections != nil || u.SourceControlDetails != nil || u.MaintenanceWindow != nil || u.LogUri != nil || u.NotificationProperty != nil || (u.JobRunQueuingEnabled != nil && bool(*u.JobRunQueuingEnabled)) || (u.JobMode != nil && value(u.JobMode) != "SCRIPT") || (u.Command != nil && u.Command.Runtime != nil) {
		return nil, unsupported("This job update requires an unsupported deployment or scheduling feature.")
	}
	if err := validateJob(&job); err != nil {
		return nil, err
	}
	if err := s.passRole(ctx, job.Role, key.ARN("job")); err != nil {
		return nil, err
	}
	if err := tx.PutJob(job); err != nil {
		return nil, err
	}
	return &api.UpdateJobOutput{JobName: in.JobName}, nil
}
func (s *Service) deleteJob(ctx context.Context, tx Transaction, in *api.DeleteJobInput) (*api.DeleteJobOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.JobName)}
	job, err := tx.GetJob(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err := s.authorize(ctx, tx, "DeleteJob", key.Scope, key.ARN("job"), job.Tags); err != nil {
		return nil, err
	}
	runs, err := tx.ListJobRuns(key)
	if err != nil {
		return nil, err
	}
	for _, run := range runs {
		if run.Active() {
			run.State = "STOPPING"
			run.Error = "Job definition deleted"
			run.Version++
			run.NextAttempt = s.clock.Now()
			if err := tx.PutJobRun(run); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.DeleteJob(key); err != nil {
		return nil, err
	}
	return &api.DeleteJobOutput{JobName: in.JobName}, nil
}
func jobWire(j JobRecord) api.Job {
	out := api.Job{Name: new(api.NameString(j.Key.Name)), Role: new(api.RoleString(j.Role)), Description: new(api.DescriptionString(j.Description)), Command: &api.JobCommand{Name: new(api.GenericString(j.Command)), ScriptLocation: new(api.ScriptLocationString(j.ScriptLocation)), PythonVersion: new(api.PythonVersionString(j.PythonVersion))}, CreatedOn: &j.CreatedAt, LastModifiedOn: &j.UpdatedAt, DefaultArguments: jobWireArguments(j.DefaultArguments), NonOverridableArguments: jobWireArguments(j.NonOverridableArguments), Timeout: new(api.Timeout(j.Timeout)), MaxRetries: new(api.MaxRetries(j.MaxRetries)), ExecutionProperty: &api.ExecutionProperty{MaxConcurrentRuns: new(api.MaxConcurrentRuns(j.MaxConcurrentRuns))}, ExecutionClass: new(api.ExecutionClass(j.ExecutionClass))}
	if j.GlueVersion != "" {
		out.GlueVersion = new(api.GlueVersionString(j.GlueVersion))
	}
	if j.WorkerType != "" {
		out.WorkerType = new(api.WorkerType(j.WorkerType))
		out.NumberOfWorkers = new(api.NullableInteger(j.NumberOfWorkers))
	}
	if j.MaxCapacity != 0 {
		out.MaxCapacity = new(api.NullableDouble(j.MaxCapacity))
	}
	if j.SecurityConfiguration != "" {
		out.SecurityConfiguration = new(api.NameString(j.SecurityConfiguration))
	}
	return out
}
func (s *Service) getJob(ctx context.Context, tx Transaction, in *api.GetJobInput) (*api.GetJobOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.JobName)}
	j, err := tx.GetJob(key)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, tx, "GetJob", key.Scope, key.ARN("job"), j.Tags); err != nil {
		return nil, err
	}
	out := jobWire(j)
	return &api.GetJobOutput{Job: &out}, nil
}

type jobPage struct {
	Scope                 Scope
	Action, Filter, After string
}

func jobPageStart(scope Scope, action, filter, token string) (string, error) {
	if token == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", failure("InvalidInputException", "Invalid pagination token.")
	}
	var p jobPage
	if json.Unmarshal(b, &p) != nil || p.Scope != scope || p.Action != action || p.Filter != filter {
		return "", failure("InvalidInputException", "Invalid pagination token.")
	}
	return p.After, nil
}
func jobPageToken(scope Scope, action, filter, after string) *api.GenericString {
	b, _ := json.Marshal(jobPage{scope, action, filter, after})
	return new(api.GenericString(base64.RawURLEncoding.EncodeToString(b)))
}
func (s *Service) getJobs(ctx context.Context, tx Transaction, in *api.GetJobsInput) (*api.GetJobsOutput, error) {
	scope := scopeFor(ctx)
	if err := s.authorize(ctx, tx, "GetJobs", scope, "*", nil); err != nil {
		return nil, err
	}
	after, err := jobPageStart(scope, "GetJobs", "", value(in.NextToken))
	if err != nil {
		return nil, err
	}
	limit := 100
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	if limit < 1 || limit > 1000 {
		return nil, failure("InvalidInputException", "Invalid MaxResults.")
	}
	jobs, err := tx.ListJobs(scope)
	if err != nil {
		return nil, err
	}
	out := &api.GetJobsOutput{Jobs: api.JobList{}}
	for _, j := range jobs {
		if j.Key.Name <= after {
			continue
		}
		if len(out.Jobs) == limit {
			out.NextToken = jobPageToken(scope, "GetJobs", "", value(out.Jobs[len(out.Jobs)-1].Name))
			break
		}
		out.Jobs = append(out.Jobs, jobWire(j))
	}
	return out, nil
}
func (s *Service) listJobs(ctx context.Context, tx Transaction, in *api.ListJobsInput) (*api.ListJobsOutput, error) {
	scope := scopeFor(ctx)
	if err := s.authorize(ctx, tx, "ListJobs", scope, "*", nil); err != nil {
		return nil, err
	}
	filter, _ := json.Marshal(in.Tags)
	after, err := jobPageStart(scope, "ListJobs", string(filter), value(in.NextToken))
	if err != nil {
		return nil, err
	}
	limit := 100
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	if limit < 1 || limit > 1000 {
		return nil, failure("InvalidInputException", "Invalid MaxResults.")
	}
	jobs, err := tx.ListJobs(scope)
	if err != nil {
		return nil, err
	}
	out := &api.ListJobsOutput{JobNames: api.JobNameList{}}
	for _, j := range jobs {
		match := j.Key.Name > after
		for k, v := range in.Tags {
			if j.Tags[string(k)] != string(v) {
				match = false
			}
		}
		if !match {
			continue
		}
		if len(out.JobNames) == limit {
			out.NextToken = jobPageToken(scope, "ListJobs", string(filter), string(out.JobNames[len(out.JobNames)-1]))
			break
		}
		out.JobNames = append(out.JobNames, api.NameString(j.Key.Name))
	}
	return out, nil
}
func jobResourceTags(tx Reader, scope Scope, arn string) (map[string]string, error) {
	prefix := ResourceKey{Scope: scope}.ARN("job")
	name, ok := strings.CutPrefix(arn, prefix)
	if !ok || name == "" {
		return nil, ErrNotFound
	}
	j, err := tx.GetJob(ResourceKey{scope, name})
	return maps.Clone(j.Tags), err
}
func tagJobResource(tx Transaction, scope Scope, arn string, tags map[string]string) error {
	prefix := ResourceKey{Scope: scope}.ARN("job")
	name, ok := strings.CutPrefix(arn, prefix)
	if !ok || name == "" {
		return ErrNotFound
	}
	j, err := tx.GetJob(ResourceKey{scope, name})
	if err != nil {
		return err
	}
	j.Tags = maps.Clone(tags)
	return tx.PutJob(j)
}
