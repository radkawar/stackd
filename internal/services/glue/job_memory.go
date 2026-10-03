package glue

import (
	"cmp"
	"maps"
	"slices"
)

type jobRunKey struct {
	Job ResourceKey
	ID  string
}
type jobsMemory struct {
	jobDefinitions map[ResourceKey]JobRecord
	jobRuns        map[jobRunKey]JobRunRecord
}

func initJobsMemory() jobsMemory {
	return jobsMemory{jobDefinitions: map[ResourceKey]JobRecord{}, jobRuns: map[jobRunKey]JobRunRecord{}}
}
func cloneJobsMemory(v jobsMemory) jobsMemory {
	v.jobDefinitions = maps.Clone(v.jobDefinitions)
	v.jobRuns = maps.Clone(v.jobRuns)
	return v
}
func cloneJob(v JobRecord) JobRecord {
	v.DefaultArguments = maps.Clone(v.DefaultArguments)
	v.NonOverridableArguments = maps.Clone(v.NonOverridableArguments)
	v.Tags = maps.Clone(v.Tags)
	return v
}
func cloneJobRun(v JobRunRecord) JobRunRecord {
	v.Arguments = maps.Clone(v.Arguments)
	v.RunArguments = maps.Clone(v.RunArguments)
	v.Attempts = slices.Clone(v.Attempts)
	return v
}
func (r memoryReader) GetJob(key ResourceKey) (JobRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return JobRecord{}, err
	}
	v, ok := r.s.jobDefinitions[key]
	if !ok {
		return JobRecord{}, ErrNotFound
	}
	return cloneJob(v), nil
}
func (r memoryReader) ListJobs(scope Scope) ([]JobRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []JobRecord{}
	for key, v := range r.s.jobDefinitions {
		if key.Scope == scope {
			out = append(out, cloneJob(v))
		}
	}
	slices.SortFunc(out, func(a, b JobRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) GetJobRun(key ResourceKey, id string) (JobRunRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return JobRunRecord{}, err
	}
	v, ok := r.s.jobRuns[jobRunKey{key, id}]
	if !ok {
		return JobRunRecord{}, ErrNotFound
	}
	return cloneJobRun(v), nil
}
func (r memoryReader) ListJobRuns(key ResourceKey) ([]JobRunRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []JobRunRecord{}
	for k, v := range r.s.jobRuns {
		if k.Job == key {
			out = append(out, cloneJobRun(v))
		}
	}
	slices.SortFunc(out, func(a, b JobRunRecord) int { return cmp.Or(b.StartedAt.Compare(a.StartedAt), cmp.Compare(b.ID, a.ID)) })
	return out, nil
}
func (r memoryReader) PendingJobRuns() ([]JobRunRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []JobRunRecord{}
	for _, v := range r.s.jobRuns {
		if v.Active() || v.CleanupPending || !v.Published {
			out = append(out, cloneJobRun(v))
		}
	}
	slices.SortFunc(out, func(a, b JobRunRecord) int {
		return cmp.Or(a.NextAttempt.Compare(b.NextAttempt), cmp.Compare(a.ExecutionKey(), b.ExecutionKey()))
	})
	return out, nil
}
func (w memoryWriter) PutJob(v JobRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.jobDefinitions[v.Key] = cloneJob(v)
	return nil
}
func (w memoryWriter) DeleteJob(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.jobDefinitions, key)
	return nil
}
func (w memoryWriter) PutJobRun(v JobRunRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.jobRuns[jobRunKey{v.Key, v.ID}] = cloneJobRun(v)
	return nil
}
