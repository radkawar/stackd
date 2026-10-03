package ecs

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/ecs"
)

func cloneTaskRecord(v TaskRecord) TaskRecord {
	v.Data.Tags = nil
	v.Data = api.CloneTask(v.Data)
	v.Definition = api.CloneTaskDefinition(v.Definition)
	v.NetworkConfiguration = api.CloneAwsVpcConfiguration(v.NetworkConfiguration)
	v.MetadataTokens = maps.Clone(v.MetadataTokens)
	v.LogCursors = maps.Clone(v.LogCursors)
	v.DependencyWaitStarted = maps.Clone(v.DependencyWaitStarted)
	return v
}

func cloneTaskRunRecord(v TaskRunRecord) TaskRunRecord {
	v.Input = api.CloneRunTaskRequest(v.Input)
	v.TaskIDs = slices.Clone(v.TaskIDs)
	return v
}

func (r memoryReader) Task(k TaskKey) (TaskRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TaskRecord{}, err
	}
	v, ok := r.s.tasks[k]
	if !ok {
		return TaskRecord{}, ErrNotFound
	}
	return cloneTaskRecord(v), nil
}

func (r memoryReader) Tasks(q TaskQuery) ([]TaskRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []TaskRecord{}
	for k, v := range r.s.tasks {
		if k.ClusterKey != q.ClusterKey || k.ID <= q.AfterID ||
			q.ServiceName != "" && v.ServiceName != q.ServiceName ||
			q.ActiveOnly && value(v.Data.LastStatus) == "STOPPED" ||
			q.DesiredStatus != "" && value(v.Data.DesiredStatus) != q.DesiredStatus ||
			q.Family != "" && value(v.Definition.Family) != q.Family ||
			q.StartedBy != "" && value(v.Data.StartedBy) != q.StartedBy ||
			q.LaunchType != "" && value(v.Data.LaunchType) != q.LaunchType {
			continue
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b TaskRecord) int { return strings.Compare(a.Key.ID, b.Key.ID) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	for i := range out {
		out[i] = cloneTaskRecord(out[i])
	}
	return out, nil
}

func (r memoryReader) ActiveTaskKeys() ([]TaskKey, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []TaskKey{}
	for k, v := range r.s.tasks {
		if value(v.Data.LastStatus) != "STOPPED" {
			out = append(out, k)
		}
	}
	slices.SortFunc(out, func(a, b TaskKey) int {
		return cmp.Or(strings.Compare(a.Partition, b.Partition), strings.Compare(a.AccountID, b.AccountID),
			strings.Compare(a.Region, b.Region), strings.Compare(a.Name, b.Name), strings.Compare(a.ID, b.ID))
	})
	return out, nil
}

func (r memoryReader) TaskRun(k TaskRunKey) (TaskRunRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TaskRunRecord{}, err
	}
	v, ok := r.s.taskRuns[k]
	if !ok {
		return TaskRunRecord{}, ErrNotFound
	}
	return cloneTaskRunRecord(v), nil
}

func (w memoryWriter) PutTask(v TaskRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.tasks[v.Key] = cloneTaskRecord(v)
	return nil
}

func (w memoryWriter) PutTaskRun(v TaskRunRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.taskRuns[v.Key] = cloneTaskRunRecord(v)
	return nil
}
