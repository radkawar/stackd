package ecs

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
)

func taskKey(ctx context.Context, cluster ClusterKey, id string) (TaskKey, *awswire.Error) {
	scope, name, rejected := resourceID(ctx, id, "task")
	if rejected != nil {
		return TaskKey{}, rejected
	}
	if owner, task, qualified := strings.Cut(name, "/"); qualified {
		if owner != cluster.Name || strings.Contains(task, "/") {
			return TaskKey{}, failure("InvalidParameterException", "The task does not belong to the specified cluster.")
		}
		name = task
	}
	if name == "" {
		return TaskKey{}, failure("InvalidParameterException", "Task identifier cannot be empty.")
	}
	return TaskKey{ClusterKey: ClusterKey{Scope: scope, Name: cluster.Name}, ID: name}, nil
}

// taskCluster resolves the parent without substituting cluster authorization
// for the task/task-definition resource permissions of these operations.
func taskCluster(ctx context.Context, r Reader, id string) (ClusterRecord, error) {
	key, rejected := clusterKey(ctx, id)
	if rejected != nil {
		return ClusterRecord{}, rejected
	}
	cluster, err := r.Cluster(key)
	if errors.Is(err, ErrNotFound) {
		return ClusterRecord{}, failure("ClusterNotFoundException", "Cluster not found.")
	}
	if err == nil && value(cluster.Data.Status) != "ACTIVE" {
		return ClusterRecord{}, failure("ClientException", "Cluster was not ACTIVE.")
	}
	return cluster, err
}

func (s *Service) describeTasks(ctx context.Context, tx Transaction, in *api.DescribeTasksInput) (*api.DescribeTasksOutput, error) {
	if len(in.Tasks) < 1 || len(in.Tasks) > 100 {
		return nil, failure("InvalidParameterException", "tasks must contain between 1 and 100 entries.")
	}
	cluster, err := taskCluster(ctx, tx, value(in.Cluster))
	if err != nil {
		return nil, err
	}
	out := &api.DescribeTasksOutput{Tasks: api.Tasks{}, Failures: api.Failures{}}
	for _, id := range in.Tasks {
		key, rejected := taskKey(ctx, cluster.Key, string(id))
		if rejected != nil {
			return nil, rejected
		}
		tags, err := tagsFor(tx, key.Scope, key.ARN())
		if err != nil {
			return nil, err
		}
		if err := s.authorize(ctx, "DescribeTasks", key.ARN(), tags, map[string][]string{"ecs:cluster": {cluster.Key.ARN()}}); err != nil {
			return nil, err
		}
		record, err := tx.Task(key)
		if errors.Is(err, ErrNotFound) {
			out.Failures = append(out.Failures, api.Failure{Arn: new(id), Reason: new(api.String("MISSING"))})
			continue
		}
		if err != nil {
			return nil, err
		}
		record.Data.Tags = api.Tags{}
		if slices.Contains(in.Include, api.TaskField("TAGS")) {
			record.Data.Tags = tags
		}
		out.Tasks = append(out.Tasks, record.Data)
	}
	return out, nil
}

func (s *Service) listTasks(ctx context.Context, tx Transaction, in *api.ListTasksInput) (*api.ListTasksOutput, error) {
	cluster, err := taskCluster(ctx, tx, value(in.Cluster))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "ListTasks", "*", nil, map[string][]string{"ecs:cluster": {cluster.Key.ARN()}}); err != nil {
		return nil, err
	}
	if in.ContainerInstance != nil || in.DaemonName != nil {
		return nil, unsupported("Task queries for container instances and daemons require those resource lifecycles.")
	}
	if in.StartedBy != nil && (in.DesiredStatus != nil || in.Family != nil || in.LaunchType != nil || in.ServiceName != nil) {
		return nil, failure("InvalidParameterException", "startedBy must be the only task filter.")
	}
	serviceName := ""
	if in.ServiceName != nil {
		key, rejected := serviceKey(ctx, cluster.Key, value(in.ServiceName))
		if rejected != nil {
			return nil, rejected
		}
		serviceName = key.ServiceName
	}
	status := value(in.DesiredStatus)
	if status == "" {
		status = "RUNNING"
	}
	limit, rejected := pageSize(in.MaxResults)
	if rejected != nil {
		return nil, rejected
	}
	identity := collection(cluster.Key.Scope, "tasks", cluster.Key.Name, status, value(in.Family), value(in.StartedBy), value(in.LaunchType), serviceName)
	after, rejected := page(in.NextToken, identity)
	if rejected != nil {
		return nil, rejected
	}
	query := TaskQuery{ClusterKey: cluster.Key, DesiredStatus: status, Family: value(in.Family), StartedBy: value(in.StartedBy), LaunchType: value(in.LaunchType), ServiceName: serviceName, AfterID: after, Limit: limit + 1}
	rows, err := tx.Tasks(query)
	if err != nil {
		return nil, err
	}
	out := &api.ListTasksOutput{TaskArns: api.StringList{}}
	lastID := ""
	for _, row := range rows {
		if len(out.TaskArns) == limit {
			out.NextToken = nextPage(identity, lastID)
			break
		}
		out.TaskArns = append(out.TaskArns, api.String(row.Key.ARN()))
		lastID = row.Key.ID
	}
	return out, nil
}

func (s *Service) stopTask(ctx context.Context, tx Transaction, in *api.StopTaskInput) (*api.StopTaskOutput, error) {
	cluster, err := taskCluster(ctx, tx, value(in.Cluster))
	if err != nil {
		return nil, err
	}
	key, rejected := taskKey(ctx, cluster.Key, value(in.Task))
	if rejected != nil {
		return nil, rejected
	}
	tags, err := tagsFor(tx, key.Scope, key.ARN())
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "StopTask", key.ARN(), tags, map[string][]string{"ecs:cluster": {cluster.Key.ARN()}}); err != nil {
		return nil, err
	}
	record, err := tx.Task(key)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("InvalidParameterException", "The referenced task was not found.")
	}
	if err != nil {
		return nil, err
	}
	if value(record.Data.DesiredStatus) != "STOPPED" {
		if s.executor == nil {
			return nil, unsupported("No ECS container executor is configured.")
		}
		record.Data.DesiredStatus = new(api.String("STOPPED"))
		record.AcceptedEventID = apievents.EventID(ctx)
		record.Data.StopCode = new(api.TaskStopCode("UserInitiated"))
		reason := value(in.Reason)
		if reason == "" {
			reason = "User initiated"
		}
		record.Data.StoppedReason = new(api.String(reason))
		record.Data.StoppingAt = new(s.clock.Now().Truncate(time.Millisecond))
		if err := s.putTaskTransition(ctx, tx, &record); err != nil {
			return nil, err
		}
	}
	// Native StopTask omits current task tags even though Describe/replay retain them.
	record.Data.Tags = api.Tags{}
	return &api.StopTaskOutput{Task: &record.Data}, nil
}

// ObserveTaskCompletion projects the authoritative stopped task for a trusted
// completion-event consumer. Public polling must use DescribeTasks instead.
// No runtime observation or external effect runs inside this repository view.
func (s *Service) ObserveTaskCompletion(ctx context.Context, arn string) (*api.Task, error) {
	scope, resource, rejected := resourceID(ctx, arn, "task")
	if rejected != nil {
		return nil, rejected
	}
	cluster, id, qualified := strings.Cut(resource, "/")
	if !qualified || cluster == "" || id == "" || strings.Contains(id, "/") {
		return nil, failure("InvalidParameterException", "A cluster-qualified task ARN is required.")
	}
	var task api.Task
	err := s.repository.View(ctx, func(r Reader) error {
		record, err := r.Task(TaskKey{ClusterKey: ClusterKey{Scope: scope, Name: cluster}, ID: id})
		if err != nil {
			return err
		}
		if value(record.Data.LastStatus) != "STOPPED" {
			return errors.New("ECS completion event precedes the retained stopped task")
		}
		task = taskEventProjection(record.Data)
		task.Tags = api.Tags{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &task, nil
}
