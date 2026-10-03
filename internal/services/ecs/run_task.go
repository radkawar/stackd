package ecs

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
)

func (s *Service) runTask(ctx context.Context, tx Transaction, in *api.RunTaskInput) (*api.RunTaskOutput, error) {
	key, rejected := definitionKey(ctx, value(in.TaskDefinition), false)
	if rejected != nil {
		return nil, rejected
	}
	definition, err := loadDefinition(tx, key)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ClientException", "TaskDefinition not found.")
	}
	if err != nil {
		return nil, err
	}
	cluster, err := taskCluster(ctx, tx, value(in.Cluster))
	if err != nil {
		return nil, err
	}
	if value(definition.Data.Status) != "ACTIVE" {
		return nil, failure("ClientException", "TaskDefinition is inactive")
	}
	requestedTags, conditions, rejected := admitTags(in.Tags, "InvalidParameterException")
	if rejected != nil {
		return nil, rejected
	}
	conditions["ecs:cluster"] = []string{cluster.Key.ARN()}
	conditions["ecs:enable-execute-command"] = []string{strconv.FormatBool(in.EnableExecuteCommand != nil && bool(*in.EnableExecuteCommand))}
	definitionTags, err := tagsFor(tx, key.Scope, definition.Key.ARN())
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "RunTask", definition.Key.ARN(), definitionTags, conditions); err != nil {
		return nil, err
	}
	count := 1
	if in.Count != nil {
		count = int(*in.Count)
	}
	if count < 1 || count > 10 {
		return nil, failure("InvalidParameterException", "Count must be between 1 and 10.")
	}
	if in.ClientToken != nil && (len(value(in.ClientToken)) < 1 || len(value(in.ClientToken)) > 64) {
		return nil, failure("InvalidParameterException", "clientToken must contain between 1 and 64 characters.")
	}
	plan, err := s.prepareTask(ctx, in, cluster, definition)
	if err != nil {
		return nil, err
	}
	// Native replay rechecks definition eligibility and the caller's authority.
	// The token binds exact presence, ordering and identifier spelling, not defaults.
	tokenKey := TaskRunKey{ClusterKey: cluster.Key, ClientToken: value(in.ClientToken)}
	if tokenKey.ClientToken != "" {
		previous, err := tx.TaskRun(tokenKey)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if err == nil {
			out, active, err := taskRunReplay(tx, previous, s.clock.Now())
			if err != nil {
				return nil, err
			}
			if active {
				if !reflect.DeepEqual(previous.Input, *in) {
					ids := make([]string, len(out.Tasks))
					for i, task := range out.Tasks {
						ids[i] = value(task.TaskArn)
					}
					return nil, &awswire.Error{Code: "ConflictException", StatusCode: 400, Message: "The RunTask request could not be processed due to conflicts. The provided clientToken is already in use with a different request.", ResourceIDs: ids}
				}
				return out, nil
			}
		}
	}
	tags := requestedTags
	switch value(in.PropagateTags) {
	case "", "NONE":
	case "TASK_DEFINITION":
		tags = mergeTaskTags(definitionTags, requestedTags)
	default:
		return nil, failure("InvalidParameterException", "Only task definition tags can be propagated to standalone tasks.")
	}
	if len(tags) > 50 {
		return nil, failure("InvalidParameterException", "The maximum number of tags per resource is 50.")
	}
	now := s.clock.Now().Truncate(time.Millisecond)
	out := &api.RunTaskOutput{Tasks: api.Tasks{}, Failures: api.Failures{}}
	run := TaskRunRecord{Key: tokenKey, Input: api.CloneRunTaskRequest(*in), Created: now}
	for range count {
		record := s.buildTask(plan, apievents.EventID(ctx))
		taskKey := record.Key
		if err := s.validateTaskRoles(ctx, plan, taskKey.ARN()); err != nil {
			return nil, err
		}
		if len(requestedTags) > 0 {
			conditions["ecs:CreateAction"] = []string{"RunTask"}
			if err := s.authorize(ctx, "TagResource", taskKey.ARN(), nil, conditions); err != nil {
				return nil, err
			}
		}
		if err := s.acceptTask(ctx, tx, record, tags, in.EnableECSManagedTags != nil && bool(*in.EnableECSManagedTags), ""); err != nil {
			return nil, err
		}
		record.Data.Tags, err = tagsFor(tx, taskKey.Scope, taskKey.ARN())
		if err != nil {
			return nil, err
		}
		run.TaskIDs = append(run.TaskIDs, taskKey.ID)
		out.Tasks = append(out.Tasks, record.Data)
	}
	if tokenKey.ClientToken != "" {
		if err := tx.PutTaskRun(run); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func taskLaunchType(in *api.RunTaskInput, cluster api.Cluster) (string, string, *awswire.Error) {
	strategy := in.CapacityProviderStrategy
	if in.LaunchType != nil && len(strategy) > 0 {
		return "", "", failure("InvalidParameterException", "Capacity provider strategy and launch type cannot both be specified.")
	}
	if in.LaunchType != nil {
		return value(in.LaunchType), "", nil
	}
	if len(strategy) == 0 {
		strategy = cluster.DefaultCapacityProviderStrategy
	}
	if len(strategy) == 0 {
		return "FARGATE", "", nil
	} // Intentional local default, documented in docs/ecs.md.
	for _, provider := range strategy {
		if value(provider.CapacityProvider) != "FARGATE" {
			return "", "", unsupported("This capacity provider requires its real capacity and interruption lifecycle.")
		}
	}
	return "FARGATE", "FARGATE", nil
}

func taskRunReplay(r Reader, run TaskRunRecord, now time.Time) (*api.RunTaskOutput, bool, error) {
	out := &api.RunTaskOutput{Tasks: api.Tasks{}, Failures: api.Failures{}}
	expires := run.Created.Add(24 * time.Hour)
	allStopped := true
	var lastStop time.Time
	for _, id := range run.TaskIDs {
		record, err := r.Task(TaskKey{ClusterKey: run.Key.ClusterKey, ID: id})
		if err != nil {
			return nil, false, err
		}
		if value(record.Data.LastStatus) != "STOPPED" || record.Data.StoppedAt == nil {
			allStopped = false
		} else if record.Data.StoppedAt.After(lastStop) {
			lastStop = *record.Data.StoppedAt
		}
		record.Data.Tags, err = tagsFor(r, record.Key.Scope, record.Key.ARN())
		if err != nil {
			return nil, false, err
		}
		out.Tasks = append(out.Tasks, record.Data)
	}
	if allStopped && lastStop.Add(time.Hour).Before(expires) {
		expires = lastStop.Add(time.Hour)
	}
	return out, now.Before(expires), nil
}
