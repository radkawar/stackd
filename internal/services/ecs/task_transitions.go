package ecs

import (
	"context"
	"fmt"
	"reflect"
	"time"

	runtime "stackd/compute/ecs"
	api "stackd/internal/awsapi/ecs"
)

// putTaskTransition owns public task versions, cluster counters and atomic
// native event publication. Internal cursors do not manufacture state events.
func (s *Service) putTaskTransition(ctx context.Context, tx Transaction, record *TaskRecord) error {
	previous, err := tx.Task(record.Key)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(previous.Data, record.Data) {
		return tx.PutTask(*record)
	}
	*record.Data.Version++
	before, after := value(previous.Data.LastStatus), value(record.Data.LastStatus)
	if before != after {
		pending := taskCount(after, "PENDING") - taskCount(before, "PENDING")
		running := taskCount(after, "RUNNING") - taskCount(before, "RUNNING")
		if pending != 0 || running != 0 {
			cluster, err := tx.Cluster(record.Key.ClusterKey)
			if err != nil {
				return err
			}
			*cluster.Data.PendingTasksCount += api.Integer(pending)
			*cluster.Data.RunningTasksCount += api.Integer(running)
			cluster.Updated = s.clock.Now()
			if err := tx.PutCluster(cluster); err != nil {
				return err
			}
		}
	}
	s.tasks.wake()
	if err := tx.PutTask(*record); err != nil {
		return err
	}
	return s.publishTaskEvent(ctx, *record)
}

func (s *Service) publishTaskEvent(ctx context.Context, record TaskRecord) error {
	if s.events == nil {
		return nil
	}
	event, err := taskEvent(record, s.clock.Now().Truncate(time.Millisecond))
	if err != nil {
		return err
	}
	return s.events.PublishTaskEvent(taskOwnerContext(ctx, record), event)
}
func taskCount(status, want string) int {
	if status == want {
		return 1
	}
	return 0
}

func (e *taskExecution) observePrepared() error {
	status, err := e.environment.Inspect(e.ctx)
	if err != nil {
		return err
	}
	return e.service.repository.Update(e.ctx, func(tx Transaction) error {
		record, err := tx.Task(e.key)
		if err != nil {
			return err
		}
		now := e.service.clock.Now().Truncate(time.Millisecond)
		// Preparing resolves installed image manifests; it does not claim a
		// registry download. Both edges can occur at the same service instant.
		if record.Data.PullStartedAt == nil {
			record.Data.PullStartedAt = new(now)
			record.Data.PullStoppedAt = new(now)
		}
		applyTaskObservation(&record, status, now)
		if err := retainReplicaImages(tx, record, status); err != nil {
			return err
		}
		return e.service.putTaskTransition(tx.Context(), tx, &record)
	})
}
func (e *taskExecution) observe(status []runtime.ContainerStatus) error {
	return e.service.repository.Update(e.ctx, func(tx Transaction) error {
		record, err := tx.Task(e.key)
		if err != nil {
			return err
		}
		applyTaskObservation(&record, status, e.service.clock.Now().Truncate(time.Millisecond))
		return e.service.putTaskTransition(tx.Context(), tx, &record)
	})
}

func applyTaskObservation(record *TaskRecord, status []runtime.ContainerStatus, now time.Time) {
	byName := make(map[string]runtime.ContainerStatus, len(status))
	for _, container := range status {
		byName[container.Name] = container
	}
	allStarted := true
	essentialExited := false
	health := api.HealthStatus("HEALTHY")
	hasHealth := false
	for i, definition := range record.Definition.ContainerDefinitions {
		observed, exists := byName[value(definition.Name)]
		if !exists {
			allStarted = false
			continue
		}
		data := &record.Data.Containers[i]
		data.RuntimeId = new(api.String(observed.RuntimeID))
		if observed.ImageDigest != "" {
			data.ImageDigest = new(api.String(observed.ImageDigest))
		}
		data.HealthStatus = new(api.HealthStatus(observed.Health))
		switch observed.State {
		case runtime.ContainerRunning:
			data.LastStatus = new(api.String("RUNNING"))
		case runtime.ContainerExited:
			data.LastStatus = new(api.String("STOPPED"))
		case runtime.ContainerCreated:
			data.LastStatus = new(api.String("PENDING"))
		}
		if observed.ExitCode != nil {
			data.ExitCode = new(api.BoxedInteger(*observed.ExitCode))
		}
		if observed.OOMKilled {
			data.Reason = new(api.String("OutOfMemoryError: Container killed due to memory usage"))
		} else if observed.Error != "" {
			data.Reason = new(api.String(observed.Error))
		}
		if observed.StartedAt.IsZero() {
			allStarted = false
		} else if _, exists := record.DependencyWaitStarted[observed.Name]; !exists {
			record.DependencyWaitStarted[observed.Name] = now
		}
		essential := definition.Essential == nil || bool(*definition.Essential)
		if essential && observed.State == runtime.ContainerExited {
			essentialExited = true
		}
		if essential && definition.HealthCheck != nil {
			hasHealth = true
			if observed.Health == runtime.HealthUnhealthy {
				health = "UNHEALTHY"
			} else if observed.Health != runtime.HealthHealthy && health != "UNHEALTHY" {
				health = "UNKNOWN"
			}
		}
	}
	if !hasHealth {
		health = "UNKNOWN"
	}
	record.Data.HealthStatus = &health
	if value(record.Data.DesiredStatus) == "RUNNING" {
		if allStarted {
			record.Data.LastStatus = new(api.String("RUNNING"))
			if record.Data.StartedAt == nil {
				record.Data.StartedAt = new(now)
			}
		}
		if essentialExited {
			record.Data.DesiredStatus = new(api.String("STOPPED"))
			record.Data.StopCode = new(api.TaskStopCode("EssentialContainerExited"))
			record.Data.StoppedReason = new(api.String("Essential container in task exited"))
			record.Data.StoppingAt = new(now)
			record.Data.ExecutionStoppedAt = new(now)
		}
	}
}

func (e *taskExecution) requestStop(code, reason string) error {
	return e.service.repository.Update(e.ctx, func(tx Transaction) error {
		record, err := tx.Task(e.key)
		if err != nil {
			return err
		}
		if value(record.Data.DesiredStatus) == "STOPPED" {
			return nil
		}
		record.Data.DesiredStatus = new(api.String("STOPPED"))
		record.Data.StopCode = new(api.TaskStopCode(code))
		record.Data.StoppedReason = new(api.String(reason))
		record.Data.StoppingAt = new(e.service.clock.Now().Truncate(time.Millisecond))
		return e.service.putTaskTransition(tx.Context(), tx, &record)
	})
}

// Dependencies gate a container only before its first start. In particular a
// HEALTHY dependency becoming unhealthy later does not stop a standalone task.
func taskReadyContainer(record TaskRecord, status []runtime.ContainerStatus, now time.Time) (string, string) {
	byName := make(map[string]runtime.ContainerStatus, len(status))
	for _, container := range status {
		byName[container.Name] = container
	}
	definitions := make(map[string]api.ContainerDefinition, len(record.Definition.ContainerDefinitions))
	for _, container := range record.Definition.ContainerDefinitions {
		definitions[value(container.Name)] = container
	}
	for _, container := range record.Definition.ContainerDefinitions {
		name := value(container.Name)
		if byName[name].State != runtime.ContainerCreated {
			continue
		}
		ready := true
		for _, dependency := range container.DependsOn {
			providerName := value(dependency.ContainerName)
			provider := byName[providerName]
			met := false
			switch value(dependency.Condition) {
			case "START":
				met = !provider.StartedAt.IsZero()
			case "COMPLETE":
				met = provider.State == runtime.ContainerExited && provider.ExitCode != nil
			case "SUCCESS":
				met = provider.State == runtime.ContainerExited && provider.ExitCode != nil && *provider.ExitCode == 0
				if provider.State == runtime.ContainerExited && !met {
					return "", fmt.Sprintf("Container dependency %s for %s did not complete successfully", providerName, name)
				}
			case "HEALTHY":
				met = provider.Health == runtime.HealthHealthy
			}
			if met {
				continue
			}
			if provider.State == runtime.ContainerExited {
				return "", fmt.Sprintf("Container dependency %s for %s stopped before satisfying %s", providerName, name, value(dependency.Condition))
			}
			ready = false
			definition := definitions[providerName]
			if started, exists := record.DependencyWaitStarted[providerName]; exists && definition.StartTimeout != nil && value(dependency.Condition) != "START" && provider.State != runtime.ContainerExited && now.After(started.Add(time.Duration(*definition.StartTimeout)*time.Second)) {
				return "", fmt.Sprintf("Container dependency %s for %s timed out", providerName, name)
			}
		}
		if ready {
			return name, ""
		}
	}
	return "", ""
}
