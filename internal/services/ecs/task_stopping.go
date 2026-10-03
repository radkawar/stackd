package ecs

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	runtime "stackd/compute/ecs"
	"stackd/compute/network"
	api "stackd/internal/awsapi/ecs"
)

func (e *taskExecution) stop(record TaskRecord) error {
	// Preserve the process and its ENI until the owner confirms that no traffic
	// for this exact task incarnation remains. Replays do not restart draining.
	for {
		// A pending or rejected ELB drain is not permission to keep a stale
		// packet policy. Native safety is independent of target cleanup.
		if err := e.secureDrainingTask(record); err != nil {
			return err
		}
		drained, err := e.drainTargets(record)
		if err != nil {
			return err
		}
		if drained {
			break
		}
		select {
		case <-e.ctx.Done():
			return e.ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	if value(record.Data.LastStatus) != "DEPROVISIONING" {
		if err := e.service.repository.Update(e.ctx, func(tx Transaction) error {
			current, err := tx.Task(e.key)
			if err != nil {
				return err
			}
			current.Data.LastStatus = new(api.String("STOPPING"))
			return e.service.putTaskTransition(tx.Context(), tx, &current)
		}); err != nil {
			return err
		}
		processes := runtime.TaskProcesses(e.environment)
		if processes == nil {
			var err error
			processes, err = e.service.executor.Processes(e.ctx, e.service.taskSpecification(record, network.Specification{}, nil, nil))
			if err != nil {
				return err
			}
		}
		status, err := processes.Inspect(e.ctx)
		if err != nil {
			return err
		}
		for _, container := range status {
			if !container.StartedAt.IsZero() {
				if err := e.openLogs(record); err != nil {
					slog.Warn("ECS retained logs unavailable during stop", "task", e.key.ARN(), "error", err)
				}
				break
			}
		}
		for _, container := range status {
			if !container.StartedAt.IsZero() {
				e.startLogs(record, processes, container.Name)
			}
		}
		if err := e.stopContainers(processes, record, status); err != nil {
			return err
		}
		status, err = processes.Inspect(e.ctx)
		if err != nil {
			return err
		}
		if err := e.observe(status); err != nil {
			return err
		}
		e.drainLogs()
		if err := e.service.repository.Update(e.ctx, func(tx Transaction) error {
			current, err := tx.Task(e.key)
			if err != nil {
				return err
			}
			current.Data.LastStatus = new(api.String("DEPROVISIONING"))
			for i := range current.Data.Containers {
				current.Data.Containers[i].LastStatus = new(api.String("STOPPED"))
			}
			if current.Data.ExecutionStoppedAt == nil && len(current.DependencyWaitStarted) > 0 {
				current.Data.ExecutionStoppedAt = new(e.service.clock.Now().Truncate(time.Millisecond))
			}
			return e.service.putTaskTransition(tx.Context(), tx, &current)
		}); err != nil {
			return err
		}
	}
	if value(record.Data.Attachments[0].Status) != "PRECREATED" {
		if e.specification.TaskARN == "" {
			e.specification = runtime.Specification{TaskARN: e.key.ARN()}
		}
		if err := e.service.executor.Remove(e.ctx, e.specification); err != nil {
			return err
		}
	}
	// Native resources have gone before the IP becomes reusable. ENI release,
	// terminal task state and its event commit in the same shared transaction.
	return e.service.repository.Update(e.ctx, func(tx Transaction) error {
		current, err := tx.Task(e.key)
		if err != nil {
			return err
		}
		if err := e.service.networks.Release(taskOwnerContext(tx.Context(), current), e.key.ARN(), current.Data.Attachments[0]); err != nil {
			return err
		}
		current.Data.Attachments[0].Status = new(api.String("DELETED"))
		current.Data.LastStatus = new(api.String("STOPPED"))
		current.Data.StoppedAt = new(e.service.clock.Now().Truncate(time.Millisecond))
		if err := e.service.putTaskTransition(tx.Context(), tx, &current); err != nil {
			return err
		}
		return e.service.reapTaskDefinitions(tx, current.Key.Scope)
	})
}

// secureDrainingTask preserves graceful draining only while current EC2 policy
// can be enforced. Recovery without a policy-capable attachment cannot trust the
// retained native policy: attach only to owned processes and stop them immediately.
// The ENI remains reserved until the independent target drain has completed.
func (e *taskExecution) secureDrainingTask(record TaskRecord) error {
	if value(record.Data.LastStatus) == "DEPROVISIONING" || value(record.Data.Attachments[0].Status) == "PRECREATED" {
		return nil
	}
	if err := e.ctx.Err(); err != nil {
		return err
	}
	var cause error
	if e.environment != nil {
		cause = e.refreshNetwork(record)
		if cause == nil {
			return nil
		}
	} else {
		cause = errors.New("stopping task has no attached native policy enforcer")
	}
	if err := e.ctx.Err(); err != nil {
		return err
	}
	processes := runtime.TaskProcesses(e.environment)
	if processes == nil {
		var err error
		processes, err = e.service.executor.Processes(e.ctx, e.service.taskSpecification(record, network.Specification{}, nil, nil))
		if err != nil {
			return errors.Join(cause, err)
		}
	}
	status, err := processes.Inspect(e.ctx)
	if err != nil {
		return errors.Join(cause, err)
	}
	var stopped bool
	var stopErr error
	for _, container := range status {
		if container.State == runtime.ContainerRunning {
			// Network revocation cannot wait for customer shutdown timeouts or
			// container dependencies, and one failure must not spare the rest.
			stopErr = errors.Join(stopErr, processes.Stop(e.ctx, container.Name, 0))
			stopped = true
		}
	}
	if stopErr != nil {
		return errors.Join(cause, stopErr)
	}
	if stopped {
		slog.Warn("ECS stopped unsecured task processes before target drain", "task", e.key.ARN(), "error", cause)
	}
	return nil
}

func (e *taskExecution) stopContainers(processes runtime.TaskProcesses, record TaskRecord, status []runtime.ContainerStatus) error {
	remaining := map[string]api.ContainerDefinition{}
	for i, container := range record.Definition.ContainerDefinitions {
		for _, observed := range status {
			if observed.Name == value(container.Name) && observed.State == runtime.ContainerRunning {
				remaining[observed.Name] = record.Definition.ContainerDefinitions[i]
				break
			}
		}
	}
	for len(remaining) > 0 {
		var leaves []api.ContainerDefinition
		for name, container := range remaining {
			dependent := false
			for _, other := range remaining {
				for _, dependency := range other.DependsOn {
					if value(dependency.ContainerName) == name {
						dependent = true
					}
				}
			}
			if !dependent {
				leaves = append(leaves, container)
			}
		}
		// Cycles are rejected at definition admission; do not force through an
		// impossible graph and silently violate the shutdown contract.
		if len(leaves) == 0 {
			return errors.New("ECS task shutdown graph contains a cycle")
		}
		var work sync.WaitGroup
		failures := make(chan error, len(leaves))
		for _, container := range leaves {
			work.Go(func() {
				timeout := 30 * time.Second
				if container.StopTimeout != nil {
					timeout = time.Duration(*container.StopTimeout) * time.Second
				}
				if err := processes.Stop(e.ctx, value(container.Name), timeout); err != nil {
					failures <- err
				}
			})
		}
		work.Wait()
		close(failures)
		var joined error
		for failure := range failures {
			joined = errors.Join(joined, failure)
		}
		if joined != nil {
			return joined
		}
		for _, container := range leaves {
			delete(remaining, value(container.Name))
		}
	}
	return nil
}

func (e *taskExecution) drainLogs() {
	done := make(chan struct{})
	go func() { e.logWork.Wait(); close(done) }()
	select {
	case <-done:
	case <-e.ctx.Done():
	case <-time.After(20 * time.Second):
		slog.Warn("ECS task log readers did not drain before cleanup", "task", e.key.ARN())
	}
	if e.logCancel != nil {
		e.logCancel()
	}
	<-done
	for name, sink := range e.logs {
		if err := sink.Close(); err != nil {
			slog.Warn("ECS task log delivery incomplete", "task", e.key.ARN(), "container", name, "error", err)
		}
		delete(e.logs, name)
	}
}
