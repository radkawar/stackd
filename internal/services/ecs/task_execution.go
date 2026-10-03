package ecs

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"time"

	runtime "stackd/compute/ecs"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// A failed network authority refresh cannot be treated like an unavailable log
// destination while retained customer processes continue running.
type taskNetworkError struct{ error }

type taskExecution struct {
	service       *Service
	key           TaskKey
	ctx           context.Context
	mu            sync.Mutex
	environment   runtime.Environment
	prepared      bool
	specification runtime.Specification
	credentialMu  sync.Mutex
	credentials   map[string]identity.Credential
	origin        TaskRecord
	logs          map[string]TaskLogSink
	logContext    context.Context
	logCancel     context.CancelFunc
	logWork       sync.WaitGroup
	logStarted    map[string]bool
}

func (e *taskExecution) load() (TaskRecord, error) {
	var record TaskRecord
	err := e.service.repository.View(e.ctx, func(r Reader) error { var err error; record, err = r.Task(e.key); return err })
	return record, err
}
func (e *taskExecution) run() {
	defer func() {
		if e.logCancel != nil {
			e.logCancel()
		}
		e.logWork.Wait()
		for _, sink := range e.logs {
			if err := sink.Close(); err != nil {
				slog.Warn("ECS log drain failed", "task", e.key.ARN(), "error", err)
			}
		}
		e.mu.Lock()
		environment := e.environment
		e.mu.Unlock()
		if environment != nil {
			if err := environment.Close(); err != nil {
				slog.Warn("ECS runtime detach failed", "task", e.key.ARN(), "error", err)
			}
		}
	}()
	for e.ctx.Err() == nil {
		record, err := e.load()
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				slog.Error("ECS task state unavailable", "task", e.key.ARN(), "error", err)
			}
			return
		}
		if value(record.Data.LastStatus) == "STOPPED" {
			return
		}
		if e.origin.Key.ID == "" {
			e.origin = record
		}
		if value(record.Data.DesiredStatus) == "STOPPED" {
			if err := e.stop(record); err != nil {
				if !e.pause("task stop", err) {
					return
				}
				continue
			}
			return
		}
		if !e.prepared {
			if err := e.prepare(record); err != nil {
				if e.ctx.Err() != nil {
					return
				}
				retained := record.Data.StartedAt != nil
				for _, container := range record.Data.Containers {
					retained = retained || value(container.RuntimeId) != ""
				}
				var networkFailure *taskNetworkError
				if retained && !errors.As(err, &networkFailure) && !errors.Is(err, runtime.ErrNetworkPolicy) {
					// A failed controller reattachment is not proof that retained
					// customer processes have failed. Preserve them for recovery.
					if !e.pause("runtime reattachment", err) {
						return
					}
					continue
				}
				if failureErr := e.requestStop("TaskFailedToStart", "ResourceInitializationError: "+err.Error()); failureErr != nil {
					if !e.pause("startup failure commit", failureErr) {
						return
					}
				}
				continue
			}
			continue
		}
		status, err := e.environment.Inspect(e.ctx)
		if err != nil {
			if !e.pause("runtime inspection", err) {
				return
			}
			continue
		}
		if err := e.observe(status); err != nil {
			if !e.pause("runtime observation commit", err) {
				return
			}
			continue
		}
		record, err = e.load()
		if err != nil {
			if !e.pause("task refresh", err) {
				return
			}
			continue
		}
		if value(record.Data.DesiredStatus) == "STOPPED" {
			continue
		}
		if err := e.refreshNetwork(record); err != nil {
			// Continuing to run with a policy that can no longer be resolved or
			// applied would silently grant stale network authority.
			if failureErr := e.requestStop("TaskFailedToStart", "ResourceInitializationError: task networking: "+err.Error()); failureErr != nil {
				if !e.pause("network failure commit", failureErr) {
					return
				}
			}
			continue
		}
		if err := e.registerTargets(record); err != nil {
			if failureErr := e.requestStop("TaskFailedToStart", "ResourceInitializationError: load balancer registration: "+err.Error()); failureErr != nil {
				if !e.pause("target registration failure commit", failureErr) {
					return
				}
			}
			continue
		}
		name, reason := taskReadyContainer(record, status, e.service.clock.Now())
		if reason != "" {
			slog.Warn("ECS task dependency failed", "task", e.key.ARN(), "reason", reason)
			if err := e.requestStop("TaskFailedToStart", "Task failed to start"); err != nil {
				if !e.pause("dependency failure commit", err) {
					return
				}
			}
			continue
		}
		if name != "" {
			if err := e.environment.Start(e.ctx, name); err != nil {
				if err = e.requestStop("TaskFailedToStart", "CannotStartContainerError: "+err.Error()); err != nil {
					if !e.pause("container start failure commit", err) {
						return
					}
				}
				continue
			}
			e.startLogs(record, e.environment, name)
			continue
		}
		select {
		case <-e.ctx.Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (e *taskExecution) pause(operation string, err error) bool {
	if e.ctx.Err() != nil {
		return false
	}
	slog.Error("ECS task reconciliation failed", "task", e.key.ARN(), "operation", operation, "error", err)
	select {
	case <-e.ctx.Done():
		return false
	case <-time.After(time.Second):
		return true
	}
}

func (e *taskExecution) prepare(record TaskRecord) error {
	if value(record.Data.Attachments[0].Status) == "PRECREATED" {
		err := e.service.repository.Update(taskOwnerContext(e.ctx, record), func(tx Transaction) error {
			current, err := tx.Task(e.key)
			if err != nil {
				return err
			}
			if value(current.Data.DesiredStatus) == "STOPPED" {
				return nil
			}
			network, err := e.service.networks.Allocate(tx.Context(), e.key.ARN(), current.Data.Attachments[0], current.NetworkConfiguration)
			if err != nil {
				return err
			}
			current.Data.Attachments[0] = network.Attachment
			for i := range current.Data.Containers {
				current.Data.Containers[i].NetworkInterfaces = api.NetworkInterfaces{{AttachmentId: network.Attachment.Id, PrivateIpv4Address: new(api.String(network.Network.Address.String()))}}
			}
			current.Data.Connectivity = new(api.Connectivity("CONNECTED"))
			current.Data.ConnectivityAt = new(e.service.clock.Now().Truncate(time.Millisecond))
			current.Data.LastStatus = new(api.String("PENDING"))
			return e.service.putTaskTransition(tx.Context(), tx, &current)
		})
		if err != nil {
			return err
		}
		record, err = e.load()
		if err != nil {
			return err
		}
		if value(record.Data.DesiredStatus) == "STOPPED" {
			return nil
		}
	}
	if e.environment == nil {
		network, err := e.service.networks.Resolve(taskOwnerContext(e.ctx, record), e.key.ARN(), record.Data.Attachments[0])
		if err != nil {
			return &taskNetworkError{err}
		}
		metadata := newTaskMetadata(e.service, e.key, e.credentialSource(taskRoleARN(record)), e)
		e.specification = e.service.taskSpecification(record, network, metadata, e.credentialSource(taskExecutionRoleARN(record)))
		if err := e.service.applyReplicaImages(e.ctx, record, &e.specification); err != nil {
			return err
		}
		environment, err := e.service.executor.Prepare(taskOwnerContext(e.ctx, record), e.specification)
		if err != nil {
			return err
		}
		e.mu.Lock()
		e.environment = environment
		e.mu.Unlock()
		if err := e.observePrepared(); err != nil {
			return err
		}
	} else if err := e.refreshNetwork(record); err != nil {
		return &taskNetworkError{err}
	}
	if err := e.openLogs(record); err != nil {
		return err
	}
	status, err := e.environment.Inspect(e.ctx)
	if err != nil {
		return err
	}
	for _, container := range status {
		if !container.StartedAt.IsZero() {
			e.startLogs(record, e.environment, container.Name)
		}
	}
	e.prepared = true
	return nil
}

func (e *taskExecution) credentialSource(role string) TaskCredentialSource {
	return func(ctx context.Context) (identity.Credential, *awswire.Error) {
		e.credentialMu.Lock()
		defer e.credentialMu.Unlock()
		if role == "" {
			return identity.Credential{}, failure("AccessDeniedException", "No role is configured for this task consumer.")
		}
		if credential, ok := e.credentials[role]; ok && credential.Expiration.After(e.service.clock.Now().Add(5*time.Minute)) {
			return credential, nil
		}
		credential, rejected := e.service.taskRoles.Assume(taskOwnerContext(ctx, e.origin), role, e.key.ARN())
		if rejected != nil {
			return identity.Credential{}, rejected
		}
		if e.credentials == nil {
			e.credentials = map[string]identity.Credential{}
		}
		e.credentials[role] = credential
		return credential, nil
	}
}

func (e *taskExecution) refreshNetwork(record TaskRecord) error {
	network, err := e.service.networks.Resolve(taskOwnerContext(e.ctx, record), e.key.ARN(), record.Data.Attachments[0])
	if err != nil {
		return err
	}
	if reflect.DeepEqual(network.Policy, e.specification.Network.Policy) {
		return nil
	}
	if err := e.environment.SetNetworkPolicy(e.ctx, network.Policy); err != nil {
		return err
	}
	e.specification.Network.Policy = network.Policy
	return nil
}
