package ecs

import (
	"context"
	"errors"
	"log/slog"
	"time"

	runtime "stackd/compute/ecs"
)

// openLogs retains successfully opened sinks across preparation retries. A stop
// may consume those sinks even when another container's log startup is denied.
func (e *taskExecution) openLogs(record TaskRecord) error {
	if e.logs == nil {
		e.logs = map[string]TaskLogSink{}
		e.logStarted = map[string]bool{}
	}
	var failures error
	for _, container := range record.Definition.ContainerDefinitions {
		name := value(container.Name)
		if container.LogConfiguration == nil || e.logs[name] != nil {
			continue
		}
		if e.service.logs == nil {
			return errors.New("ECS runtime Logs dependency is not configured")
		}
		sink, err := e.service.logs.Open(taskOwnerContext(e.ctx, record), e.key, name, *container.LogConfiguration, e.credentialSource(taskExecutionRoleARN(record)))
		if err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		e.logs[name] = sink
	}
	return failures
}

func (e *taskExecution) startLogs(record TaskRecord, processes runtime.TaskProcesses, name string) {
	sink := e.logs[name]
	if sink == nil || e.logStarted[name] {
		return
	}
	e.logStarted[name] = true
	if e.logContext == nil {
		e.logContext, e.logCancel = context.WithCancel(e.ctx)
	}
	ctx := taskOwnerContext(e.logContext, record)
	e.logWork.Go(func() {
		cursor := record.LogCursors[name]
		lastCommit := time.Now()
		persist := func() error {
			if cursor.IsZero() {
				return nil
			}
			return e.service.repository.Update(ctx, func(tx Transaction) error {
				current, err := tx.Task(e.key)
				if err != nil {
					return err
				}
				current.LogCursors[name] = cursor
				return tx.PutTask(current)
			})
		}
		for ctx.Err() == nil {
			// Native timestamps are inclusive resume positions, not unique event
			// identities. Reattachment can replay the last entry; it must not
			// discard distinct Docker fragments sharing that timestamp.
			err := processes.Logs(ctx, name, cursor, func(entry runtime.LogRecord) error {
				// TODO: Comeback bind blocking awslogs to the native stdout driver;
				// following Docker's retained log file cannot backpressure customer IO.
				if err := sink.Write(ctx, entry); err != nil {
					return err
				}
				cursor = entry.Time
				if time.Since(lastCommit) < time.Second {
					return nil
				}
				if err := persist(); err != nil {
					return err
				}
				lastCommit = time.Now()
				return nil
			})
			if ctx.Err() != nil {
				return
			}
			if commitErr := persist(); commitErr != nil {
				slog.Warn("ECS native log cursor commit failed", "task", e.key.ARN(), "container", name, "error", commitErr)
			}
			if err == nil {
				return
			}
			slog.Warn("ECS native log stream interrupted", "task", e.key.ARN(), "container", name, "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	})
}
