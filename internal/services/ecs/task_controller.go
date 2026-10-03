package ecs

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"

	runtime "stackd/compute/ecs"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// taskController routes committed task intents to one owner per live task.
// Service shutdown detaches native resources; StopTask owns their destruction.
type taskController struct {
	service         *Service
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	started, closed bool
	wakeups         chan struct{}
	active          map[TaskKey]*taskExecution
	replicas        map[ServiceKey]*replicaExecution
	work            sync.WaitGroup
}

func newTaskController(s *Service) *taskController {
	ctx, cancel := context.WithCancel(context.Background())
	return &taskController{service: s, ctx: ctx, cancel: cancel, wakeups: make(chan struct{}, 1), active: map[TaskKey]*taskExecution{}, replicas: map[ServiceKey]*replicaExecution{}}
}
func (s *Service) Start() error { return s.tasks.start() }
func (s *Service) Close() error {
	err := s.tasks.close()
	s.jobs.Close()
	return err
}

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (c *taskController) wake() {
	select {
	case c.wakeups <- struct{}{}:
	default:
	}
}
func (c *taskController) start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("ECS service is closed")
	}
	if c.started || c.service.executor == nil {
		return nil
	}
	var keys []TaskKey
	if err := c.service.repository.View(c.ctx, func(r Reader) error { var err error; keys, err = r.ActiveTaskKeys(); return err }); err != nil {
		return err
	}
	c.started = true
	c.work.Add(1)
	go c.run(keys)
	return nil
}
func (c *taskController) run(keys []TaskKey) {
	defer c.work.Done()
	for {
		if err := c.dispatchServices(); err != nil && c.ctx.Err() == nil {
			slog.Error("ECS service recovery scan failed", "error", err)
		}
		c.mu.Lock()
		for _, key := range keys {
			if _, exists := c.active[key]; exists {
				continue
			}
			e := &taskExecution{service: c.service, key: key, ctx: c.ctx}
			c.active[key] = e
			c.work.Add(1)
			go func() {
				defer c.work.Done()
				e.run()
				c.mu.Lock()
				delete(c.active, e.key)
				c.mu.Unlock()
				c.wake()
			}()
		}
		c.mu.Unlock()
		select {
		case <-c.ctx.Done():
			return
		case <-c.wakeups:
		}
		err := c.service.repository.View(c.ctx, func(r Reader) error { var err error; keys, err = r.ActiveTaskKeys(); return err })
		if err != nil {
			if c.ctx.Err() == nil {
				slog.Error("ECS task recovery scan failed", "error", err)
			}
			return
		}
	}
}
func (c *taskController) close() error {
	c.mu.Lock()
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	c.work.Wait()
	return nil
}

func taskOwnerContext(ctx context.Context, record TaskRecord) context.Context {
	key := record.Key
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ParentEventID: record.AcceptedEventID, InvokedBy: "ecs.amazonaws.com", SourceIP: "ecs.amazonaws.com", UserAgent: "ecs.amazonaws.com"})
}

func (e *taskExecution) attachedEnvironment() (runtime.Environment, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.environment == nil {
		return nil, errors.New("ECS runtime is not attached")
	}
	return e.environment, nil
}

func (e *taskExecution) Inspect(ctx context.Context) ([]runtime.ContainerStatus, error) {
	environment, err := e.attachedEnvironment()
	if err != nil {
		return nil, err
	}
	return environment.Inspect(ctx)
}

func (e *taskExecution) Stats(ctx context.Context, name string) (json.RawMessage, error) {
	environment, err := e.attachedEnvironment()
	if err != nil {
		return nil, err
	}
	return environment.Stats(ctx, name)
}

func (c *taskController) usage(ctx context.Context, key TaskKey, name string) (runtime.ContainerUsage, error) {
	c.mu.Lock()
	execution := c.active[key]
	c.mu.Unlock()
	if execution == nil {
		return runtime.ContainerUsage{}, errors.New("ECS task execution is not attached")
	}
	environment, err := execution.attachedEnvironment()
	if err != nil {
		return runtime.ContainerUsage{}, err
	}
	return environment.Usage(ctx, name)
}
