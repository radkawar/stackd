package cloudformation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type deploymentJobs struct{ s *Service }

func (j deploymentJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var op OperationRecord
	var found bool
	e := j.s.repository.View(ctx, func(r Reader) error { var e error; op, found, e = r.NextOperation(); return e })
	return scheduler.Job{Key: op.ID, Version: op.Revision, Due: op.Due}, found, e
}
func (j deploymentJobs) Run(ctx context.Context, job scheduler.Job) error {
	return j.s.runDeployment(ctx, job)
}

func (s *Service) stackEvent(tx Transaction, stack *StackRecord, token, status, reason string) error {
	stack.EventSequence++
	stack.Status = status
	stack.StatusReason = reason
	return tx.PutEvent(EventRecord{StackID: stack.ID, ID: uuid.NewString(), LogicalID: stack.Name, Type: "AWS::CloudFormation::Stack", PhysicalID: stack.ID, Status: status, Reason: reason, Token: token, Sequence: stack.EventSequence, Timestamp: s.clock.Now()})
}
func (s *Service) resourceEvent(tx Transaction, stack *StackRecord, op OperationRecord, v ResourceRecord, status, reason string) error {
	stack.EventSequence++
	v.Status = status
	v.StatusReason = reason
	v.Updated = s.clock.Now()
	if e := tx.PutResource(v); e != nil {
		return e
	}
	properties := v.EventProperties
	if op.Kind == "UPDATE" && strings.HasPrefix(status, "DELETE_") {
		// Native update cleanup and rollback deletion events omit properties.
		// Keep the incarnation's projection for subsequent retained-state use.
		properties = nil
	}
	return tx.PutEvent(EventRecord{StackID: stack.ID, ID: uuid.NewString(), LogicalID: v.LogicalID, Type: v.Type, PhysicalID: v.PhysicalID, Status: status, Reason: reason, Token: op.Token, Sequence: stack.EventSequence, Timestamp: v.Updated, Properties: properties})
}
func (s *Service) runDeployment(ctx context.Context, job scheduler.Job) error {
	var op OperationRecord
	var stack StackRecord
	var step StepRecord
	var execute, finalize, beforeCleanup, planning bool
	// Resolve the retained caller's current execution authority before opening a
	// state transaction. Intrinsic owner reads and native effects use the same
	// authority; role assumption must not run inside the shared transaction.
	err := s.repository.View(ctx, func(reader Reader) error {
		var err error
		op, err = reader.Operation(job.Key)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil || op.Phase == "DONE" || op.Revision != job.Version {
		return err
	}
	caller := op.Caller
	caller.InvokedBy = "cloudformation.amazonaws.com"
	caller.SourceIP, caller.UserAgent = caller.InvokedBy, caller.InvokedBy
	caller.TransportKnown, caller.SecureTransport = true, true
	commandCtx := awsctx.WithMetadata(ctx, caller)
	commandCtx = awsctx.WithViaService(commandCtx, caller.InvokedBy)
	var authorityErr error
	if op.RoleARN != "" {
		if s.roles == nil {
			authorityErr = invalid("CloudFormation execution-role authority is unavailable")
		} else {
			var authorized context.Context
			authorized, authorityErr = s.roles.Context(commandCtx, op.StackID, op.RoleARN)
			if authorityErr == nil {
				commandCtx = authorized
			}
		}
	}
	err = s.repository.Update(commandCtx, func(tx Transaction) error {
		var e error
		op, e = tx.Operation(job.Key)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if op.Phase == "DONE" || op.Revision != job.Version {
			return nil
		}
		stack, e = tx.Stack(op.StackID)
		if e != nil {
			return e
		}
		if stack.OperationID != op.ID {
			return nil
		}
		if op.Kind == "DELETE" && op.Cursor == 0 {
			if e = s.checkExports(tx, stack, nil); e != nil {
				events, readErr := tx.Events(stack.ID)
				if readErr != nil {
					return readErr
				}
				for _, event := range events {
					if event.Type != "AWS::CloudFormation::Stack" || active(StackRecord{Status: event.Status}) {
						continue
					}
					op.Phase = "DONE"
					op.Reason = "Delete canceled. " + e.Error()
					if e = s.stackEvent(tx, &stack, op.Token, event.Status, op.Reason); e != nil {
						return e
					}
					if e = tx.PutStack(stack); e != nil {
						return e
					}
					return tx.PutOperation(op)
				}
				return fmt.Errorf("delete cancellation has no retained prior stack status")
			}
		}
		if op.Cancel && op.Phase == "APPLY" {
			if e = s.startRollback(tx, &stack, &op, "Update cancelled by user"); e != nil {
				return e
			}
		}
		if op.Phase == "ROLLBACK" {
			for op.Cursor >= 0 && op.Cursor < len(op.Steps) && (op.Steps[op.Cursor].State == "PENDING" || op.Steps[op.Cursor].State == "PLANNING" || op.Steps[op.Cursor].State == "SKIPPED" || op.Steps[op.Cursor].State == "ROLLED_BACK") {
				op.Cursor--
			}
			if op.Cursor < 0 || len(op.Steps) == 0 {
				if op.Kind == "CREATE" {
					return s.finishRollback(tx, &stack, &op)
				}
				execute, finalize = true, true
				// The output refresh is revision/cursor fenced. Retain the
				// skipped rollback cursor before running that external phase.
				return tx.PutOperation(op)
			}
			step = op.Steps[op.Cursor]
			if step.State == "RUNNING" && !step.AdmissionPending && step.After.PhysicalID == "" && (step.Action == "CREATE" || step.Action == "REPLACE") {
				step.State = "RECOVERING"
			}
			if step.BeforeDeleted && step.Restore.Token == "" {
				step.Restore = step.Before
				step.Restore.Generation = max(step.Before.Generation, step.After.Generation) + 1
				step.Restore.Token = uuid.NewString()
				step.Restore.PhysicalID, step.Restore.Ref, step.Restore.Attributes = "", "", nil
				step.Restore.Current = false
			}
			op.Steps[op.Cursor] = step
			execute = true
			return tx.PutOperation(op)
		}
		if op.Cursor >= len(op.Steps) {
			if op.Kind != "DELETE" && op.Phase != "CLEANUP" {
				execute, finalize = true, true
				return nil
			}
			return s.complete(tx, &stack, &op)
		}
		step = op.Steps[op.Cursor]
		if step.State == "PLANNING" {
			execute, planning = true, true
			return nil
		}
		if step.State == "PENDING" {
			if step.Action == "UPSERT" {
				if authorityErr != nil {
					return s.failResourceAdmission(tx, &stack, &op, step, authorityErr)
				}
				t, e := ParseTemplate(op.Template)
				if e != nil {
					return s.failOperation(tx, &stack, &op, e)
				}
				evaluation, e := s.evaluation(tx, stack, op.Parameters, op.ResolvedParameters)
				if e != nil {
					return e
				}
				props, e := t.ResolveResource(step.LogicalID, evaluation)
				if e != nil {
					return s.failResourceAdmission(tx, &stack, &op, step, e)
				}
				step.After.Properties = props
				step.After.EventProperties = t.eventProperties(step.LogicalID, evaluation, props)
				h := s.handlers[step.After.Type]
				if h == nil {
					return s.failResourceAdmission(tx, &stack, &op, step, invalid("Resource handler is unavailable: "+step.After.Type))
				}
				updateValidator, validatesUpdate := h.(ResourceUpdateValidator)
				validatesUpdate = validatesUpdate && step.Before.PhysicalID != "" && step.Before.Type == step.After.Type
				if validatesUpdate {
					e = updateValidator.ValidateUpdate(step.Before.Properties, props)
				} else {
					e = h.Validate(props)
				}
				if e != nil {
					return s.failResourceAdmission(tx, &stack, &op, step, e)
				}
				replace := step.Before.PhysicalID != "" && step.Before.Type != step.After.Type
				if step.Before.PhysicalID != "" && !replace {
					if _, contextual := h.(ResourceContextualReplacementPlanner); contextual {
						// Resolve customer state first, then retain planning intent.
						// Owner observations run with fresh authority after commit.
						step.State = "PLANNING"
						op.Steps[op.Cursor] = step
						op.Revision++
						op.Due = s.clock.Now()
						execute, planning = true, true
						return tx.PutOperation(op)
					}
					replace, e = RequiresReplacement(h, stack.Scope, step.Before.Properties, props)
					if e != nil {
						return s.failResourceAdmission(tx, &stack, &op, step, e)
					}
				}
				if e = resolveStepAction(&step, replace); e != nil {
					return s.failResourceAdmission(tx, &stack, &op, step, e)
				}
				if step.Action == "REPLACE" && validatesUpdate {
					if e = h.Validate(props); e != nil {
						return s.failResourceAdmission(tx, &stack, &op, step, e)
					}
				}
				if step.Action == "UPDATE" && reflect.DeepEqual(props, step.Before.Properties) && maps.Equal(op.Tags, stack.Tags) {
					step.State = "SKIPPED"
					op.Steps[op.Cursor] = step
					op.Cursor++
					op.Revision++
					if e = tx.PutResource(step.After); e != nil {
						return e
					}
					return tx.PutOperation(op)
				}
			}
			if step.Action == "DELETE" || step.Action == "RETIRE" {
				// Refresh owner-derived attributes before committing outputs and
				// entering irreversible cleanup. Reads run outside this transaction.
				if op.Kind != "DELETE" && op.Phase == "APPLY" {
					execute, finalize, beforeCleanup = true, true, true
					return nil
				}
				policy := step.Before.DeletionPolicy
				if step.Action == "RETIRE" {
					policy = step.Before.UpdateReplacePolicy
				}
				if policy == "Retain" || policy == "RetainExceptOnCreate" {
					step.State = "SKIPPED"
					before := step.Before
					before.Current = op.Kind == "DELETE" && step.Before.Current
					if e = s.resourceEvent(tx, &stack, op, before, "DELETE_SKIPPED", "Resource retained by policy"); e != nil {
						return e
					}
					op.Steps[op.Cursor] = step
					op.Cursor++
					op.Revision++
					if e = tx.PutStack(stack); e != nil {
						return e
					}
					return tx.PutOperation(op)
				}
			}
			step.State = "RUNNING"
			if deleteBeforeCreate(step) {
				if _, readable := s.handlers[step.Before.Type].(ResourceReader); !readable {
					return s.failOperation(tx, &stack, &op, invalid("Delete-before-create replacement requires an authoritative reader: "+step.Before.Type))
				}
				step.BeforeDeleteStarted = true
				step.State = "BEFORE_DELETE_RUNNING"
			}
			op.Steps[op.Cursor] = step
			resource, status := step.After, "CREATE_IN_PROGRESS"
			if step.Action == "UPDATE" || step.Action == "REPLACE" {
				status = "UPDATE_IN_PROGRESS"
			}
			if step.Action == "DELETE" || step.Action == "RETIRE" {
				resource = step.Before
				status = "DELETE_IN_PROGRESS"
			}
			resource.Current = step.Before.PhysicalID == "" || step.Action == "UPDATE" || step.Action == "DELETE"
			if e = s.resourceEvent(tx, &stack, op, resource, status, ""); e != nil {
				return e
			}
			if e = tx.PutStack(stack); e != nil {
				return e
			}
			if e = tx.PutOperation(op); e != nil {
				return e
			}
		}
		if step.State == "BEFORE_DELETED" {
			// The durable create intent distinguishes cancellation before the
			// command from recovery after a possibly admitted owner creation.
			step.State = "RUNNING"
			op.Steps[op.Cursor] = step
			if e = tx.PutOperation(op); e != nil {
				return e
			}
		}
		execute = true
		return nil
	})
	if err != nil || !execute {
		return err
	}
	err = authorityErr
	if finalize {
		return s.finalizeDefinition(ctx, commandCtx, stack, op, beforeCleanup, err)
	}
	if planning {
		return s.planReplacement(ctx, commandCtx, stack, op, step, err)
	}
	var result ResourceResult
	var pending, effectStarted bool
	if err == nil {
		if op.Phase == "ROLLBACK" {
			result, pending, err = s.undoStep(commandCtx, stack, op, &step)
		} else {
			effectStarted = true
			result, pending, err = s.executeStep(commandCtx, stack, op, &step)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	} // retained RUNNING intent is replayed by replacement controller
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Operation(op.ID)
		if e != nil {
			return e
		}
		if current.Phase != op.Phase || current.Revision != op.Revision || current.Cursor != op.Cursor {
			return nil
		}
		stack, e = tx.Stack(op.StackID)
		if e != nil {
			return e
		}
		if stack.OperationID != op.ID {
			return nil
		}
		op.Cancel = current.Cancel
		var admission *ResourcePendingError
		if errors.As(err, &admission) {
			step.AdmissionPending = true
			op.Steps[op.Cursor] = step
			op.Revision++
			op.Due = s.clock.Now().Add(time.Second)
			return tx.PutOperation(op)
		}
		step.AdmissionPending = false
		if step.BeforeDeleted && !op.Steps[op.Cursor].BeforeDeleted {
			before := step.Before
			before.Current = false
			if e = s.resourceEvent(tx, &stack, op, before, "DELETE_COMPLETE", "Deleted before replacement"); e != nil {
				return e
			}
			if e = tx.PutStack(stack); e != nil {
				return e
			}
		}
		if op.Phase == "ROLLBACK" {
			return s.recordUndo(tx, &stack, &op, step, result, pending, err)
		}
		if result.PhysicalID != "" {
			step.After.PhysicalID = result.PhysicalID
			step.After.Ref = result.Ref
			step.After.Attributes = result.Attributes
		}
		if err != nil {
			if op.Phase == "CLEANUP" {
				step.DeleteFailures++
				step.Error = err.Error()
				v := step.Before
				if step.DeleteFailures >= 3 {
					step.State = "DETACHED"
					v.Current = false
					op.Steps[op.Cursor] = step
					op.Cursor++
				} else {
					step.State = "PENDING"
					op.Steps[op.Cursor] = step
				}
				if e := s.resourceEvent(tx, &stack, op, v, "DELETE_FAILED", step.Error); e != nil {
					return e
				}
				op.Revision++
				op.Due = s.clock.Now().Add(time.Second)
				if e := tx.PutStack(stack); e != nil {
					return e
				}
				return tx.PutOperation(op)
			}
			step.State = "FAILED"
			if effectStarted && step.After.PhysicalID == "" && (step.Action == "CREATE" || (step.Action == "REPLACE" && (!deleteBeforeCreate(step) || step.BeforeDeleted))) {
				// A modeled failure may occur after a multi-command adapter
				// admitted an owner resource. Retain exact-token recovery intent
				// rather than assuming the failed creation never existed.
				step.State = "FAILED_CREATE_RECOVERING"
			}
			step.Error = err.Error()
			op.Steps[op.Cursor] = step
			v := step.After
			status := "CREATE_FAILED"
			if step.Action == "UPDATE" || step.Action == "REPLACE" {
				status = "UPDATE_FAILED"
			}
			if step.Action == "DELETE" || step.Action == "RETIRE" {
				v = step.Before
				status = "DELETE_FAILED"
			}
			if e = s.resourceEvent(tx, &stack, op, v, status, err.Error()); e != nil {
				return e
			}
			return s.failOperation(tx, &stack, &op, err)
		}
		if pending {
			if step.State != "BEFORE_DELETE_STABILIZING" && step.State != "BEFORE_DELETED" {
				step.State = "STABILIZING"
			}
			op.Steps[op.Cursor] = step
			op.Revision++
			op.Due = s.clock.Now().Add(time.Second)
			if step.After.PhysicalID != "" {
				v := step.After
				v.Current = step.Action != "REPLACE"
				v.Status = "CREATE_IN_PROGRESS"
				if step.Action == "UPDATE" || step.Action == "REPLACE" {
					v.Status = "UPDATE_IN_PROGRESS"
				}
				v.Updated = s.clock.Now()
				if e = tx.PutResource(v); e != nil {
					return e
				}
			}
			return tx.PutOperation(op)
		}
		step.State = "SUCCEEDED"
		op.Steps[op.Cursor] = step
		v := step.After
		status := "CREATE_COMPLETE"
		if step.Action == "UPDATE" || step.Action == "REPLACE" {
			status = "UPDATE_COMPLETE"
		}
		if step.Action == "DELETE" || step.Action == "RETIRE" {
			v = step.Before
			v.Current = op.Kind == "DELETE" && step.Before.Current
			status = "DELETE_COMPLETE"
		} else {
			v.Current = true
		}
		if step.Action == "REPLACE" {
			before := step.Before
			before.Current = false
			if step.BeforeDeleted {
				before.Status, before.StatusReason = "DELETE_COMPLETE", "Deleted before replacement"
			}
			if e = tx.PutResource(before); e != nil {
				return e
			}
			if !step.BeforeDeleted {
				op.Steps = append(op.Steps, StepRecord{Position: len(op.Steps), LogicalID: before.LogicalID, Action: "RETIRE", State: "PENDING", Before: before})
			}
		}
		if e = s.resourceEvent(tx, &stack, op, v, status, ""); e != nil {
			return e
		}
		op.Cursor++
		op.Revision++
		op.Due = s.clock.Now()
		if e = tx.PutStack(stack); e != nil {
			return e
		}
		return tx.PutOperation(op)
	})
}
func resourceRequest(stack StackRecord, op OperationRecord, v ResourceRecord, previous Properties) ResourceRequest {
	return ResourceRequest{StackID: stack.ID, StackName: stack.Name, LogicalID: v.LogicalID, Type: v.Type, PhysicalID: v.PhysicalID, Token: v.Token, OperationToken: op.ID, Scope: stack.Scope, Properties: v.Properties, Previous: previous, Tags: op.Tags}
}

func resolveStepAction(step *StepRecord, replace bool) error {
	step.Action = "CREATE"
	if step.Before.PhysicalID == "" {
		return nil
	}
	if replace {
		step.Action = "REPLACE"
		if deleteBeforeCreate(*step) && ((step.Before.UpdateReplacePolicy != "" && step.Before.UpdateReplacePolicy != "Delete") || (step.After.UpdateReplacePolicy != "" && step.After.UpdateReplacePolicy != "Delete")) {
			return invalid("Resource " + step.LogicalID + " requires delete-before-create replacement; UpdateReplacePolicy must be Delete")
		}
		return nil
	}
	after := step.Before
	after.Properties = step.After.Properties
	after.EventProperties = step.After.EventProperties
	after.DeletionPolicy = step.After.DeletionPolicy
	after.UpdateReplacePolicy = step.After.UpdateReplacePolicy
	step.After, step.Action = after, "UPDATE"
	return nil
}

// planReplacement consumes a durable resolved planning intent. Native owner
// observations never execute inside the shared repository transaction.
func (s *Service) planReplacement(ctx, commandCtx context.Context, stack StackRecord, op OperationRecord, step StepRecord, cause error) error {
	var replace bool
	if cause == nil {
		planner, ok := s.handlers[step.After.Type].(ResourceContextualReplacementPlanner)
		if !ok {
			cause = invalid("Contextual replacement planner is unavailable: " + step.After.Type)
		} else {
			request := resourceRequest(stack, op, step.After, step.Before.Properties)
			request.PhysicalID = step.Before.PhysicalID
			request.Token = step.Before.Token
			replace, cause = planner.ReplacementForResource(commandCtx, request)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Operation(op.ID)
		if err != nil {
			return err
		}
		if current.Phase != op.Phase || current.Revision != op.Revision || current.Cursor != op.Cursor || current.Steps[op.Cursor].State != "PLANNING" {
			return nil
		}
		stack, err = tx.Stack(op.StackID)
		if err != nil {
			return err
		}
		if stack.OperationID != op.ID {
			return nil
		}
		op.Cancel = current.Cancel
		if op.Cancel {
			return s.startRollback(tx, &stack, &op, "Update cancelled by user")
		}
		var admission *ResourcePendingError
		if errors.As(cause, &admission) {
			op.Revision++
			op.Due = s.clock.Now().Add(time.Second)
			return tx.PutOperation(op)
		}
		if cause == nil {
			cause = resolveStepAction(&step, replace)
		}
		if cause == nil && step.Action == "REPLACE" {
			if handler := s.handlers[step.After.Type]; handler != nil {
				if _, validatesUpdate := handler.(ResourceUpdateValidator); validatesUpdate {
					cause = handler.Validate(step.After.Properties)
				}
			}
		}
		if cause != nil {
			return s.failResourceAdmission(tx, &stack, &op, step, cause)
		}
		step.State = "PENDING"
		position := op.Cursor
		if step.Action == "UPDATE" && reflect.DeepEqual(step.After.Properties, step.Before.Properties) && maps.Equal(op.Tags, stack.Tags) {
			step.State = "SKIPPED"
			op.Cursor++
			if err = tx.PutResource(step.After); err != nil {
				return err
			}
		}
		op.Steps[position] = step
		op.Revision++
		op.Due = s.clock.Now()
		return tx.PutOperation(op)
	})
}
func (s *Service) executeStep(ctx context.Context, stack StackRecord, op OperationRecord, step *StepRecord) (ResourceResult, bool, error) {
	if deleteBeforeCreate(*step) && !step.BeforeDeleted {
		h := s.handlers[step.Before.Type]
		if h == nil {
			return ResourceResult{}, false, invalid("Resource handler is unavailable: " + step.Before.Type)
		}
		request := resourceRequest(stack, op, step.Before, nil)
		request.DeletionPolicy = "Delete"
		if step.State == "BEFORE_DELETE_STABILIZING" {
			if waiter, ok := h.(ResourceDeletionStabilizer); ok {
				ready, err := waiter.StabilizeDeletion(ctx, request)
				if err != nil || !ready {
					return ResourceResult{}, !ready, err
				}
			}
		} else {
			if err := h.Delete(ctx, request); err != nil {
				return ResourceResult{}, false, err
			}
			if _, asynchronous := h.(ResourceDeletionStabilizer); asynchronous {
				step.State = "BEFORE_DELETE_STABILIZING"
				return ResourceResult{}, true, nil
			}
		}
		step.BeforeDeleted = true
		step.State = "BEFORE_DELETED"
		return ResourceResult{}, true, nil
	}
	v := step.After
	deleting := step.Action == "DELETE" || step.Action == "RETIRE"
	if deleting {
		v = step.Before
	}
	if deleting && v.PhysicalID == "" {
		return ResourceResult{}, false, nil
	}
	h := s.handlers[v.Type]
	if h == nil {
		return ResourceResult{}, false, invalid("Resource handler is unavailable: " + v.Type)
	}
	request := resourceRequest(stack, op, v, step.Before.Properties)
	request.DeletionPolicy = v.DeletionPolicy
	if step.Action == "RETIRE" {
		request.DeletionPolicy = v.UpdateReplacePolicy
		if request.DeletionPolicy == "" {
			request.DeletionPolicy = "Delete"
		}
	}
	if step.State == "STABILIZING" {
		result := ResourceResult{PhysicalID: v.PhysicalID, Ref: v.Ref, Attributes: v.Attributes}
		if deleting {
			if waiter, ok := h.(ResourceDeletionStabilizer); ok {
				ready, e := waiter.StabilizeDeletion(ctx, request)
				return ResourceResult{}, !ready, e
			}
		} else if waiter, ok := h.(ResourceStabilizer); ok {
			ready, e := waiter.Stabilize(ctx, request)
			if e == nil && ready {
				result, e = stabilizedResourceResult(ctx, h, request, result)
			}
			return result, !ready, e
		}
		return result, false, nil
	}
	var result ResourceResult
	var err error
	switch step.Action {
	case "CREATE", "REPLACE":
		result, err = h.Create(ctx, request)
	case "UPDATE":
		result, err = h.Update(ctx, request)
	case "DELETE", "RETIRE":
		err = h.Delete(ctx, request)
	default:
		err = fmt.Errorf("invalid retained deployment action %q", step.Action)
	}
	if err == nil && (step.Action == "CREATE" || step.Action == "REPLACE") && result.PhysicalID == "" {
		err = invalid("Resource creation did not return a physical identity")
	}
	pending := false
	if err == nil {
		if deleting {
			_, pending = h.(ResourceDeletionStabilizer)
		} else {
			_, pending = h.(ResourceStabilizer)
		}
	}
	return result, pending, err
}

func stabilizedResourceResult(ctx context.Context, handler ResourceHandler, request ResourceRequest, previous ResourceResult) (ResourceResult, error) {
	reader, ok := handler.(ResourceResultReader)
	if !ok {
		return previous, nil
	}
	result, err := reader.Result(ctx, request)
	if err != nil {
		return previous, err
	}
	if result.PhysicalID != request.PhysicalID {
		return previous, fmt.Errorf("stabilized resource changed physical identity from %q to %q", request.PhysicalID, result.PhysicalID)
	}
	return result, nil
}
func (s *Service) startRollback(tx Transaction, stack *StackRecord, op *OperationRecord, reason string) error {
	op.Reason = reason
	op.Phase = "ROLLBACK"
	if op.Cursor >= len(op.Steps) {
		op.Cursor = len(op.Steps) - 1
	}
	status := "UPDATE_ROLLBACK_IN_PROGRESS"
	if op.Kind == "CREATE" {
		status = "ROLLBACK_IN_PROGRESS"
	}
	if e := s.stackEvent(tx, stack, op.Token, status, reason); e != nil {
		return e
	}
	if e := tx.PutStack(*stack); e != nil {
		return e
	}
	return tx.PutOperation(*op)
}

// failResourceAdmission records a rejected logical resource without scheduling
// recovery or undo for an owner effect that was never attempted.
func (s *Service) failResourceAdmission(tx Transaction, stack *StackRecord, op *OperationRecord, step StepRecord, cause error) error {
	step.State, step.Error = "SKIPPED", cause.Error()
	op.Steps[op.Cursor] = step
	resource := step.After
	resource.Current = false
	status := "CREATE_FAILED"
	if step.Before.PhysicalID != "" {
		status = "UPDATE_FAILED"
	}
	if err := s.resourceEvent(tx, stack, *op, resource, status, cause.Error()); err != nil {
		return err
	}
	return s.failOperation(tx, stack, op, cause)
}

func (s *Service) failOperation(tx Transaction, stack *StackRecord, op *OperationRecord, cause error) error {
	if op.Kind == "DELETE" || op.DisableRollback {
		op.Phase = "DONE"
		op.Reason = cause.Error()
		if e := s.stackEvent(tx, stack, op.Token, op.Kind+"_FAILED", cause.Error()); e != nil {
			return e
		}
		if e := s.finishChangeSet(tx, *op, false); e != nil {
			return e
		}
		if e := tx.PutStack(*stack); e != nil {
			return e
		}
		return tx.PutOperation(*op)
	}
	return s.startRollback(tx, stack, op, cause.Error())
}
func (s *Service) undoStep(ctx context.Context, stack StackRecord, op OperationRecord, step *StepRecord) (ResourceResult, bool, error) {
	before, after := step.Before, step.After
	result := ResourceResult{PhysicalID: before.PhysicalID, Ref: before.Ref, Attributes: before.Attributes}
	if step.BeforeDeleteStarted && !step.BeforeDeleted {
		h := s.handlers[before.Type]
		reader, ok := h.(ResourceReader)
		if !ok {
			return ResourceResult{}, false, invalid("Delete-before-create recovery requires an authoritative reader: " + before.Type)
		}
		request := resourceRequest(stack, op, before, nil)
		_, err := reader.Read(ctx, request)
		if modeledResourceAbsent(err) {
			step.BeforeDeleted = true
			step.State = "UNDO_REPLACEMENT"
			return ResourceResult{}, true, nil
		}
		if err != nil {
			return ResourceResult{}, false, err
		}
		if step.State == "BEFORE_DELETE_STABILIZING" {
			waiter, ok := h.(ResourceDeletionStabilizer)
			if !ok {
				return ResourceResult{}, false, invalid("Retained deletion stabilizer is unavailable")
			}
			ready, err := waiter.StabilizeDeletion(ctx, request)
			if err != nil || !ready {
				return ResourceResult{}, !ready, err
			}
			// A successful waiter must not turn a still-live old owner into a
			// fake restored row. Only a modeled absence permits a fresh Create.
			_, err = reader.Read(ctx, request)
			if !modeledResourceAbsent(err) {
				if err == nil {
					err = invalid("Deletion stabilized while the exact old resource still exists")
				}
				return ResourceResult{}, false, err
			}
			step.BeforeDeleted = true
			step.State = "UNDO_REPLACEMENT"
			return ResourceResult{}, true, nil
		}
		// An ambiguous interrupted deletion can still expose a live resource.
		// Confirm its owner is stable before keeping that original incarnation.
		if waiter, ok := h.(ResourceStabilizer); ok {
			ready, err := waiter.Stabilize(ctx, request)
			if err != nil {
				return ResourceResult{}, false, err
			}
			if !ready {
				if _, asynchronous := h.(ResourceDeletionStabilizer); asynchronous && !step.AdmissionPending {
					// A crash can lose an admitted asynchronous Delete result.
					// Replay the exact old identity before waiting for absence.
					request.DeletionPolicy = "Delete"
					if err := h.Delete(ctx, request); err != nil {
						return ResourceResult{}, false, err
					}
					step.State = "BEFORE_DELETE_STABILIZING"
				}
				return ResourceResult{}, true, nil
			}
			result, err = stabilizedResourceResult(ctx, h, request, result)
			if err != nil {
				return ResourceResult{}, false, err
			}
		}
	}
	if step.BeforeDeleted {
		return s.undoDeletedReplacement(ctx, stack, op, step)
	}
	if step.Action == "CREATE" || step.Action == "REPLACE" {
		if step.State == "RECOVERING" || step.State == "FAILED_CREATE_RECOVERING" {
			return s.recoverCreation(ctx, stack, op, step)
		}
		if after.PhysicalID == "" || after.DeletionPolicy == "Retain" {
			return result, false, nil
		}
		h := s.handlers[after.Type]
		if h == nil {
			return ResourceResult{}, false, invalid("Resource handler unavailable")
		}
		request := resourceRequest(stack, op, after, nil)
		request.DeletionPolicy = "Delete"
		waiter, asynchronous := h.(ResourceDeletionStabilizer)
		if step.State == "UNDO_STABILIZING" && asynchronous {
			ready, err := waiter.StabilizeDeletion(ctx, request)
			return result, !ready, err
		}
		err := h.Delete(ctx, request)
		return result, asynchronous && err == nil, err
	}
	if step.Action == "UPDATE" {
		op.Tags = stack.Tags
		h := s.handlers[before.Type]
		if h == nil {
			return ResourceResult{}, false, invalid("Resource handler unavailable")
		}
		request := resourceRequest(stack, op, before, after.Properties)
		waiter, asynchronous := h.(ResourceStabilizer)
		if step.State == "UNDO_STABILIZING" && asynchronous {
			ready, err := waiter.Stabilize(ctx, request)
			if err == nil && ready {
				result, err = stabilizedResourceResult(ctx, h, request, result)
			}
			return result, !ready, err
		}
		result, err := h.Update(ctx, request)
		return result, asynchronous && err == nil, err
	}
	return result, false, nil
}

func modeledResourceAbsent(err error) bool {
	var wire *awswire.Error
	if !errors.As(err, &wire) {
		return false
	}
	switch wire.Code {
	case "NotFound", "ResourceNotFound", "ResourceNotFoundException", "EntityNotFoundException", "NoSuchEntity", "NoSuchBucket":
		return true
	}
	return strings.HasSuffix(wire.Code, ".NotFound")
}

func (s *Service) recoverCreation(ctx context.Context, stack StackRecord, op OperationRecord, step *StepRecord) (ResourceResult, bool, error) {
	h := s.handlers[step.After.Type]
	if h == nil {
		return ResourceResult{}, false, invalid("Resource creation recovery handler is unavailable: " + step.After.Type)
	}
	request := resourceRequest(stack, op, step.After, nil)
	var result ResourceResult
	var err error
	if reader, authoritative := h.(ResourceCreationRecoverer); authoritative {
		result, err = reader.RecoverCreation(ctx, request)
		if result.PhysicalID == "" && modeledResourceAbsent(err) {
			step.State = "CREATE_NOT_ADMITTED"
			// A deleted-before-create owner still needs a fresh restoration.
			// Otherwise the original incarnation remains authoritative.
			before := step.Before
			return ResourceResult{PhysicalID: before.PhysicalID, Ref: before.Ref, Attributes: before.Attributes}, step.BeforeDeleted, nil
		}
	} else {
		// The same incarnation token can recover a partially admitted native
		// object. An error with no authentic result is not proof of absence.
		result, err = h.Create(ctx, request)
	}
	if result.PhysicalID == "" {
		if err == nil {
			err = invalid("Resource creation recovery did not return a physical identity")
		}
		return ResourceResult{}, false, fmt.Errorf("recover exact creation of %s: %w", step.LogicalID, err)
	}
	return result, false, err
}

// undoDeletedReplacement first removes the admitted replacement, then restores
// the old properties through a separately retained, freshly owned incarnation.
func (s *Service) undoDeletedReplacement(ctx context.Context, stack StackRecord, op OperationRecord, step *StepRecord) (ResourceResult, bool, error) {
	if step.State == "RECOVERING" || step.State == "FAILED_CREATE_RECOVERING" {
		return s.recoverCreation(ctx, stack, op, step)
	}
	if step.State == "RESTORE_RUNNING" || step.State == "RESTORE_STABILIZING" {
		if step.Restore.Token == "" {
			return ResourceResult{}, false, invalid("Rollback restoration has no retained incarnation")
		}
		h := s.handlers[step.Restore.Type]
		if h == nil {
			return ResourceResult{}, false, invalid("Resource restoration handler is unavailable")
		}
		op.Tags = stack.Tags
		request := resourceRequest(stack, op, step.Restore, nil)
		result := ResourceResult{PhysicalID: step.Restore.PhysicalID, Ref: step.Restore.Ref, Attributes: step.Restore.Attributes}
		var err error
		if step.State == "RESTORE_STABILIZING" {
			waiter, ok := h.(ResourceStabilizer)
			if !ok {
				return ResourceResult{}, false, invalid("Retained restoration stabilizer is unavailable")
			}
			ready, stabilizeErr := waiter.Stabilize(ctx, request)
			if stabilizeErr != nil || !ready {
				return result, !ready, stabilizeErr
			}
			result, err = stabilizedResourceResult(ctx, h, request, result)
		} else {
			result, err = h.Create(ctx, request)
			if err == nil && result.PhysicalID == "" {
				err = invalid("Resource restoration did not return a physical identity")
			}
		}
		if result.PhysicalID != "" {
			step.Restore.PhysicalID, step.Restore.Ref, step.Restore.Attributes = result.PhysicalID, result.Ref, result.Attributes
		}
		if err != nil {
			return result, false, err
		}
		if step.State == "RESTORE_RUNNING" {
			if _, asynchronous := h.(ResourceStabilizer); asynchronous {
				step.State = "RESTORE_STABILIZING"
				return result, true, nil
			}
		}
		step.State = "RESTORED"
		return result, false, nil
	}
	if step.After.PhysicalID != "" {
		h := s.handlers[step.After.Type]
		if h == nil {
			return ResourceResult{}, false, invalid("Replacement deletion handler is unavailable")
		}
		request := resourceRequest(stack, op, step.After, nil)
		request.DeletionPolicy = "Delete"
		waiter, asynchronous := h.(ResourceDeletionStabilizer)
		if step.State == "UNDO_STABILIZING" && asynchronous {
			ready, err := waiter.StabilizeDeletion(ctx, request)
			if err != nil || !ready {
				return ResourceResult{}, !ready, err
			}
		} else {
			if err := h.Delete(ctx, request); err != nil {
				return ResourceResult{}, false, err
			}
			if asynchronous {
				step.State = "UNDO_STABILIZING"
				return ResourceResult{}, true, nil
			}
		}
	}
	step.State = "RESTORE_RUNNING"
	return ResourceResult{}, true, nil
}
func (s *Service) recordUndo(tx Transaction, stack *StackRecord, op *OperationRecord, step StepRecord, result ResourceResult, pending bool, cause error) error {
	if (step.State == "RECOVERING" || step.State == "FAILED_CREATE_RECOVERING") && result.PhysicalID != "" {
		step.After.PhysicalID, step.After.Ref, step.After.Attributes = result.PhysicalID, result.Ref, result.Attributes
		step.State = "RECOVERED"
		if cause != nil && step.Error == "" {
			step.Error = cause.Error()
		}
		op.Steps[op.Cursor] = step
		op.Revision++
		op.Due = s.clock.Now()
		return tx.PutOperation(*op)
	}
	if cause != nil {
		op.Steps[op.Cursor] = step
		return s.failRollback(tx, stack, op, cause)
	}
	if step.State == "RESTORE_RUNNING" && op.Steps[op.Cursor].State != "RESTORE_RUNNING" && step.After.PhysicalID != "" {
		v := step.After
		v.Current = false
		if err := s.resourceEvent(tx, stack, *op, v, "DELETE_COMPLETE", "Deleted replacement before rollback restoration"); err != nil {
			return err
		}
	}
	if pending {
		if !step.BeforeDeleteStarted {
			step.State = "UNDO_STABILIZING"
			if result.PhysicalID != "" {
				step.Before.PhysicalID, step.Before.Ref, step.Before.Attributes = result.PhysicalID, result.Ref, result.Attributes
			}
		}
		op.Steps[op.Cursor] = step
		op.Revision++
		op.Due = s.clock.Now().Add(time.Second)
		if err := tx.PutStack(*stack); err != nil {
			return err
		}
		return tx.PutOperation(*op)
	}
	if !step.BeforeDeleted && step.After.PhysicalID != "" && (step.Action == "CREATE" || step.Action == "REPLACE") {
		v := step.After
		v.Current = false
		status := "DELETE_COMPLETE"
		if v.DeletionPolicy == "Retain" {
			status = "DELETE_SKIPPED"
		}
		if e := s.resourceEvent(tx, stack, *op, v, status, ""); e != nil {
			return e
		}
	}
	if step.After.PhysicalID == "" && (step.Action == "CREATE" || step.Action == "REPLACE") {
		// Preserve the failed/unadmitted logical history, but do not leave its
		// initial blank in-progress row selected as a current incarnation or
		// fabricate a successful native deletion for a resource that never existed.
		v := step.After
		v.Current, v.Status, v.StatusReason = false, "CREATE_FAILED", step.Error
		if step.Action == "REPLACE" {
			v.Status = "UPDATE_FAILED"
		}
		if v.StatusReason == "" {
			v.StatusReason = "Resource creation cancelled before admission"
		}
		v.Updated = s.clock.Now()
		if err := tx.PutResource(v); err != nil {
			return err
		}
	}
	v := step.Before
	if step.BeforeDeleted {
		v = step.Restore
	}
	if v.PhysicalID != "" {
		v.Current = true
		if result.PhysicalID != "" {
			v.PhysicalID, v.Ref, v.Attributes = result.PhysicalID, result.Ref, result.Attributes
		}
		if e := s.resourceEvent(tx, stack, *op, v, "UPDATE_COMPLETE", ""); e != nil {
			return e
		}
	}
	step.State = "ROLLED_BACK"
	op.Steps[op.Cursor] = step
	op.Cursor--
	op.Revision++
	op.Due = s.clock.Now()
	if e := tx.PutStack(*stack); e != nil {
		return e
	}
	return tx.PutOperation(*op)
}

func (s *Service) failRollback(tx Transaction, stack *StackRecord, op *OperationRecord, cause error) error {
	op.Phase, op.Reason = "DONE", cause.Error()
	status := "UPDATE_ROLLBACK_FAILED"
	if op.Kind == "CREATE" {
		status = "ROLLBACK_FAILED"
	}
	if err := s.stackEvent(tx, stack, op.Token, status, cause.Error()); err != nil {
		return err
	}
	if err := s.finishChangeSet(tx, *op, false); err != nil {
		return err
	}
	if err := tx.PutStack(*stack); err != nil {
		return err
	}
	return tx.PutOperation(*op)
}
func (s *Service) finishRollback(tx Transaction, stack *StackRecord, op *OperationRecord) error {
	op.Phase = "DONE"
	status := "UPDATE_ROLLBACK_COMPLETE"
	if op.Kind == "CREATE" {
		status = "ROLLBACK_COMPLETE"
		stack.Template = op.Template
		stack.Parameters = op.Parameters
		stack.ResolvedParameters = op.ResolvedParameters
		stack.Capabilities = op.Capabilities
	} else {
		if e := s.stackEvent(tx, stack, op.Token, "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS", ""); e != nil {
			return e
		}
	}
	if e := s.stackEvent(tx, stack, op.Token, status, op.Reason); e != nil {
		return e
	}
	if e := s.finishChangeSet(tx, *op, false); e != nil {
		return e
	}
	if e := tx.PutStack(*stack); e != nil {
		return e
	}
	return tx.PutOperation(*op)
}
func (s *Service) commitDefinition(tx Transaction, stack *StackRecord, op OperationRecord) error {
	t, e := ParseTemplate(op.Template)
	if e != nil {
		return e
	}
	evaluation, e := s.evaluation(tx, *stack, op.Parameters, op.ResolvedParameters)
	if e != nil {
		return e
	}
	out, imports, e := t.ResolveOutputs(evaluation)
	if e != nil {
		return e
	}
	if e = s.checkExports(tx, *stack, out); e != nil {
		return e
	}
	stack.Outputs, stack.Imports = out, imports
	stack.Template, stack.Parameters, stack.Tags, stack.Capabilities = op.Template, op.Parameters, op.Tags, op.Capabilities
	stack.ResolvedParameters = op.ResolvedParameters
	stack.Description = t.Description
	exports, e := tx.Exports(stack.Scope)
	if e != nil {
		return e
	}
	for _, v := range exports {
		if v.StackID == stack.ID {
			if e := tx.DeleteExport(v.Scope, v.Name); e != nil {
				return e
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(out)) {
		v := out[name]
		if v.ExportName != "" {
			if e := tx.PutExport(ExportRecord{Scope: stack.Scope, Name: v.ExportName, Value: v.Value, StackID: stack.ID}); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Service) complete(tx Transaction, stack *StackRecord, op *OperationRecord) error {
	if op.Kind != "DELETE" {
		if op.Phase != "CLEANUP" {
			if e := s.commitDefinition(tx, stack, *op); e != nil {
				return s.failOperation(tx, stack, op, e)
			}
		}
	} else {
		stack.Imports = nil
		stack.Deleted = new(s.clock.Now())
		exports, e := tx.Exports(stack.Scope)
		if e != nil {
			return e
		}
		for _, v := range exports {
			if v.StackID == stack.ID {
				if e := tx.DeleteExport(v.Scope, v.Name); e != nil {
					return e
				}
			}
		}
	}
	for _, step := range op.Steps {
		if step.State == "DETACHED" {
			op.Reason = "Update successful. One or more resources could not be deleted."
			break
		}
	}
	op.Phase = "DONE"
	if e := s.stackEvent(tx, stack, op.Token, op.Kind+"_COMPLETE", op.Reason); e != nil {
		return e
	}
	if e := s.finishChangeSet(tx, *op, true); e != nil {
		return e
	}
	if e := tx.PutStack(*stack); e != nil {
		return e
	}
	return tx.PutOperation(*op)
}
func (s *Service) finishChangeSet(tx Transaction, op OperationRecord, success bool) error {
	if op.ChangeSetID == "" {
		return nil
	}
	set, e := tx.ChangeSet(op.ChangeSetID)
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	set.ExecutionStatus = "EXECUTE_COMPLETE"
	if !success {
		set.ExecutionStatus = "EXECUTE_FAILED"
	}
	return tx.PutChangeSet(set)
}
