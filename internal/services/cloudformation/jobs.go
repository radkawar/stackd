package cloudformation

import (
	"cmp"
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
	var execute bool
	err := s.repository.Update(ctx, func(tx Transaction) error {
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
			for op.Cursor >= 0 && op.Cursor < len(op.Steps) && (op.Steps[op.Cursor].State == "PENDING" || op.Steps[op.Cursor].State == "SKIPPED" || op.Steps[op.Cursor].State == "ROLLED_BACK") {
				op.Cursor--
			}
			if op.Cursor < 0 || len(op.Steps) == 0 {
				return s.finishRollback(tx, &stack, &op)
			}
			step = op.Steps[op.Cursor]
			if step.State == "RUNNING" && step.After.PhysicalID == "" && (step.Action == "CREATE" || step.Action == "REPLACE") {
				step.State = "RECOVERING"
				op.Steps[op.Cursor] = step
			}
			execute = true
			return tx.PutOperation(op)
		}
		if op.Cursor >= len(op.Steps) {
			return s.complete(tx, &stack, &op)
		}
		step = op.Steps[op.Cursor]
		if step.State == "PENDING" {
			if step.Action == "UPSERT" {
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
					return s.failOperation(tx, &stack, &op, e)
				}
				h := s.handlers[step.After.Type]
				if h == nil {
					return s.failOperation(tx, &stack, &op, invalid("Resource handler is unavailable: "+step.After.Type))
				}
				if e = h.Validate(props); e != nil {
					return s.failOperation(tx, &stack, &op, e)
				}
				step.After.Properties = props
				step.After.EventProperties = t.eventProperties(step.LogicalID, evaluation, props)
				step.Action = "CREATE"
				if step.Before.PhysicalID != "" {
					replace := step.Before.Type != step.After.Type
					if !replace {
						replace, e = RequiresReplacement(h, stack.Scope, step.Before.Properties, props)
						if e != nil {
							return s.failOperation(tx, &stack, &op, e)
						}
					}
					if replace {
						step.Action = "REPLACE"
					} else {
						after := step.Before
						after.Properties = props
						after.EventProperties = step.After.EventProperties
						after.DeletionPolicy = step.After.DeletionPolicy
						after.UpdateReplacePolicy = step.After.UpdateReplacePolicy
						step.After = after
						step.Action = "UPDATE"
						if reflect.DeepEqual(props, step.Before.Properties) && maps.Equal(op.Tags, stack.Tags) {
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
				}
			}
			if step.Action == "DELETE" || step.Action == "RETIRE" {
				// Commit the new definition before entering irreversible cleanup.
				if op.Kind != "DELETE" && op.Phase == "APPLY" {
					previous, e := ParseTemplate(stack.Template)
					if e != nil {
						return s.failOperation(tx, &stack, &op, e)
					}
					evaluation, e := s.evaluation(tx, stack, stack.Parameters, stack.ResolvedParameters)
					if e != nil {
						return e
					}
					previousOrder, e := previous.Order(evaluation)
					if e != nil {
						return s.failOperation(tx, &stack, &op, e)
					}
					order := make(map[string]int, len(previousOrder))
					for i, id := range previousOrder {
						order[id] = i
					}
					slices.SortStableFunc(op.Steps[op.Cursor:], func(a, b StepRecord) int {
						return cmp.Compare(order[b.LogicalID], order[a.LogicalID])
					})
					for i := op.Cursor; i < len(op.Steps); i++ {
						op.Steps[i].Position = i
					}
					step = op.Steps[op.Cursor]
					if e := s.commitDefinition(tx, &stack, op); e != nil {
						return s.failOperation(tx, &stack, &op, e)
					}
					op.Phase = "CLEANUP"
					if e = s.stackEvent(tx, &stack, op.Token, "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", ""); e != nil {
						return e
					}
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
		execute = true
		return nil
	})
	if err != nil || !execute {
		return err
	}
	caller := op.Caller
	caller.InvokedBy = "cloudformation.amazonaws.com"
	caller.SourceIP, caller.UserAgent = caller.InvokedBy, caller.InvokedBy
	caller.TransportKnown, caller.SecureTransport = true, true
	commandCtx := awsctx.WithMetadata(ctx, caller)
	commandCtx = awsctx.WithViaService(commandCtx, caller.InvokedBy)
	if op.RoleARN != "" {
		if s.roles == nil {
			err = invalid("CloudFormation execution-role authority is unavailable")
		} else {
			commandCtx, err = s.roles.Context(commandCtx, stack.ID, op.RoleARN)
		}
	}
	var result ResourceResult
	var pending bool
	if err == nil {
		if op.Phase == "ROLLBACK" {
			result, pending, err = s.undoStep(commandCtx, stack, op, step)
		} else {
			result, pending, err = s.executeStep(commandCtx, stack, op, step)
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
		if current.Phase == "DONE" || current.Revision != op.Revision || current.Cursor != op.Cursor {
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
			step.State = "STABILIZING"
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
			if e = tx.PutResource(before); e != nil {
				return e
			}
			op.Steps = append(op.Steps, StepRecord{Position: len(op.Steps), LogicalID: before.LogicalID, Action: "RETIRE", State: "PENDING", Before: before})
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
	return ResourceRequest{StackID: stack.ID, StackName: stack.Name, LogicalID: v.LogicalID, Type: v.Type, PhysicalID: v.PhysicalID, Token: v.Token, Scope: stack.Scope, Properties: v.Properties, Previous: previous, Tags: op.Tags}
}
func (s *Service) executeStep(ctx context.Context, stack StackRecord, op OperationRecord, step StepRecord) (ResourceResult, bool, error) {
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
	if step.State == "STABILIZING" {
		result := ResourceResult{PhysicalID: v.PhysicalID, Ref: v.Ref, Attributes: v.Attributes}
		if deleting {
			if waiter, ok := h.(ResourceDeletionStabilizer); ok {
				ready, e := waiter.StabilizeDeletion(ctx, request)
				return ResourceResult{}, !ready, e
			}
		} else if waiter, ok := h.(ResourceStabilizer); ok {
			ready, e := waiter.Stabilize(ctx, request)
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
func (s *Service) undoStep(ctx context.Context, stack StackRecord, op OperationRecord, step StepRecord) (ResourceResult, bool, error) {
	before, after := step.Before, step.After
	result := ResourceResult{PhysicalID: before.PhysicalID, Ref: before.Ref, Attributes: before.Attributes}
	if step.Action == "CREATE" || step.Action == "REPLACE" {
		if step.State == "RECOVERING" {
			h := s.handlers[after.Type]
			if h == nil {
				return ResourceResult{}, false, invalid("Resource handler unavailable")
			}
			recovered, err := h.Create(ctx, resourceRequest(stack, op, after, nil))
			if err == nil && recovered.PhysicalID == "" {
				err = invalid("Resource recovery did not return a physical identity")
			}
			return recovered, false, err
		}
		if after.PhysicalID == "" || after.DeletionPolicy == "Retain" {
			return result, false, nil
		}
		h := s.handlers[after.Type]
		if h == nil {
			return ResourceResult{}, false, invalid("Resource handler unavailable")
		}
		request := resourceRequest(stack, op, after, nil)
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
			return result, !ready, err
		}
		result, err := h.Update(ctx, request)
		return result, asynchronous && err == nil, err
	}
	return result, false, nil
}
func (s *Service) recordUndo(tx Transaction, stack *StackRecord, op *OperationRecord, step StepRecord, result ResourceResult, pending bool, cause error) error {
	if step.State == "RECOVERING" && result.PhysicalID != "" {
		step.After.PhysicalID, step.After.Ref, step.After.Attributes = result.PhysicalID, result.Ref, result.Attributes
		step.State = "RECOVERED"
		if cause != nil {
			step.Error = cause.Error()
		}
		op.Steps[op.Cursor] = step
		op.Revision++
		op.Due = s.clock.Now()
		return tx.PutOperation(*op)
	}
	if cause != nil {
		op.Phase = "DONE"
		op.Reason = cause.Error()
		status := "UPDATE_ROLLBACK_FAILED"
		if op.Kind == "CREATE" {
			status = "ROLLBACK_FAILED"
		}
		if e := s.stackEvent(tx, stack, op.Token, status, cause.Error()); e != nil {
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
	if pending {
		step.State = "UNDO_STABILIZING"
		if result.PhysicalID != "" {
			step.Before.PhysicalID, step.Before.Ref, step.Before.Attributes = result.PhysicalID, result.Ref, result.Attributes
		}
		op.Steps[op.Cursor] = step
		op.Revision++
		op.Due = s.clock.Now().Add(time.Second)
		return tx.PutOperation(*op)
	}
	if step.After.LogicalID != "" && (step.Action == "CREATE" || step.Action == "REPLACE") {
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
	if step.Before.PhysicalID != "" {
		v := step.Before
		v.Current = true
		if result.PhysicalID != "" {
			v.PhysicalID = result.PhysicalID
			v.Ref = result.Ref
			v.Attributes = result.Attributes
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
