package cloudformation

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// finalizeDefinition refreshes late owner-derived attributes after dependent
// resources have stabilized, without holding a CloudFormation transaction across
// service calls. The operation revision fences the refreshed projection.
func (s *Service) finalizeDefinition(ctx, commandCtx context.Context, stack StackRecord, op OperationRecord, beforeCleanup bool, cause error) error {
	rollback := op.Phase == "ROLLBACK"
	definition := op
	if rollback {
		definition.Template, definition.Parameters, definition.ResolvedParameters = stack.Template, stack.Parameters, stack.ResolvedParameters
		definition.Tags, definition.Capabilities = stack.Tags, stack.Capabilities
	}
	var resources []ResourceRecord
	if cause == nil {
		cause = s.repository.View(ctx, func(reader Reader) error {
			var err error
			resources, err = reader.Resources(stack.ID)
			return err
		})
	}
	var template *Template
	if cause == nil {
		template, cause = ParseTemplate(definition.Template)
	}
	refreshed := make([]ResourceRecord, 0, len(resources))
	if cause == nil {
		for _, resource := range resources {
			if !resource.Current || resource.PhysicalID == "" {
				continue
			}
			if _, live := template.Resources[resource.LogicalID]; !live {
				continue
			}
			handler := s.handlers[resource.Type]
			if _, readable := handler.(ResourceResultReader); !readable {
				continue
			}
			previous := ResourceResult{PhysicalID: resource.PhysicalID, Ref: resource.Ref, Attributes: resource.Attributes}
			result, err := stabilizedResourceResult(commandCtx, handler, resourceRequest(stack, definition, resource, nil), previous)
			if err != nil {
				cause = fmt.Errorf("refresh %s: %w", resource.LogicalID, err)
				break
			}
			resource.Ref, resource.Attributes = result.Ref, result.Attributes
			refreshed = append(refreshed, resource)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(commandCtx, func(tx Transaction) error {
		current, err := tx.Operation(op.ID)
		if err != nil {
			return err
		}
		if current.Phase != op.Phase || current.Revision != op.Revision || current.Cursor != op.Cursor {
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
		if op.Cancel && op.Phase == "APPLY" {
			return s.startRollback(tx, &stack, &op, "Update cancelled by user")
		}
		var admission *ResourcePendingError
		if errors.As(cause, &admission) {
			op.Revision++
			op.Due = s.clock.Now().Add(time.Second)
			return tx.PutOperation(op)
		}
		if cause != nil {
			if rollback {
				return s.failRollback(tx, &stack, &op, cause)
			}
			return s.failOperation(tx, &stack, &op, cause)
		}
		for _, resource := range refreshed {
			if err := tx.PutResource(resource); err != nil {
				return err
			}
			for i := range op.Steps {
				after := &op.Steps[i].After
				if after.LogicalID == resource.LogicalID && after.Generation == resource.Generation && after.Token == resource.Token {
					after.Ref, after.Attributes = resource.Ref, resource.Attributes
				}
				restore := &op.Steps[i].Restore
				if restore.LogicalID == resource.LogicalID && restore.Generation == resource.Generation && restore.Token == resource.Token {
					restore.Ref, restore.Attributes = resource.Ref, resource.Attributes
				}
			}
		}
		if rollback {
			if err := s.commitDefinition(tx, &stack, definition); err != nil {
				return s.failRollback(tx, &stack, &op, err)
			}
			return s.finishRollback(tx, &stack, &op)
		}
		if !beforeCleanup {
			return s.complete(tx, &stack, &op)
		}
		previous, err := ParseTemplate(stack.Template)
		if err != nil {
			return s.failOperation(tx, &stack, &op, err)
		}
		evaluation, err := s.evaluation(tx, stack, stack.Parameters, stack.ResolvedParameters)
		if err != nil {
			return err
		}
		previousOrder, err := previous.Order(evaluation)
		if err != nil {
			return s.failOperation(tx, &stack, &op, err)
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
		if err := s.commitDefinition(tx, &stack, op); err != nil {
			return s.failOperation(tx, &stack, &op, err)
		}
		op.Phase = "CLEANUP"
		op.Revision++
		op.Due = s.clock.Now()
		if err := s.stackEvent(tx, &stack, op.Token, "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", ""); err != nil {
			return err
		}
		if err := tx.PutStack(stack); err != nil {
			return err
		}
		return tx.PutOperation(op)
	})
}
