package cloudformation

import (
	"context"
	"errors"
)

// NestedStackOwnership is trusted controller metadata, never a request field or
// a user tag. The native stack owner retains it with the admitted stack and job.
type NestedStackOwnership struct {
	ParentID, RootID, LogicalID, Incarnation string
}

type stackResourceOperationKey struct{}

// WithStackResourceOperation preserves native busy admission as a controller
// wait signal. It does not claim parent ownership or alter IAM authorization.
func WithStackResourceOperation(ctx context.Context) context.Context {
	return context.WithValue(ctx, stackResourceOperationKey{}, true)
}

func stackBusyAdmission(ctx context.Context, reason string) error {
	rejected := failure("ValidationError", reason)
	if pending, _ := ctx.Value(stackResourceOperationKey{}).(bool); pending {
		rejected.Cause = &ResourcePendingError{Reason: reason}
	}
	return rejected
}

type nestedStackOwnershipKey struct{}

type stackResourceObservationKey struct{}

// StackResourceObservation exposes the actual source job's retained operation
// identity to in-process adapters without inventing public AWS response fields.
type StackResourceObservation struct {
	OperationToken, Kind, Phase string
}

func WithStackResourceObservation(ctx context.Context, observation *StackResourceObservation) context.Context {
	return context.WithValue(ctx, stackResourceObservationKey{}, observation)
}

func observeStackResource(r Reader, stack StackRecord) error {
	observation, _ := r.Context().Value(stackResourceObservationKey{}).(*StackResourceObservation)
	if observation == nil || stack.OperationID == "" {
		return nil
	}
	op, err := r.Operation(stack.OperationID)
	if err != nil {
		return err
	}
	*observation = StackResourceObservation{OperationToken: op.Token, Kind: op.Kind, Phase: op.Phase}
	return nil
}

func WithNestedStackOwnership(ctx context.Context, owner NestedStackOwnership) context.Context {
	return context.WithValue(ctx, nestedStackOwnershipKey{}, owner)
}

func nestedStackOwner(ctx context.Context) (NestedStackOwnership, bool) {
	owner, ok := ctx.Value(nestedStackOwnershipKey{}).(NestedStackOwnership)
	return owner, ok
}

func nestedOwnerMarker(owner NestedStackOwnership) string {
	return requestHash([]string{owner.ParentID, owner.LogicalID, owner.Incarnation})
}

func checkNestedStackOwner(r Reader, stack StackRecord) error {
	owner, ok := nestedStackOwner(r.Context())
	if !ok {
		return nil
	}
	if owner.ParentID == "" || owner.LogicalID == "" || owner.Incarnation == "" || stack.ParentID != owner.ParentID || stack.NestedOwner != nestedOwnerMarker(owner) {
		return failure("ValidationError", "Stack is not owned by this CloudFormation resource incarnation")
	}
	if owner.RootID != "" && owner.RootID != stack.RootID {
		return invalid("Nested stack root ownership does not match")
	}
	return nil
}

func admitNestedStackOwner(r Reader, stack *StackRecord) error {
	owner, ok := nestedStackOwner(r.Context())
	if !ok {
		return nil
	}
	if owner.ParentID == "" || owner.LogicalID == "" || owner.Incarnation == "" {
		return invalid("Nested stack ownership requires parent, logical resource and incarnation")
	}
	if stack.TerminationProtection {
		return invalid("Termination protection cannot be set directly on a nested stack")
	}
	parent, err := r.Stack(owner.ParentID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return invalid("Nested stack parent does not exist")
		}
		return err
	}
	if parent.Scope != stack.Scope || parent.Deleted != nil {
		return invalid("Nested stack parent is outside the current scope or deleted")
	}
	root := parent.RootID
	if root == "" {
		root = parent.ID
	}
	if owner.RootID != "" && owner.RootID != root {
		return invalid("Nested stack root ownership does not match")
	}
	stack.NestedOwner = nestedOwnerMarker(owner)
	stack.ParentID = parent.ID
	stack.RootID = root
	stack.Capabilities = parent.Capabilities
	stack.RoleARN = parent.RoleARN
	return nil
}

func nestedStackConfiguration(r Reader, capabilities []string, role string) ([]string, string, error) {
	owner, nested := nestedStackOwner(r.Context())
	if !nested {
		return capabilities, role, nil
	}
	parent, err := r.Stack(owner.ParentID)
	if err != nil {
		return nil, "", err
	}
	if parent.Scope != scopeFor(r.Context()) || parent.Deleted != nil {
		return nil, "", invalid("Nested stack parent is outside the current scope or deleted")
	}
	if capabilities == nil {
		capabilities = parent.Capabilities
		if active(parent) && parent.OperationID != "" {
			op, err := r.Operation(parent.OperationID)
			if err != nil {
				return nil, "", err
			}
			if op.Phase == "APPLY" {
				capabilities = op.Capabilities
			}
		}
	}
	return capabilities, parent.RoleARN, nil
}

// Retained token replay also searches deleted stack history. A recovery retry
// must recover the exact stack incarnation, not create another same-name child.
func findCreateStack(r Reader, name, token string) (StackRecord, error) {
	owner, nested := nestedStackOwner(r.Context())
	if token != "" || nested {
		rows, err := r.Stacks(scopeFor(r.Context()))
		if err != nil {
			return StackRecord{}, err
		}
		for _, stack := range rows {
			if nested && stack.NestedOwner == nestedOwnerMarker(owner) {
				if stack.Name != name {
					return StackRecord{}, failure("TokenAlreadyExistsException", "A different stack name already exists for this resource incarnation")
				}
				return stack, nil
			}
			if token == "" || stack.Name != name {
				continue
			}
			_, err := r.Operation(operationID(stack.ID, "CREATE", token))
			if err == nil {
				return stack, nil
			}
			if !errors.Is(err, ErrNotFound) {
				return StackRecord{}, err
			}
		}
	}
	return findStack(r, name)
}
