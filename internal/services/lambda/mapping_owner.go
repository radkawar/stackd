package lambda

import (
	"context"
	"errors"

	"stackd/internal/awswire"
)

// MappingOwner identifies the private admission of a mapping independently of
// customer tags, its source, and the function's lifetime.
type MappingOwner struct{ StackID, LogicalID, Token string }

type mappingOwnerContextKey struct{}
type mappingOwnerRequest struct {
	Owner MappingOwner
	UUID  string
}

// WithMappingOwner constrains trusted stack commands. UUID, when known, fences
// create recovery to that exact native identity; it does not adopt a native row.
func WithMappingOwner(ctx context.Context, owner MappingOwner, uuid string) context.Context {
	return context.WithValue(ctx, mappingOwnerContextKey{}, mappingOwnerRequest{Owner: owner, UUID: uuid})
}

func mappingOwnerFor(ctx context.Context) (mappingOwnerRequest, *awswire.Error) {
	claim, present := ctx.Value(mappingOwnerContextKey{}).(mappingOwnerRequest)
	if present && (claim.Owner.StackID == "" || claim.Owner.LogicalID == "" || claim.Owner.Token == "") {
		return claim, failure("AccessDeniedException", "The event source mapping owner identity is incomplete.", 403)
	}
	return claim, nil
}

func requireMappingOwner(ctx context.Context, current EventSourceMappingRecord) *awswire.Error {
	claim, wire := mappingOwnerFor(ctx)
	if wire != nil {
		return wire
	}
	if claim.Owner != (MappingOwner{}) && (claim.Owner != current.Owner || claim.UUID != "" && claim.UUID != current.Key.UUID) {
		return failure("AccessDeniedException", "The event source mapping belongs to a different resource incarnation.", 403)
	}
	return nil
}

func (s *Service) recoverMapping(r Reader, claim mappingOwnerRequest, requested map[string]string) (EventSourceMappingRecord, bool, error) {
	if claim.Owner == (MappingOwner{}) {
		return EventSourceMappingRecord{}, false, nil
	}
	if claim.UUID != "" {
		current, err := r.EventSourceMapping(EventSourceMappingKey{Scope: scopeFor(r.Context()), UUID: claim.UUID})
		if err == nil {
			conditions := map[string][]string{"lambda:FunctionArn": {current.Function.ARN()}}
			if wire := s.authorize(r.Context(), "CreateEventSourceMapping", "*", current.Tags, requested, conditions); wire != nil {
				return current, false, wire
			}
			if wire := requireMappingOwner(r.Context(), current); wire != nil {
				return current, false, wire
			}
			return current, true, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return current, false, err
		}
	}
	rows, err := r.EventSourceMappings(scopeFor(r.Context()))
	if err != nil {
		return EventSourceMappingRecord{}, false, err
	}
	for _, current := range rows {
		if current.Owner != claim.Owner {
			continue
		}
		conditions := map[string][]string{"lambda:FunctionArn": {current.Function.ARN()}}
		if wire := s.authorize(r.Context(), "CreateEventSourceMapping", "*", current.Tags, requested, conditions); wire != nil {
			return current, false, wire
		}
		if wire := requireMappingOwner(r.Context(), current); wire != nil {
			return current, false, wire
		}
		return current, true, nil
	}
	return EventSourceMappingRecord{}, false, nil
}
