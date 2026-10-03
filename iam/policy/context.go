package policy

import (
	"fmt"
	"strings"
)

// evaluationContext keeps normalized values and their declared cardinality
// together through every policy layer and variable expansion.
type evaluationContext struct {
	values map[string][]string
	types  map[string]string
}

func (c evaluationContext) multivalued(key string) bool {
	return strings.HasSuffix(c.types[key], "List") || len(c.values[key]) > 1
}

func (c evaluationContext) nonNull(key string) bool {
	return c.values[key] != nil
}

func requestContext(request Request) (evaluationContext, error) {
	if !actionPattern.MatchString(request.Action) || strings.ContainsAny(request.Action, "*?") {
		return evaluationContext{}, fmt.Errorf("%w: Action must be a concrete service:Action", ErrInvalidRequest)
	}
	if request.Resource != "*" {
		parts := strings.SplitN(request.Resource, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] == "" || parts[5] == "" {
			return evaluationContext{}, fmt.Errorf("%w: Resource must be a complete ARN or *", ErrInvalidRequest)
		}
	}
	context := make(map[string][]string, len(request.Context))
	for _, key := range sortedKeys(request.Context) {
		canonical := strings.ToLower(key)
		if canonical == "" {
			return evaluationContext{}, fmt.Errorf("%w: context key cannot be empty", ErrInvalidRequest)
		}
		if _, exists := context[canonical]; exists {
			return evaluationContext{}, fmt.Errorf("%w: case-colliding context key %q", ErrInvalidRequest, key)
		}
		context[canonical] = request.Context[key]
	}
	types := make(map[string]string, len(request.ContextTypes))
	for _, key := range sortedKeys(request.ContextTypes) {
		canonical := strings.ToLower(key)
		if canonical == "" || types[canonical] != "" {
			return evaluationContext{}, fmt.Errorf("%w: empty or case-colliding context type key %q", ErrInvalidRequest, key)
		}
		kind := request.ContextTypes[key]
		switch strings.TrimSuffix(kind, "List") {
		case "string", "numeric", "boolean", "date", "ip", "binary":
		default:
			return evaluationContext{}, fmt.Errorf("%w: unknown context type %q for %s", ErrInvalidRequest, kind, key)
		}
		if !strings.HasSuffix(kind, "List") && len(context[canonical]) > 1 {
			return evaluationContext{}, fmt.Errorf("%w: scalar context key %s has multiple values", ErrInvalidRequest, key)
		}
		types[canonical] = kind
	}
	return evaluationContext{values: context, types: types}, nil
}
