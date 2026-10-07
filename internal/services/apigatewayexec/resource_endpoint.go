package apigatewayexec

import (
	"errors"
	"net/http"
)

// ResourceExecutionResolver is implemented by each native API owner. A matched
// namespace with ErrUnknownAPI lets the other API protocol owner try its store,
// but must never fall through to an unrelated control-plane route.
type ResourceExecutionResolver interface {
	ResourceExecution(*http.Request) (ExecutionTarget, bool, error)
}
type WebSocketExecution interface {
	ServeExecution(http.ResponseWriter, *http.Request) bool
}

// ResourceDispatcher precedes path routing while retaining original signed bytes.
func (s *Handler) ResourceDispatcher(websocket WebSocketExecution, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ServeResourceExecution(w, r, websocket) {
			next.ServeHTTP(w, r)
		}
	})
}
func (s *Handler) ServeResourceExecution(w http.ResponseWriter, r *http.Request, websocket WebSocketExecution) bool {
	matched := false
	for _, resolver := range []Resolver{s.http, s.rest} {
		owner, ok := resolver.(ResourceExecutionResolver)
		if !ok {
			continue
		}
		target, claimed, err := owner.ResourceExecution(r)
		matched = matched || claimed
		if !claimed || errors.Is(err, ErrUnknownAPI) {
			continue
		}
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return true
		}
		r = r.WithContext(WithExecutionTarget(r.Context(), target))
		if !target.REST && websocket != nil && websocket.ServeExecution(w, r) {
			return true
		}
		s.ServeHTTP(w, r)
		return true
	}
	if matched {
		http.NotFound(w, r)
	}
	return matched
}
