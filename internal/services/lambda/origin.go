package lambda

import (
	"context"

	runtime "stackd/compute/lambda"
	"stackd/internal/awsctx"
)

// invocationEnvironment retains only the runtime's public credential identifier.
// Its invocation context spans runtime and extension work, including work after
// the function response. originMu is independent of the execution lock held
// while SDK calls reach the gateway.
type invocationEnvironment struct {
	runtime.Environment
	service     *Service
	accessKeyID string
	invocation  context.Context // guarded by service.originMu
}

// InvocationParent returns attribution only for an active runtime's verified key.
// It never supplies identity or authorization and does not retain warm origins.
func (s *Service) InvocationParent(accessKeyID string) string {
	s.originMu.RLock()
	defer s.originMu.RUnlock()
	e := s.origins[accessKeyID]
	if e == nil || e.invocation.Err() != nil || s.lifetime.Err() != nil {
		return ""
	}
	return awsctx.FromContext(e.invocation).ParentEventID
}

func (e *invocationEnvironment) Invoke(ctx context.Context, in runtime.Invocation, respond func(runtime.Result)) (runtime.Report, error) {
	if awsctx.FromContext(ctx).ParentEventID == "" {
		return e.Environment.Invoke(ctx, in, respond)
	}
	s := e.service
	s.originMu.Lock()
	if s.origins == nil {
		s.origins = make(map[string]*invocationEnvironment)
	}
	e.invocation = ctx
	s.origins[e.accessKeyID] = e
	s.originMu.Unlock()
	// The execution owner serializes invocations and cleanup. Lookup rejects a
	// cancelled context immediately; no cancellation callback can outlive this
	// invocation and race its warm successor.
	defer func() {
		s.originMu.Lock()
		delete(s.origins, e.accessKeyID)
		e.invocation = nil
		s.originMu.Unlock()
	}()
	return e.Environment.Invoke(ctx, in, respond)
}
