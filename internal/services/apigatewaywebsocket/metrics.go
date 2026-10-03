package apigatewaywebsocket

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/services/apigatewayexec"
)

const managementPostRoute = "POST /@connections/{connectionId}"

// eventMetrics describes one gateway operation, not one frame or dimension set.
// Native error statistics contain one zero/one sample per operation, whereas
// MessageCount contains a separate sample for each counted incoming/outgoing message.
type eventMetrics struct {
	messages           int64
	connect            bool
	clientError        bool
	executionError     bool
	integrationCalled  bool
	integrationLatency time.Duration
}

func (m *eventMetrics) responseStatus(status int) {
	m.clientError = status >= http.StatusBadRequest && status < http.StatusInternalServerError
	m.executionError = status >= http.StatusInternalServerError
}

func (s *Service) recordMetrics(ctx context.Context, route *apigatewayexec.Route, at time.Time, m eventMetrics) {
	if s.metrics == nil || route == nil {
		return
	}
	// Unmatched MESSAGE requests have API/stage error statistics, but no
	// detailed series for the unbound route. Reserved and callback routes do.
	if route.ResourceID == "" && route.DetailedMetricsEnabled && route.RouteKey != "$connect" && route.RouteKey != "$disconnect" && route.RouteKey != managementPostRoute {
		metadata := *route
		metadata.DetailedMetricsEnabled = false
		route = &metadata
	}
	var samples [6]apigatewayexec.MetricSample
	samples[0] = apigatewayexec.MetricSample{Name: "IntegrationError", SampleCount: 1}
	samples[1] = apigatewayexec.MetricSample{Name: "ClientError", SampleCount: 1}
	samples[2] = apigatewayexec.MetricSample{Name: "ExecutionError", SampleCount: 1}
	// Captured proxy 503 and missing-alias failures populate ExecutionError.
	// TODO: Comeback calibrate positive IntegrationError, runtime FunctionError
	// and rejected management callbacks against native WebSocket metrics.
	if m.clientError {
		samples[1].Value = 1
	}
	if m.executionError {
		samples[2].Value = 1
	}
	n := 3
	if m.connect {
		samples[n] = apigatewayexec.MetricSample{Name: "ConnectCount", Value: 1, SampleCount: 1}
		n++
	}
	if m.messages != 0 {
		samples[n] = apigatewayexec.MetricSample{Name: "MessageCount", Value: 1, SampleCount: m.messages}
		n++
	}
	if m.integrationCalled {
		samples[n] = apigatewayexec.MetricSample{Name: "IntegrationLatency", Value: float64(m.integrationLatency.Milliseconds()), SampleCount: 1}
		n++
	}
	if err := s.metrics.RecordMetrics(context.WithoutCancel(ctx), route, at, samples[:n]); err != nil {
		slog.Error("API Gateway WebSocket metric commit failed", "api", route.APIID, "stage", route.Stage, "route", route.RouteKey, "error", err)
	}
}

func (s *Service) managementRoute(ctx context.Context, method string) *apigatewayexec.Route {
	if (s.metrics == nil && s.logs == nil) || s.resolver == nil {
		return nil
	}
	target, ok := ctx.Value(endpointContextKey{}).(endpoint)
	if !ok {
		return nil
	}
	route, err := s.resolver.ResolveWebSocket(context.WithoutCancel(ctx), target.api, target.stage, method+" /@connections/{connectionId}", nil)
	if err != nil || route == nil || owner(route) != target {
		slog.Error("API Gateway WebSocket management route resolution failed", "api", target.api, "stage", target.stage, "error", err)
		return nil
	}
	return route
}

func (s *Service) recordPostMetrics(ctx context.Context, route *apigatewayexec.Route, at time.Time, m eventMetrics, rejected *awswire.Error) {
	if rejected != nil {
		m.responseStatus(rejected.StatusCode)
	}
	s.recordMetrics(ctx, route, at, m)
}
