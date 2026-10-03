package apigatewayexec

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

type requestMetrics struct {
	http.ResponseWriter
	status             int
	requestBytes       int64
	processedBytes     int64
	receivedPayload    bool
	integrated         bool
	integrationLatency time.Duration
	responseBytes      int64
	responseBody       []byte
	observation        *requestObservation
}

func (w *requestMetrics) WriteHeader(status int) {
	if status >= 200 && w.status == 0 {
		if o := w.observation; o != nil {
			if o.rest {
				w.Header().Set("x-amzn-RequestId", o.requestID)
				w.Header().Set("x-amz-apigw-id", o.extendedRequestID)
			} else {
				w.Header().Set("apigw-requestid", o.requestID)
			}
		}
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *requestMetrics) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	written, err := w.ResponseWriter.Write(body)
	w.responseBytes += int64(written)
	if w.observation != nil && w.observation.dataTrace {
		remaining := executionLogLimit - len(w.responseBody)
		w.responseBody = append(w.responseBody, body[:min(written, remaining)]...)
	}
	return written, err
}

func (w *requestMetrics) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Handler) recordRequestMetrics(ctx context.Context, route *Route, at time.Time, elapsed time.Duration, response *requestMetrics) {
	if s.metrics == nil {
		return
	}
	clientError, serverError := "4xx", "5xx"
	if route.ProtocolType == "REST" {
		clientError, serverError = "4XXError", "5XXError"
	}
	values := [6]MetricSample{
		{Name: "Count", Value: 1, SampleCount: 1},
		{Name: clientError, SampleCount: 1},
		{Name: serverError, SampleCount: 1},
		{Name: "Latency", Value: float64(elapsed.Milliseconds()), SampleCount: 1},
	}
	samples := values[:4]
	if response.status >= 400 && response.status < 500 {
		samples[1].Value = 1
	}
	if response.status >= 500 {
		samples[2].Value = 1
	}
	if response.integrated {
		samples = append(samples, MetricSample{Name: "IntegrationLatency", Value: float64(response.integrationLatency.Milliseconds()), SampleCount: 1})
	}
	if route.ProtocolType == "HTTP" && response.receivedPayload {
		samples = append(samples, MetricSample{Name: "DataProcessed", Value: float64(response.processedBytes), SampleCount: 1})
	}
	// TODO: Comeback calibrate HTTP DataProcessed for pre-integration rejection
	// and nonempty request bodies. Native IAM rejection bytes include an
	// unobserved internal envelope; do not invent that envelope or publish zero.
	if err := s.metrics.RecordMetrics(context.WithoutCancel(ctx), route, at, samples); err != nil {
		slog.Error("API Gateway metric commit failed", "api", route.APIID, "stage", route.Stage, "error", err)
	}
}
