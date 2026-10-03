package apigateway

import (
	"context"
	"time"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/services/apigatewayexec"
)

// MetricPublisher joins service-generated samples to the shared transaction.
// Publication is not a customer PutMetricData request.
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}

// MetricPublicationKey owns a native dimension set for one UTC minute. REST,
// HTTP and WebSocket APIs share the AWS/ApiGateway publication owner. Dimensions
// are not foreign keys: pending observations survive API and stage deletion.
type MetricPublicationKey struct {
	API          APIKey
	Minute       time.Time
	ProtocolType string
	APIName      string
	Stage        string
	Method       string
	Resource     string
	Route        string
}

type MetricSample = apigatewayexec.MetricSample

type MetricReader interface {
	NextMetricPublication() (MetricPublicationKey, error)
	MetricSamples(MetricPublicationKey) ([]MetricSample, error)
}

type MetricWriter interface {
	AddMetricSamples(MetricPublicationKey, []MetricSample) error
	DeleteMetricPublication(MetricPublicationKey) error
}
