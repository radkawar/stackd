package lambda

import (
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge/eventpattern"
	"time"
)

func mappingParameter(message string) *awswire.Error {
	return &awswire.Error{Code: "InvalidParameterValueException", Message: message, StatusCode: 400, Type: "User"}
}

func mappingSettingsInput(in *api.CreateEventSourceMappingInput) *api.UpdateEventSourceMappingInput {
	return &api.UpdateEventSourceMappingInput{
		BatchSize: in.BatchSize, MaximumBatchingWindowInSeconds: in.MaximumBatchingWindowInSeconds,
		FilterCriteria: in.FilterCriteria, FunctionResponseTypes: in.FunctionResponseTypes, ScalingConfig: in.ScalingConfig,
		ProvisionedPollerConfig: in.ProvisionedPollerConfig, MetricsConfig: in.MetricsConfig, KMSKeyArn: in.KMSKeyArn,
		BisectBatchOnFunctionError: in.BisectBatchOnFunctionError, DestinationConfig: in.DestinationConfig,
		MaximumRecordAgeInSeconds: in.MaximumRecordAgeInSeconds, MaximumRetryAttempts: in.MaximumRetryAttempts,
		ParallelizationFactor: in.ParallelizationFactor, TumblingWindowInSeconds: in.TumblingWindowInSeconds,
		AmazonManagedKafkaEventSourceConfig: in.AmazonManagedKafkaEventSourceConfig, SelfManagedKafkaEventSourceConfig: in.SelfManagedKafkaEventSourceConfig,
		SourceAccessConfigurations: in.SourceAccessConfigurations, DocumentDBEventSourceConfig: in.DocumentDBEventSourceConfig, LoggingConfig: in.LoggingConfig,
	}
}

func applyCommonMappingSettings(v EventSourceMappingSettings, in *api.UpdateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	if in.BatchSize != nil {
		v.BatchSize = int(*in.BatchSize)
	}
	if in.MaximumBatchingWindowInSeconds != nil {
		v.BatchingWindow = time.Duration(*in.MaximumBatchingWindowInSeconds) * time.Second
	}
	if in.FilterCriteria != nil {
		v.Filters = nil
		for _, filter := range in.FilterCriteria.Filters {
			pattern := value(filter.Pattern)
			if _, err := eventpattern.Compile([]byte(pattern)); err != nil {
				return v, mappingParameter("Invalid filter pattern definition.")
			}
			v.Filters = append(v.Filters, pattern)
		}
	}
	if in.FunctionResponseTypes != nil {
		v.ReportBatchItemFailures = len(in.FunctionResponseTypes) > 0
	}
	if in.MetricsConfig != nil {
		v.Metrics = nil
		for _, metric := range in.MetricsConfig.Metrics {
			if metric != api.EventSourceMappingMetricEventCount {
				return v, mappingParameter("Only EventCount metrics are supported for event source mappings.")
			}
			if len(v.Metrics) == 0 {
				v.Metrics = append(v.Metrics, string(metric))
			}
		}
	}
	return v, nil
}

func eventSourceMappingConfiguration(v EventSourceMappingRecord) *api.EventSourceMappingConfiguration {
	out := &api.EventSourceMappingConfiguration{
		UUID: new(api.UUIDString(v.Key.UUID)), EventSourceMappingArn: new(api.EventSourceMappingArn(v.Key.ARN())),
		EventSourceArn: new(api.Arn(v.EventSourceARN)), FunctionArn: new(api.FunctionArn(v.Function.ARN())),
		BatchSize: new(api.BatchSize(v.Settings.BatchSize)),
		State:     new(api.String(v.State)), StateTransitionReason: new(api.String(v.StateTransitionReason)), LastModified: new(api.Date(v.LastModified)),
		FunctionResponseTypes: api.FunctionResponseTypeList{},
	}
	// An initial 500ms window has no integer-seconds representation.
	// Native responses omit it rather than reporting the distinct zero window.
	if v.Settings.BatchingWindow%time.Second == 0 {
		out.MaximumBatchingWindowInSeconds = new(api.MaximumBatchingWindowInSeconds(v.Settings.BatchingWindow / time.Second))
	}
	if v.EventSourceARN == "" {
		out.EventSourceArn = nil
	}
	if v.Settings.KMSKeyARN != "" {
		out.KMSKeyArn = new(api.KMSKeyArn(v.Settings.KMSKeyARN))
	}
	if v.Settings.ReportBatchItemFailures {
		out.FunctionResponseTypes = append(out.FunctionResponseTypes, api.FunctionResponseTypeReportBatchItemFailures)
	}
	if len(v.Settings.Filters) > 0 {
		out.FilterCriteria = &api.FilterCriteria{Filters: api.FilterList{}}
		for _, pattern := range v.Settings.Filters {
			out.FilterCriteria.Filters = append(out.FilterCriteria.Filters, api.Filter{Pattern: new(api.Pattern(pattern))})
		}
	}
	if v.Settings.MaximumConcurrency != nil {
		out.ScalingConfig = &api.ScalingConfig{MaximumConcurrency: new(api.MaximumConcurrency(*v.Settings.MaximumConcurrency))}
	}
	if p := v.Settings.ProvisionedPollers; p != nil {
		out.ProvisionedPollerConfig = &api.ProvisionedPollerConfig{MinimumPollers: new(api.MinimumNumberOfPollers(p.Minimum)), MaximumPollers: new(api.MaximumNumberOfPollers(p.Maximum))}
	}
	if len(v.Settings.Metrics) > 0 {
		out.MetricsConfig = &api.EventSourceMappingMetricsConfig{Metrics: api.EventSourceMappingMetricList{}}
		for _, metric := range v.Settings.Metrics {
			out.MetricsConfig.Metrics = append(out.MetricsConfig.Metrics, api.EventSourceMappingMetric(metric))
		}
	}
	if v.Settings.Stream != nil {
		streamMappingConfiguration(v, out)
	}
	if v.Settings.Kafka != nil {
		kafkaMappingConfiguration(v, out)
	}
	if v.Settings.MQ != nil {
		mqMappingConfiguration(v, out)
	}
	if v.Settings.DocumentDB != nil {
		documentDBMappingConfiguration(v, out)
	}
	return out
}
