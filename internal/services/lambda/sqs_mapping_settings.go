package lambda

import (
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func sqsMappingCreateSettings(in *api.CreateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	if in.StartingPosition != nil || in.StartingPositionTimestamp != nil || in.Topics != nil || in.Queues != nil || in.SelfManagedEventSource != nil {
		return EventSourceMappingSettings{}, mappingParameter("StartingPosition, StartingPositionTimestamp, Topics, Queues and SelfManagedEventSource are not supported for SQS event sources.")
	}
	return applySQSMappingSettings(EventSourceMappingSettings{BatchSize: 10}, mappingSettingsInput(in), true)
}

func applySQSMappingSettings(v EventSourceMappingSettings, in *api.UpdateEventSourceMappingInput, create bool) (EventSourceMappingSettings, *awswire.Error) {
	if in.BisectBatchOnFunctionError != nil || in.DestinationConfig != nil || in.MaximumRecordAgeInSeconds != nil || in.MaximumRetryAttempts != nil || in.ParallelizationFactor != nil || in.TumblingWindowInSeconds != nil || in.AmazonManagedKafkaEventSourceConfig != nil || in.SelfManagedKafkaEventSourceConfig != nil || in.SourceAccessConfigurations != nil || in.DocumentDBEventSourceConfig != nil || in.LoggingConfig != nil {
		return v, mappingParameter("Stream, Kafka, MQ, DocumentDB and logging configuration parameters are not supported for SQS event sources.")
	}
	var wire *awswire.Error
	v, wire = applyCommonMappingSettings(v, in)
	if wire != nil {
		return v, wire
	}
	if in.ScalingConfig != nil {
		v.MaximumConcurrency = nil
		if in.ScalingConfig.MaximumConcurrency != nil {
			v.MaximumConcurrency = new(int(*in.ScalingConfig.MaximumConcurrency))
		}
	}
	if in.ProvisionedPollerConfig != nil {
		p := in.ProvisionedPollerConfig
		if p.PollerGroupName != nil {
			return v, mappingParameter("PollerGroupName is not supported for SQS event sources.")
		}
		if p.MinimumPollers == nil && p.MaximumPollers == nil {
			if create {
				return v, mappingParameter("Either MinimumPollers or MaximumPollers are required if ProvisionedPollerConfig is provided.")
			}
			v.ProvisionedPollers = nil
		} else {
			next := SQSProvisionedPollers{Minimum: 2, Maximum: 200}
			if v.ProvisionedPollers != nil {
				next = *v.ProvisionedPollers
			}
			if p.MinimumPollers != nil {
				next.Minimum = int(*p.MinimumPollers)
			}
			if p.MaximumPollers != nil {
				next.Maximum = int(*p.MaximumPollers)
			}
			if next.Minimum < 2 || next.Minimum > 200 || next.Maximum < next.Minimum || next.Maximum > 10000 {
				return v, mappingParameter("MinimumPollers should be between [2, 200] and MaximumPollers should be between [MinimumPollers, 10000]")
			}
			v.ProvisionedPollers = &next
		}
	}
	if v.ProvisionedPollers != nil && v.MaximumConcurrency != nil {
		return v, mappingParameter("Provisioned mode for SQS ESM does not support maximum concurrency feature. Use MaximumPollers as the control mechanism and remove maximum concurrency.")
	}
	return v, nil
}

func validateSQSMappingBatch(v EventSourceMappingSettings, fifo bool) *awswire.Error {
	// The generated shape boundary owns scalar range and enum validation.
	if v.BatchSize > 10 && v.BatchingWindow == 0 {
		return mappingParameter("Maximum batch window in seconds must be greater than 0 if maximum batch size is greater than 10")
	}
	if fifo && v.BatchingWindow > 0 {
		return mappingParameter("Batching window is not supported for FIFO queues")
	}
	if fifo && v.BatchSize > 10 {
		return mappingParameter("Batch size must not exceed 10 for FIFO queues")
	}
	return nil
}
