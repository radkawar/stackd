package lambda

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

var kafkaTopicName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,249}$`)

type kafkaMappingControl struct{ s *Service }

func (c kafkaMappingControl) createSettings(in *api.CreateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	v := EventSourceMappingSettings{BatchSize: 100, BatchingWindow: 500 * time.Millisecond, Kafka: &KafkaMappingSettings{StartingPosition: value(in.StartingPosition)}}
	if in.SelfManagedEventSource != nil && len(in.SourceAccessConfigurations) == 0 {
		return v, mappingParameter("Required 'sourceAccessConfigurations' parameter is missing.")
	}
	if len(in.Topics) != 1 || !kafkaTopicName.MatchString(string(in.Topics[0])) || in.Topics[0] == "." || in.Topics[0] == ".." {
		return v, mappingParameter("Exactly one valid Kafka topic is required.")
	}
	v.Kafka.Topic = string(in.Topics[0])
	switch v.Kafka.StartingPosition {
	case "TRIM_HORIZON", "LATEST":
		if in.StartingPositionTimestamp != nil {
			return v, mappingParameter("StartingPositionTimestamp requires AT_TIMESTAMP.")
		}
	case "AT_TIMESTAMP":
		if in.StartingPositionTimestamp == nil {
			return v, mappingParameter("StartingPositionTimestamp is required for AT_TIMESTAMP.")
		}
		v.Kafka.StartingPositionTimestamp = time.Time(*in.StartingPositionTimestamp)
		if v.Kafka.StartingPositionTimestamp.After(c.s.clock.Now()) || v.Kafka.StartingPositionTimestamp.Before(time.Unix(0, 0)) {
			return v, mappingParameter("StartingPositionTimestamp must be between the Unix epoch and the present.")
		}
	default:
		return v, mappingParameter("StartingPosition must be TRIM_HORIZON, LATEST or AT_TIMESTAMP for Kafka.")
	}
	if in.Queues != nil {
		return v, mappingParameter("MQ configuration cannot be used with Kafka.")
	}
	if in.SelfManagedEventSource != nil {
		var wire *awswire.Error
		v.Kafka.BootstrapServers, wire = selfManagedKafkaEndpoints(in.SelfManagedEventSource)
		if wire != nil {
			return v, wire
		}
		if in.AmazonManagedKafkaEventSourceConfig != nil {
			return v, mappingParameter("AmazonManagedKafkaEventSourceConfig cannot be used with self-managed Kafka.")
		}
	} else if in.SelfManagedKafkaEventSourceConfig != nil {
		return v, mappingParameter("SelfManagedKafkaEventSourceConfig requires SelfManagedEventSource.")
	}
	if config := in.AmazonManagedKafkaEventSourceConfig; config != nil {
		if config.SchemaRegistryConfig != nil {
			return v, unsupported("Kafka schema registry deserialization is not implemented.")
		}
		v.Kafka.ConsumerGroupID = value(config.ConsumerGroupId)
		if config.ConsumerGroupId != nil && (v.Kafka.ConsumerGroupID == "" || len(v.Kafka.ConsumerGroupID) > 200 || strings.ContainsAny(v.Kafka.ConsumerGroupID, "\x00\r\n")) {
			return v, mappingParameter("Invalid Kafka ConsumerGroupId.")
		}
	}
	if config := in.SelfManagedKafkaEventSourceConfig; config != nil {
		if config.SchemaRegistryConfig != nil {
			return v, unsupported("Kafka schema registry deserialization is not implemented.")
		}
		v.Kafka.ConsumerGroupID = value(config.ConsumerGroupId)
		if config.ConsumerGroupId != nil && (v.Kafka.ConsumerGroupID == "" || len(v.Kafka.ConsumerGroupID) > 200 || strings.ContainsAny(v.Kafka.ConsumerGroupID, "\x00\r\n")) {
			return v, mappingParameter("Invalid Kafka ConsumerGroupId.")
		}
	}
	update := mappingSettingsInput(in)
	update.AmazonManagedKafkaEventSourceConfig = nil
	update.SelfManagedKafkaEventSourceConfig = nil
	return c.updateSettings(v, update)
}

func (c kafkaMappingControl) updateSettings(v EventSourceMappingSettings, in *api.UpdateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	d := *v.Kafka
	v.Kafka = &d
	if in.AmazonManagedKafkaEventSourceConfig != nil || in.SelfManagedKafkaEventSourceConfig != nil {
		return v, mappingParameter("ConsumerGroupId cannot be updated; Kafka schema registry configuration is not implemented.")
	}
	if in.ScalingConfig != nil || in.DocumentDBEventSourceConfig != nil || in.ParallelizationFactor != nil || in.TumblingWindowInSeconds != nil {
		return v, mappingParameter("The supplied source configuration does not apply to Kafka.")
	}
	// TODO: Comeback implement Kafka provisioned polling, schema registries, logging and finite retry/bisection/failure-destination controls through their real owners.
	if in.ProvisionedPollerConfig != nil || in.LoggingConfig != nil || in.DestinationConfig != nil || len(in.FunctionResponseTypes) > 0 || in.MaximumRetryAttempts != nil && *in.MaximumRetryAttempts != -1 || in.MaximumRecordAgeInSeconds != nil && *in.MaximumRecordAgeInSeconds != -1 || in.BisectBatchOnFunctionError != nil && bool(*in.BisectBatchOnFunctionError) {
		return v, unsupported("Kafka currently supports on-demand polling and whole-batch retries until success or Kafka retention; provisioned polling, logging, schema registries and configured failure handling are not implemented.")
	}
	if in.MetricsConfig != nil && len(in.MetricsConfig.Metrics) != 0 {
		return v, mappingParameter("MetricsConfig is only available for Provisioned Mode. Enable Provisioned Mode by specifying MinimumPollers in ProvisionedPollerConfig.")
	}
	if in.SourceAccessConfigurations != nil {
		previousNetwork := d.Network
		if wire := kafkaSourceAccess(&d, in.SourceAccessConfigurations); wire != nil {
			return v, wire
		}
		if d.Identity != (KafkaIdentity{}) {
			if len(d.Network.SubnetIDs) == 0 {
				d.Network = previousNetwork
			}
			if !slices.Equal(previousNetwork.SubnetIDs, d.Network.SubnetIDs) || !slices.Equal(previousNetwork.SecurityGroupIDs, d.Network.SecurityGroupIDs) {
				// TODO: Comeback stage replacement source ENIs before accepting a Kafka mapping's changed VPC placement.
				return v, unsupported("Changing an existing Kafka mapping's VPC placement is not implemented.")
			}
		}
	}
	var wire *awswire.Error
	v, wire = applyCommonMappingSettings(v, in)
	if wire != nil {
		return v, wire
	}
	if v.BatchSize < 1 || v.BatchSize > 10000 || v.BatchingWindow < 0 || v.BatchingWindow > 300*time.Second {
		return v, mappingParameter("Kafka BatchSize must be between 1 and 10000 and batching window between 0 and 300 seconds.")
	}
	for _, filter := range v.Filters {
		if err := validateKafkaMappingFilter(filter); err != nil {
			return v, mappingParameter(err.Error())
		}
	}
	return v, nil
}

func (c kafkaMappingControl) preflight(ctx context.Context, f FunctionRecord, key EventSourceMappingKey, source string, settings EventSourceMappingSettings, _ *api.UpdateEventSourceMappingInput) *awswire.Error {
	if len(settings.Kafka.BootstrapServers) == 0 {
		parsed, err := arn.Parse(source)
		if err != nil || !strings.HasPrefix(parsed.Resource, "cluster/") || len(strings.Split(parsed.Resource, "/")) != 3 {
			return mappingParameter("EventSourceArn must identify an MSK cluster.")
		}
	}
	for _, secret := range []string{settings.Kafka.SecretARN, settings.Kafka.RootCASecretARN} {
		if secret == "" {
			continue
		}
		parsed, err := arn.Parse(secret)
		if err != nil || parsed.Region != key.Region || parsed.Partition != key.Partition {
			return mappingParameter("Kafka authentication secrets must be in the same region and partition as the function.")
		}
	}
	if f.Capacity == nil && f.Timeout > 840 {
		return mappingParameter("Kafka event source mappings require a function timeout of no more than 840 seconds.")
	}
	if c.s.kafka == nil {
		return unsupported("Kafka event source mappings require a real configured Kafka source adapter.")
	}
	if settings.Kafka.ConsumerGroupID == "" {
		settings.Kafka.ConsumerGroupID = key.UUID
	}
	if len(settings.Kafka.Network.SubnetIDs) != 0 {
		settings.Kafka.NetworkRoleARN = f.Role
	}
	mapping := EventSourceMappingRecord{Key: key, EventSourceARN: source, Settings: settings}
	consumer, err := c.s.kafka.Open(ctx, f.Key, f.Role, mapping)
	if err != nil {
		return streamMappingPreflightError(sourceWireError(err))
	}
	defer consumer.Close()
	if err := consumer.Check(ctx); err != nil {
		return streamMappingPreflightError(sourceWireError(err))
	}
	return nil
}
func (c kafkaMappingControl) createTransition(v *EventSourceMappingRecord, enabled bool) {
	(streamMappingControl{s: c.s}).createTransition(v, enabled)
}
func (c kafkaMappingControl) updateTransition(v *EventSourceMappingRecord, enabled *api.Enabled) {
	(streamMappingControl{s: c.s}).updateTransition(v, enabled)
}
func kafkaMappingConfiguration(v EventSourceMappingRecord, out *api.EventSourceMappingConfiguration) {
	d := v.Settings.Kafka
	out.Topics = api.Topics{api.Topic(d.Topic)}
	out.StartingPosition = new(api.EventSourcePosition(d.StartingPosition))
	if !d.StartingPositionTimestamp.IsZero() {
		out.StartingPositionTimestamp = new(api.Date(d.StartingPositionTimestamp))
	}
	if len(d.BootstrapServers) == 0 {
		out.AmazonManagedKafkaEventSourceConfig = &api.AmazonManagedKafkaEventSourceConfig{ConsumerGroupId: new(api.URI(d.ConsumerGroupID))}
	} else {
		endpoints := make(api.EndpointLists, len(d.BootstrapServers))
		for i, endpoint := range d.BootstrapServers {
			endpoints[i] = api.Endpoint(endpoint)
		}
		out.SelfManagedEventSource = &api.SelfManagedEventSource{Endpoints: api.Endpoints{api.EndPointType("KAFKA_BOOTSTRAP_SERVERS"): endpoints}}
		out.SelfManagedKafkaEventSourceConfig = &api.SelfManagedKafkaEventSourceConfig{ConsumerGroupId: new(api.URI(d.ConsumerGroupID))}
	}
	out.LastProcessingResult = new(api.String(v.LastProcessingResult))
	out.SourceAccessConfigurations = kafkaSourceAccessConfiguration(d)
}
