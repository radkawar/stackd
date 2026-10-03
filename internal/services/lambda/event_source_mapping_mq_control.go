package lambda

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"strings"
	"time"
)

type mqMappingControl struct{ s *Service }

func (c mqMappingControl) createSettings(in *api.CreateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	v := EventSourceMappingSettings{BatchSize: 100, BatchingWindow: 500 * time.Millisecond, MQ: &MQMappingSettings{VirtualHost: "/"}}
	if len(in.Queues) != 1 || len(in.Queues[0]) == 0 || len(in.Queues[0]) > 1000 || strings.ContainsAny(string(in.Queues[0]), "\x00\r\n") {
		return v, mappingParameter("Exactly one valid MQ queue is required.")
	}
	v.MQ.Queue = string(in.Queues[0])
	if in.StartingPosition != nil || in.StartingPositionTimestamp != nil || in.Topics != nil || in.SelfManagedEventSource != nil {
		return v, mappingParameter("MQ mappings do not accept stream starting positions or Kafka topics.")
	}
	return applyMQMappingSettings(v, mappingSettingsInput(in))
}
func (c mqMappingControl) updateSettings(v EventSourceMappingSettings, in *api.UpdateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	for _, access := range in.SourceAccessConfigurations {
		if value(access.Type) == "VIRTUAL_HOST" {
			return v, mappingParameter("VIRTUAL_HOST cannot be specified in UpdateEventSourceMapping.")
		}
	}
	d := *v.MQ
	v.MQ = &d
	return applyMQMappingSettings(v, in)
}

func applyMQMappingSettings(v EventSourceMappingSettings, in *api.UpdateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	d := v.MQ
	if in.AmazonManagedKafkaEventSourceConfig != nil || in.SelfManagedKafkaEventSourceConfig != nil || in.DocumentDBEventSourceConfig != nil || in.ScalingConfig != nil || in.ParallelizationFactor != nil || in.TumblingWindowInSeconds != nil {
		return v, mappingParameter("The supplied source configuration does not apply to Amazon MQ.")
	}
	// TODO: Comeback implement provisioned MQ pollers and expanded ActiveMQ
	// concurrency with native independent transactional JMS sessions.
	if in.ProvisionedPollerConfig != nil || in.LoggingConfig != nil || in.DestinationConfig != nil || len(in.FunctionResponseTypes) > 0 || in.MaximumRetryAttempts != nil || in.MaximumRecordAgeInSeconds != nil || in.BisectBatchOnFunctionError != nil {
		return v, unsupported("MQ supports whole-batch retries until success or broker expiry; provisioned pollers, logging and configured failure handling are not implemented.")
	}
	if in.SourceAccessConfigurations != nil {
		d.SecretARN = ""
		seen := map[string]bool{}
		for _, access := range in.SourceAccessConfigurations {
			kind := value(access.Type)
			if seen[kind] {
				return v, mappingParameter("Duplicate MQ source access type.")
			}
			seen[kind] = true
			switch kind {
			case "BASIC_AUTH":
				p, e := arn.Parse(value(access.URI))
				if e != nil || p.Service != "secretsmanager" || !strings.HasPrefix(p.Resource, "secret:") {
					return v, mappingParameter("BASIC_AUTH requires a Secrets Manager secret ARN.")
				}
				d.SecretARN = p.String()
			case "VIRTUAL_HOST":
				d.VirtualHost = value(access.URI)
				if d.VirtualHost == "" || strings.ContainsAny(d.VirtualHost, "\x00\r\n") {
					return v, mappingParameter("Invalid RabbitMQ virtual host.")
				}
				d.VirtualHostSet = true
			default:
				return v, mappingParameter("MQ supports BASIC_AUTH and RabbitMQ VIRTUAL_HOST source access types.")
			}
		}
	}
	if d.SecretARN == "" {
		return v, mappingParameter("MQ requires BASIC_AUTH credentials in Secrets Manager.")
	}
	var wire *awswire.Error
	v, wire = applyCommonMappingSettings(v, in)
	if wire != nil {
		return v, wire
	}
	if v.BatchSize < 1 || v.BatchSize > 10000 || v.BatchingWindow < 0 || v.BatchingWindow > 300*time.Second {
		return v, mappingParameter("MQ BatchSize must be 1-10000 and batching window 0-300 seconds.")
	}
	for _, pattern := range v.Filters {
		if err := validateMQMappingFilter(pattern); err != nil {
			return v, mappingParameter(err.Error())
		}
	}
	return v, nil
}
func (c mqMappingControl) preflight(ctx context.Context, f FunctionRecord, key EventSourceMappingKey, source string, settings EventSourceMappingSettings, _ *api.UpdateEventSourceMappingInput) *awswire.Error {
	p, e := arn.Parse(source)
	if e != nil || p.Service != "mq" || !strings.HasPrefix(p.Resource, "broker:") || len(strings.Split(p.Resource, ":")) != 3 {
		return mappingParameter("EventSourceArn must identify an Amazon MQ broker.")
	}
	if p.AccountID != f.Key.Account || p.Region != f.Key.Region || p.Partition != f.Key.Partition {
		return mappingParameter("Cross-account and cross-region MQ mappings are not supported.")
	}
	if f.Timeout > 840 {
		return mappingParameter("MQ event source mappings require function timeout at most 840 seconds.")
	}
	if c.s.mq == nil {
		return unsupported("MQ mappings require a real broker source adapter.")
	}
	identity, err := c.s.mq.Check(ctx, f.Key, f.Role, EventSourceMappingRecord{Key: key, EventSourceARN: source, Settings: settings})
	if err != nil {
		return streamMappingPreflightError(sourceWireError(err))
	}
	if identity.Engine == "ACTIVEMQ" && settings.MQ.VirtualHostSet {
		return mappingParameter("VIRTUAL_HOST applies only to RabbitMQ.")
	}
	settings.MQ.Identity = identity
	return nil
}
func (c mqMappingControl) createTransition(v *EventSourceMappingRecord, enabled bool) {
	(streamMappingControl{s: c.s}).createTransition(v, enabled)
}
func (c mqMappingControl) updateTransition(v *EventSourceMappingRecord, enabled *api.Enabled) {
	(streamMappingControl{s: c.s}).updateTransition(v, enabled)
}
func mqMappingConfiguration(v EventSourceMappingRecord, out *api.EventSourceMappingConfiguration) {
	d := v.Settings.MQ
	out.Queues = api.Queues{api.Queue(d.Queue)}
	out.SourceAccessConfigurations = api.SourceAccessConfigurations{{Type: new(api.SourceAccessType("BASIC_AUTH")), URI: new(api.URI(d.SecretARN))}}
	// TODO: Comeback calibrate omitted RabbitMQ virtual-host output; native
	// captures establish explicit root/custom hosts, not the implicit default.
	if d.VirtualHostSet {
		out.SourceAccessConfigurations = append(out.SourceAccessConfigurations, api.SourceAccessConfiguration{Type: new(api.SourceAccessType("VIRTUAL_HOST")), URI: new(api.URI(d.VirtualHost))})
	}
	out.LastProcessingResult = new(api.String(v.LastProcessingResult))
}
