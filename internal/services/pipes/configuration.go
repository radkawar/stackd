package pipes

import (
	"context"
	"maps"
	"slices"
	api "stackd/internal/awsapi/pipes"
	"stackd/internal/services/eventbridge/eventpattern"
	"strings"
	"time"
)

func cloneEnrichmentHTTP(in *api.PipeEnrichmentHttpParameters) *api.PipeEnrichmentHttpParameters {
	if in == nil {
		return nil
	}
	return &api.PipeEnrichmentHttpParameters{
		HeaderParameters:      maps.Clone(in.HeaderParameters),
		PathParameterValues:   slices.Clone(in.PathParameterValues),
		QueryStringParameters: maps.Clone(in.QueryStringParameters),
	}
}

func (s *Service) validate(ctx context.Context, p PipeRecord, kms *api.KmsKeyIdentifier, logs *api.PipeLogConfigurationParameters) error {
	if p.Key.Name == "" || p.RoleARN == "" || p.SourceARN == "" || p.TargetARN == "" {
		return invalid("Name, RoleArn, Source, and Target are required.")
	}
	if p.Desired != "RUNNING" && p.Desired != "STOPPED" {
		return invalid("DesiredState must be RUNNING or STOPPED.")
	}
	role := strings.SplitN(p.RoleARN, ":", 6)
	if len(role) != 6 || role[0] != "arn" || role[1] != p.Key.Partition || role[2] != "iam" || role[4] != p.Key.AccountID || !strings.HasPrefix(role[5], "role/") {
		return invalid("RoleArn must identify an IAM role in the pipe account.")
	}
	src := strings.SplitN(p.SourceARN, ":", 6)
	if p.Source.Kind != "kafka" && (len(src) != 6 || src[1] != p.Key.Partition || src[3] != p.Key.Region || src[4] != p.Key.AccountID) {
		return invalid("Source must be in the pipe account and region.")
	}
	if s.sources == nil && !isKafka(p.Source.Kind) {
		return unsupported("Pipes requires a real source consumer adapter.")
	}
	if isKafka(p.Source.Kind) && s.kafkaSources == nil {
		return unsupported("Kafka sources require a real Kafka consumer adapter.")
	}
	if s.targets == nil {
		return unsupported("Pipes requires a real target execution adapter.")
	}
	if _, e := compileTemplate(p.EnrichmentTemplate); e != nil {
		return invalid(e.Error())
	}
	if _, e := compileTemplate(value(p.Target.InputTemplate)); e != nil {
		return invalid(e.Error())
	}
	if e := s.targets.Validate(ctx, p); e != nil {
		return e
	}
	return nil
}
func (s *Service) prepare(ctx context.Context, p *PipeRecord, kms *api.KmsKeyIdentifier, logs *api.PipeLogConfigurationParameters) error {
	if e := s.validate(ctx, *p, kms, logs); e != nil {
		return e
	}
	if e := s.passRole(ctx, *p); e != nil {
		return e
	}
	if e := s.configureLogging(ctx, p, logs); e != nil {
		return e
	}
	return s.seal(ctx, p, kms)
}
func number[T ~int32](p *T, fallback int32) int32 {
	if p == nil {
		return fallback
	}
	return int32(*p)
}
func sourceSettings(arn string, p *api.PipeSourceParameters) (SourceSettings, error) {
	s := SourceSettings{BatchSize: 10, MaximumAge: -1, MaximumRetries: -1, Parallelism: 1}
	if p == nil {
		p = &api.PipeSourceParameters{}
	}
	if p.ActiveMQBrokerParameters != nil || p.RabbitMQBrokerParameters != nil {
		return s, unsupported("MQ sources require real engine consumers that are not configured.")
	}
	if (p.ManagedStreamingKafkaParameters != nil || p.SelfManagedKafkaParameters != nil) && (p.SqsQueueParameters != nil || p.KinesisStreamParameters != nil || p.DynamoDBStreamParameters != nil || !strings.Contains(arn, ":kafka:") && !strings.HasPrefix(arn, "smk://")) {
		return s, invalid("Kafka source parameters do not match the source.")
	}
	switch {
	case strings.Contains(arn, ":kafka:") || strings.HasPrefix(arn, "smk://"):
		if err := kafkaSettings(arn, p, &s); err != nil {
			return s, err
		}
	case strings.Contains(arn, ":sqs:"):
		s.Kind = "sqs"
		if p.KinesisStreamParameters != nil || p.DynamoDBStreamParameters != nil {
			return s, invalid("SourceParameters do not match the SQS source.")
		}
		if q := p.SqsQueueParameters; q != nil {
			s.BatchSize = number(q.BatchSize, 10)
			s.WindowSeconds = number(q.MaximumBatchingWindowInSeconds, 0)
		}
		if strings.HasSuffix(arn, ".fifo") && s.BatchSize > 10 {
			return s, invalid("FIFO queue batch size cannot exceed 10.")
		}
		if s.BatchSize > 10 && s.WindowSeconds == 0 {
			return s, invalid("SQS batches over 10 require a batching window.")
		}
	case strings.Contains(arn, ":kinesis:"):
		s.Kind = "kinesis"
		q := p.KinesisStreamParameters
		if q == nil {
			return s, invalid("KinesisStreamParameters are required.")
		}
		if p.SqsQueueParameters != nil || p.DynamoDBStreamParameters != nil {
			return s, invalid("SourceParameters do not match the Kinesis source.")
		}
		s.BatchSize = number(q.BatchSize, 100)
		s.WindowSeconds = number(q.MaximumBatchingWindowInSeconds, 0)
		s.MaximumAge = number(q.MaximumRecordAgeInSeconds, -1)
		s.MaximumRetries = number(q.MaximumRetryAttempts, -1)
		s.Parallelism = number(q.ParallelizationFactor, 1)
		s.AutomaticBisect = value(q.OnPartialBatchItemFailure) == "AUTOMATIC_BISECT"
		if q.DeadLetterConfig != nil {
			s.DLQ = value(q.DeadLetterConfig.Arn)
		}
		s.StartingPosition = value(q.StartingPosition)
		if q.StartingPositionTimestamp != nil {
			t := time.Time(*q.StartingPositionTimestamp)
			s.StartingTime = &t
		}
		if s.StartingPosition == "AT_TIMESTAMP" && s.StartingTime == nil {
			return s, invalid("StartingPositionTimestamp is required for AT_TIMESTAMP.")
		}
	case strings.Contains(arn, ":dynamodb:") && strings.Contains(arn, "/stream/"):
		s.Kind = "dynamodb"
		q := p.DynamoDBStreamParameters
		if q == nil {
			return s, invalid("DynamoDBStreamParameters are required.")
		}
		if p.SqsQueueParameters != nil || p.KinesisStreamParameters != nil {
			return s, invalid("SourceParameters do not match the DynamoDB source.")
		}
		s.BatchSize = number(q.BatchSize, 100)
		s.WindowSeconds = number(q.MaximumBatchingWindowInSeconds, 0)
		s.MaximumAge = number(q.MaximumRecordAgeInSeconds, -1)
		s.MaximumRetries = number(q.MaximumRetryAttempts, -1)
		s.Parallelism = number(q.ParallelizationFactor, 1)
		s.AutomaticBisect = value(q.OnPartialBatchItemFailure) == "AUTOMATIC_BISECT"
		if q.DeadLetterConfig != nil {
			s.DLQ = value(q.DeadLetterConfig.Arn)
		}
		s.StartingPosition = value(q.StartingPosition)
	default:
		// TODO: Comeback: MQ/DocumentDB engines must provide real consumers before these sources can be admitted.
		return s, unsupported("This Pipes source requires an MQ/DocumentDB engine consumer that is not configured.")
	}
	if s.Kind != "sqs" && s.StartingPosition != "LATEST" && s.StartingPosition != "TRIM_HORIZON" && !(s.Kind == "kinesis" && s.StartingPosition == "AT_TIMESTAMP") {
		return s, invalid("Invalid stream StartingPosition.")
	}
	if s.BatchSize < 1 || s.BatchSize > 10000 || s.WindowSeconds < 0 || s.WindowSeconds > 300 || s.Parallelism < 1 || s.Parallelism > 10 || s.MaximumRetries < -1 || s.MaximumRetries > 10000 || s.MaximumAge < -1 || s.MaximumAge == 0 {
		return s, invalid("Invalid source batch, retry, age, or parallelization setting.")
	}
	if s.DLQ != "" && !strings.Contains(s.DLQ, ":sqs:") && !strings.Contains(s.DLQ, ":sns:") {
		return s, invalid("DeadLetterConfig must identify an SQS queue or SNS topic.")
	}
	if p.FilterCriteria != nil {
		if len(p.FilterCriteria.Filters) > 5 {
			return s, invalid("A pipe supports at most five filters.")
		}
		for _, f := range p.FilterCriteria.Filters {
			v := value(f.Pattern)
			if _, e := eventpattern.Compile([]byte(v)); e != nil {
				return s, invalid(e.Error())
			}
			if isKafka(s.Kind) {
				if err := validateKafkaFilter(v); err != nil {
					return s, err
				}
			}
			s.Filters = append(s.Filters, v)
		}
	}
	return s, nil
}
func sourceParameters(s SourceSettings) *api.PipeSourceParameters {
	p := &api.PipeSourceParameters{}
	if len(s.Filters) > 0 {
		p.FilterCriteria = &api.FilterCriteria{}
		for _, f := range s.Filters {
			p.FilterCriteria.Filters = append(p.FilterCriteria.Filters, api.Filter{Pattern: new(api.EventPattern(f))})
		}
	}
	switch s.Kind {
	case "msk", "kafka":
		kafkaParameters(s, p)
	case "sqs":
		p.SqsQueueParameters = &api.PipeSourceSqsQueueParameters{
			BatchSize:                      new(api.LimitMax10000(s.BatchSize)),
			MaximumBatchingWindowInSeconds: new(api.MaximumBatchingWindowInSeconds(s.WindowSeconds)),
		}
	case "kinesis":
		q := &api.PipeSourceKinesisStreamParameters{
			BatchSize:                      new(api.LimitMax10000(s.BatchSize)),
			MaximumBatchingWindowInSeconds: new(api.MaximumBatchingWindowInSeconds(s.WindowSeconds)),
			MaximumRecordAgeInSeconds:      new(api.MaximumRecordAgeInSeconds(s.MaximumAge)),
			MaximumRetryAttempts:           new(api.MaximumRetryAttemptsESM(s.MaximumRetries)),
			ParallelizationFactor:          new(api.LimitMax10(s.Parallelism)),
			StartingPosition:               new(api.KinesisStreamStartPosition(s.StartingPosition)),
			StartingPositionTimestamp:      s.StartingTime,
		}
		if s.DLQ != "" {
			q.DeadLetterConfig = &api.DeadLetterConfig{Arn: new(api.Arn(s.DLQ))}
		}
		if s.AutomaticBisect {
			q.OnPartialBatchItemFailure = new(api.OnPartialBatchItemFailureStreams("AUTOMATIC_BISECT"))
		}
		p.KinesisStreamParameters = q
	case "dynamodb":
		q := &api.PipeSourceDynamoDBStreamParameters{
			BatchSize:                      new(api.LimitMax10000(s.BatchSize)),
			MaximumBatchingWindowInSeconds: new(api.MaximumBatchingWindowInSeconds(s.WindowSeconds)),
			MaximumRecordAgeInSeconds:      new(api.MaximumRecordAgeInSeconds(s.MaximumAge)),
			MaximumRetryAttempts:           new(api.MaximumRetryAttemptsESM(s.MaximumRetries)),
			ParallelizationFactor:          new(api.LimitMax10(s.Parallelism)),
			StartingPosition:               new(api.DynamoDBStreamStartPosition(s.StartingPosition)),
		}
		if s.DLQ != "" {
			q.DeadLetterConfig = &api.DeadLetterConfig{Arn: new(api.Arn(s.DLQ))}
		}
		if s.AutomaticBisect {
			q.OnPartialBatchItemFailure = new(api.OnPartialBatchItemFailureStreams("AUTOMATIC_BISECT"))
		}
		p.DynamoDBStreamParameters = q
	}
	return p
}
