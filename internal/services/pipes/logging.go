package pipes

import (
	"context"
	"log/slog"
	api "stackd/internal/awsapi/pipes"
	"time"
)

func (s *Service) configureLogging(ctx context.Context, p *PipeRecord, in *api.PipeLogConfigurationParameters) error {
	if in == nil {
		return nil
	}
	config := Logging{Level: value(in.Level), OutputFormat: "json"}
	switch config.Level {
	case "OFF", "ERROR", "INFO", "TRACE":
	default:
		return invalid("Invalid log level.")
	}
	for _, v := range in.IncludeExecutionData {
		if v != "ALL" {
			return invalid("IncludeExecutionData supports only ALL.")
		}
		config.IncludeExecutionData = true
	}
	if d := in.CloudwatchLogsLogDestination; d != nil {
		config.LogGroupARN = value(d.LogGroupArn)
	}
	if d := in.FirehoseLogDestination; d != nil {
		config.FirehoseARN = value(d.DeliveryStreamArn)
	}
	if d := in.S3LogDestination; d != nil {
		config.BucketName = value(d.BucketName)
		config.BucketOwner = value(d.BucketOwner)
		config.Prefix = value(d.Prefix)
		if d.OutputFormat != nil {
			config.OutputFormat = value(d.OutputFormat)
		}
		if config.OutputFormat != "json" && config.OutputFormat != "plain" && config.OutputFormat != "w3c" {
			return invalid("Invalid S3 log OutputFormat.")
		}
		if config.OutputFormat != "json" {
			// TODO: Comeback: capture the native plain/w3c column layouts and
			// execution-data encoding before admitting those S3 output formats.
			return unsupported("S3 execution log output requires JSON; plain and w3c layouts are not implemented.")
		}
	}
	if config.Level != "OFF" && config.LogGroupARN == "" && config.FirehoseARN == "" && config.BucketName == "" {
		return invalid("Enabled logging requires a log destination.")
	}
	p.Logging = config
	if config.Level != "OFF" {
		if s.diagnostics == nil {
			return unsupported("Pipes execution logging requires a configured diagnostic delivery adapter.")
		}
		if e := s.diagnostics.Validate(ctx, *p); e != nil {
			return e
		}
	}
	return nil
}
func loggingOutput(v Logging) *api.PipeLogConfiguration {
	if v.Level == "" {
		return nil
	}
	out := &api.PipeLogConfiguration{Level: new(api.LogLevel(v.Level))}
	if v.IncludeExecutionData {
		out.IncludeExecutionData = api.IncludeExecutionData{"ALL"}
	}
	if v.LogGroupARN != "" {
		out.CloudwatchLogsLogDestination = &api.CloudwatchLogsLogDestination{LogGroupArn: new(api.CloudwatchLogGroupArn(v.LogGroupARN))}
	}
	if v.FirehoseARN != "" {
		out.FirehoseLogDestination = &api.FirehoseLogDestination{DeliveryStreamArn: new(api.FirehoseArn(v.FirehoseARN))}
	}
	if v.BucketName != "" {
		out.S3LogDestination = &api.S3LogDestination{
			BucketName:   new(api.String(v.BucketName)),
			BucketOwner:  new(api.String(v.BucketOwner)),
			Prefix:       new(api.String(v.Prefix)),
			OutputFormat: new(api.S3OutputFormat(v.OutputFormat)),
		}
	}
	return out
}
func (s *Service) logExecution(ctx context.Context, p PipeRecord, id, stage, level string, payload []byte, err error, started time.Time) {
	if s.diagnostics == nil || p.Logging.Level == "" || p.Logging.Level == "OFF" {
		return
	}
	if p.Logging.Level == "ERROR" && level != "ERROR" || p.Logging.Level == "INFO" && level == "TRACE" {
		return
	}
	v := ExecutionLog{ID: id, Stage: stage, Level: level, At: s.clock.Now(), Duration: s.clock.Now().Sub(started)}
	if p.Logging.IncludeExecutionData {
		v.Payload = payload
	}
	if err != nil {
		v.Error = err.Error()
	}
	// AWS vended execution logs are best effort. A rejected log write never
	// changes successful source acknowledgement or customer target execution.
	if e := s.diagnostics.Publish(ctx, p, v); e != nil {
		slog.WarnContext(ctx, "Pipes execution log delivery failed", "pipe", p.Key.ARN(), "error", e)
	}
}
