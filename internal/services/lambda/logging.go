package lambda

import (
	"encoding/hex"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

// A present LoggingConfig replaces all logging controls; an omitted object
// preserves them. Native capture: testdata/aws/lambda_logging_replacement.json.
// Generated constraints own enum, group character and length validation.
func configureLogging(v *FunctionRecord, in *api.LoggingConfig) *awswire.Error {
	if in == nil {
		return nil
	}
	format := value(in.LogFormat)
	if format == "" {
		format = "Text"
	}
	if format == "Text" && (in.ApplicationLogLevel != nil || in.SystemLogLevel != nil) {
		return failure("InvalidParameterValueException", "LogLevel is not supported when LogFormat is set to \"Text\". Remove LogLevel from your request or change the LogFormat to \"JSON\" and try again.", 400)
	}
	v.Logging.Format = format
	v.Logging.ApplicationLevel, v.Logging.SystemLevel = "", ""
	if format == "JSON" {
		v.Logging.ApplicationLevel, v.Logging.SystemLevel = "INFO", "INFO"
		if in.ApplicationLogLevel != nil {
			v.Logging.ApplicationLevel = value(in.ApplicationLogLevel)
		}
		if in.SystemLogLevel != nil {
			v.Logging.SystemLevel = value(in.SystemLogLevel)
		}
	}
	// AWS permits aws/ names here; delivery owns destination failures.
	v.LogGroup = value(in.LogGroup)
	if v.LogGroup == "/aws/lambda/"+v.Key.Name {
		v.LogGroup = ""
	}
	return nil
}

func loggingConfiguration(v FunctionRecord) *api.LoggingConfig {
	format := v.Logging.Format
	if format == "" {
		format = "Text"
	}
	out := &api.LoggingConfig{LogFormat: new(api.LogFormat(format)), LogGroup: new(api.LogGroup(functionLogGroup(v)))}
	if format == "JSON" {
		out.ApplicationLogLevel = new(api.ApplicationLogLevel(v.Logging.ApplicationLevel))
		out.SystemLogLevel = new(api.SystemLogLevel(v.Logging.SystemLevel))
	}
	return out
}

func functionLogGroup(v FunctionRecord) string {
	if v.LogGroup != "" {
		return v.LogGroup
	}
	return "/aws/lambda/" + v.Key.Name
}

// Custom groups include function identity because several functions may share a
// destination: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-loggroups.html
func functionLogStream(v FunctionRecord, now time.Time) string {
	id := uuid.New()
	guid := hex.EncodeToString(id[:])
	prefix := now.UTC().Format("2006/01/02") + "/"
	version := versionName(v.Version)
	if v.LogGroup != "" {
		return prefix + v.Key.Name + "[" + version + "][" + guid + "]"
	}
	return prefix + "[" + version + "]" + guid
}
