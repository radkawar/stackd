package firehose

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/firehose"
	"stackd/internal/awswire"
)

type lambdaProcessorOptions struct {
	functionARN, roleARN string
	retries              int32
	size                 int64
	interval             time.Duration
}

func normalizeLambdaProcessor(processor *api.Processor, defaultRole string) *awswire.Error {
	parameters := map[string]string{"NumberOfRetries": "3", "RoleArn": defaultRole, "BufferSizeInMBs": "1", "BufferIntervalInSeconds": "60"}
	seen := make(map[string]bool, len(processor.Parameters))
	for _, parameter := range processor.Parameters {
		name := value(parameter.ParameterName)
		switch name {
		case "LambdaArn", "NumberOfRetries", "RoleArn", "BufferSizeInMBs", "BufferIntervalInSeconds":
		default:
			return failure("InvalidArgumentException", "Unsupported Lambda processor parameter: "+name)
		}
		if seen[name] {
			return failure("InvalidArgumentException", "Duplicate Lambda processor parameter: "+name)
		}
		seen[name] = true
		parameters[name] = value(parameter.ParameterValue)
	}
	function, err := arn.Parse(parameters["LambdaArn"])
	if err != nil || function.Service != "lambda" || !strings.HasPrefix(function.Resource, "function:") || function.Region == "" {
		return failure("InvalidArgumentException", "The Lambda processor requires a valid LambdaArn.")
	}
	for _, bound := range []struct {
		name    string
		maximum int64
	}{{"NumberOfRetries", 300}, {"BufferIntervalInSeconds", 900}} {
		value, err := strconv.ParseInt(parameters[bound.name], 10, 32)
		if err != nil || value < 0 || value > bound.maximum {
			return failure("InvalidArgumentException", "Invalid Lambda processor parameter: "+bound.name)
		}
	}
	size, err := strconv.ParseFloat(parameters["BufferSizeInMBs"], 64)
	if err != nil || math.IsNaN(size) || size < 0.2 || size > 3 {
		return failure("InvalidArgumentException", "Lambda BufferSizeInMBs must be between 0.2 and 3.")
	}
	processor.Parameters = make(api.ProcessorParameterList, 0, 5)
	for _, name := range []string{"LambdaArn", "NumberOfRetries", "RoleArn", "BufferSizeInMBs", "BufferIntervalInSeconds"} {
		processor.Parameters = append(processor.Parameters, api.ProcessorParameter{ParameterName: new(api.ProcessorParameterName(name)), ParameterValue: new(api.ProcessorParameterValue(parameters[name]))})
	}
	return nil
}

// lambdaProcessing reads already-normalized configuration. Admission is the
// single owner of parameter validity; delivery does not repeat that validation.
func lambdaProcessing(destination api.ExtendedS3DestinationDescription) (lambdaProcessorOptions, bool) {
	processing := destination.ProcessingConfiguration
	if processing == nil || processing.Enabled == nil || !bool(*processing.Enabled) {
		return lambdaProcessorOptions{}, false
	}
	for _, processor := range processing.Processors {
		if value(processor.Type) != "Lambda" {
			continue
		}
		var out lambdaProcessorOptions
		for _, parameter := range processor.Parameters {
			switch value(parameter.ParameterName) {
			case "LambdaArn":
				out.functionARN = value(parameter.ParameterValue)
			case "RoleArn":
				out.roleARN = value(parameter.ParameterValue)
			case "NumberOfRetries":
				v, _ := strconv.ParseInt(value(parameter.ParameterValue), 10, 32)
				out.retries = int32(v)
			case "BufferSizeInMBs":
				v, _ := strconv.ParseFloat(value(parameter.ParameterValue), 64)
				out.size = int64(v * 1024 * 1024)
			case "BufferIntervalInSeconds":
				v, _ := strconv.ParseInt(value(parameter.ParameterValue), 10, 32)
				out.interval = time.Duration(v) * time.Second
			}
		}
		return out, true
	}
	return lambdaProcessorOptions{}, false
}

func processorRoleARNs(configuration *api.ProcessingConfiguration) []string {
	var roles []string
	if configuration == nil {
		return roles
	}
	for _, processor := range configuration.Processors {
		if value(processor.Type) != "Lambda" {
			continue
		}
		for _, parameter := range processor.Parameters {
			if value(parameter.ParameterName) == "RoleArn" {
				roles = append(roles, value(parameter.ParameterValue))
			}
		}
	}
	return roles
}
