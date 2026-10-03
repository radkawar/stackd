package integrations

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

func cfnLambdaMappingSettings(p cloudformation.Properties, source string) error {
	if source == "sqs" {
		for _, property := range []string{"StartingPosition", "StartingPositionTimestamp", "ParallelizationFactor", "MaximumRetryAttempts", "MaximumRecordAgeInSeconds", "BisectBatchOnFunctionError", "TumblingWindowInSeconds", "DestinationConfig"} {
			if _, present := p[property]; present {
				return fmt.Errorf("%s requires a stream event source", property)
			}
		}
	} else if _, present := p["ScalingConfig"]; present {
		return fmt.Errorf("ScalingConfig requires an SQS event source")
	}
	if _, present := p["DocumentDBEventSourceConfig"]; present {
		if source != "rds" {
			return fmt.Errorf("DocumentDBEventSourceConfig requires a DocumentDB event source")
		}
		if err := cfnLambdaMappingObject[api.DocumentDBEventSourceConfig](p, "DocumentDBEventSourceConfig"); err != nil {
			return err
		}
	}
	if _, present := p["Queues"]; present {
		if source != "mq" {
			return fmt.Errorf("queues require an Amazon MQ event source")
		}
		if _, err := cfnComputeStringList(p, "Queues"); err != nil {
			return err
		}
	}
	if value, present := p["SourceAccessConfigurations"]; present {
		if source != "rds" && source != "kafka" && source != "self-managed-kafka" && source != "mq" {
			return fmt.Errorf("SourceAccessConfigurations requires a Kafka, DocumentDB or Amazon MQ event source")
		}
		var decoded struct {
			SourceAccessConfigurations api.SourceAccessConfigurations
		}
		if err := cfnMessagingDecode(cloudformation.Properties{"SourceAccessConfigurations": value}, &decoded); err != nil {
			return err
		}
	}
	if err := cfnLambdaMappingObject[api.FilterCriteria](p, "FilterCriteria"); err != nil {
		return err
	}
	if err := cfnLambdaMappingObject[api.EventSourceMappingMetricsConfig](p, "MetricsConfig"); err != nil {
		return err
	}
	return cfnLambdaMappingObject[api.DestinationConfig](p, "DestinationConfig")
}

func cfnLambdaMappingObject[T any](p cloudformation.Properties, name string) error {
	value, present := p[name]
	if !present {
		return nil
	}
	object, ok := cfnComputeObject(value)
	if !ok {
		return fmt.Errorf("%s must be an object", name)
	}
	var decoded T
	return cfnMessagingDecode(cloudformation.Properties(object), &decoded)
}

func cfnLambdaMappingCreateInput(p cloudformation.Properties) map[string]any {
	input := cfnComputeCopy(p, "FunctionName", "EventSourceArn", "BatchSize", "Enabled", "MaximumBatchingWindowInSeconds", "FunctionResponseTypes", "ScalingConfig", "StartingPosition", "StartingPositionTimestamp", "ParallelizationFactor", "MaximumRetryAttempts", "MaximumRecordAgeInSeconds", "BisectBatchOnFunctionError", "TumblingWindowInSeconds", "DestinationConfig", "FilterCriteria", "MetricsConfig", "SelfManagedKafkaEventSourceConfig", "AmazonManagedKafkaEventSourceConfig", "Topics", "SourceAccessConfigurations", "DocumentDBEventSourceConfig", "Queues")
	if key, present := p["KmsKeyArn"]; present {
		input["KMSKeyArn"] = key
	}
	return input
}

func cfnLambdaMappingUpdateInput(r cloudformation.ResourceRequest) map[string]any {
	input := cfnLambdaMappingCreateInput(r.Properties)
	delete(input, "EventSourceArn")
	delete(input, "StartingPosition")
	delete(input, "StartingPositionTimestamp")
	input["UUID"] = r.PhysicalID
	if cfnLambdaMappingKafkaConfig(r.Properties) != "" {
		cfnLambdaMappingKafkaUpdateInput(input, r)
		return input
	}
	if strings.Contains(cfnComputeString(r.Properties, "EventSourceArn"), ":rds:") {
		// DocumentDB has native watch settings, not Kinesis retry/filter controls.
		input["BatchSize"] = cfnComputeDefault(r.Properties, "BatchSize", 100)
		input["Enabled"] = cfnComputeDefault(r.Properties, "Enabled", true)
		// The native deployment provider does not send namespace edits to
		// UpdateEventSourceMapping; only FullDocument is mutable there.
		delete(input, "DocumentDBEventSourceConfig")
		if config, ok := cfnComputeObject(r.Properties["DocumentDBEventSourceConfig"]); ok {
			if mode, present := config["FullDocument"]; present {
				input["DocumentDBEventSourceConfig"] = map[string]any{"FullDocument": mode}
			}
		}
		return input
	}
	if strings.Contains(cfnComputeString(r.Properties, "EventSourceArn"), ":mq:") {
		delete(input, "Queues")
		// The provider updates existing access only when its template value
		// changes. Omission, reintroduction and unchanged properties retain it.
		if _, previous := r.Previous["SourceAccessConfigurations"]; !previous || !cfnComputeChanged(r.Previous, r.Properties, "SourceAccessConfigurations") {
			delete(input, "SourceAccessConfigurations")
		}
		input["BatchSize"] = cfnComputeDefault(r.Properties, "BatchSize", 100)
		input["Enabled"] = cfnComputeDefault(r.Properties, "Enabled", true)
		input["FilterCriteria"] = cfnComputeDefault(r.Properties, "FilterCriteria", map[string]any{})
		return input
	}
	batchSize := 100
	if strings.Contains(cfnComputeString(r.Properties, "EventSourceArn"), ":sqs:") {
		batchSize = 10
		input["ScalingConfig"] = cfnComputeDefault(r.Properties, "ScalingConfig", map[string]any{})
	} else {
		for key, fallback := range map[string]any{"ParallelizationFactor": 1, "MaximumRetryAttempts": -1, "MaximumRecordAgeInSeconds": -1, "BisectBatchOnFunctionError": false, "TumblingWindowInSeconds": 0} {
			input[key] = cfnComputeDefault(r.Properties, key, fallback)
		}
		destination, provided := cfnComputeObject(r.Properties["DestinationConfig"])
		_, previous := r.Previous["DestinationConfig"]
		if provided || previous {
			failure, _ := cfnComputeObject(destination["OnFailure"])
			if _, present := failure["Destination"]; !present {
				// Native CFN clears omitted and empty destination objects.
				input["DestinationConfig"] = map[string]any{"OnFailure": map[string]any{"Destination": ""}}
			}
		}
	}
	// Native CloudFormation removal resets the configured values; omitting
	// these fields from UpdateEventSourceMapping would retain them instead.
	for key, fallback := range map[string]any{"BatchSize": batchSize, "Enabled": true, "MaximumBatchingWindowInSeconds": 0, "FunctionResponseTypes": []string{}, "FilterCriteria": map[string]any{}, "MetricsConfig": map[string]any{"Metrics": []string{}}} {
		input[key] = cfnComputeDefault(r.Properties, key, fallback)
	}
	// Unlike FilterCriteria, omitting KmsKeyArn retains the existing key.
	// Clearing the filters also clears encryption in the Lambda owner.
	return input
}

// CloudFormation uses Unix seconds, while Call's SDK-input decoder expects the
// formatted representation of a Go time.Time. Keep this conversion at the edge.
func cfnLambdaMappingTimestamp(value any) (string, error) {
	seconds, err := strconv.ParseFloat(fmt.Sprint(value), 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < -62135596800 || seconds >= 253402300800 {
		return "", fmt.Errorf("StartingPositionTimestamp must be Unix seconds within the RFC3339 range")
	}
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(math.Round(fraction*float64(time.Second)))).UTC().Format(time.RFC3339Nano), nil
}
