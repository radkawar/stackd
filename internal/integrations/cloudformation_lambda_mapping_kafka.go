package integrations

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

// CloudFormation names this endpoint KafkaBootstrapServers, unlike the Lambda
// API's KAFKA_BOOTSTRAP_SERVERS map key. Only the deployment boundary translates it.
type cfnLambdaKafkaSource struct {
	Endpoints *struct {
		KafkaBootstrapServers []string
	}
}

func cfnLambdaMappingKafkaSettings(p cloudformation.Properties, source string) error {
	if source != "self-managed-kafka" {
		if _, present := p["SelfManagedKafkaEventSourceConfig"]; present {
			return fmt.Errorf("SelfManagedKafkaEventSourceConfig requires a self-managed Kafka event source")
		}
	}
	if source != "kafka" {
		if _, present := p["AmazonManagedKafkaEventSourceConfig"]; present {
			return fmt.Errorf("AmazonManagedKafkaEventSourceConfig requires an MSK event source")
		}
	}
	if source != "self-managed-kafka" && source != "kafka" {
		if _, present := p["Topics"]; present {
			return fmt.Errorf("topics require a Kafka event source")
		}
		return nil
	}
	if err := cfnLambdaMappingObject[cfnLambdaKafkaSource](p, "SelfManagedEventSource"); err != nil {
		return err
	}
	if err := cfnLambdaMappingObject[api.SelfManagedKafkaEventSourceConfig](p, "SelfManagedKafkaEventSourceConfig"); err != nil {
		return err
	}
	if err := cfnLambdaMappingObject[api.AmazonManagedKafkaEventSourceConfig](p, "AmazonManagedKafkaEventSourceConfig"); err != nil {
		return err
	}
	if _, err := cfnComputeStringList(p, "Topics"); err != nil {
		return err
	}
	return nil
}

func cfnLambdaMappingKafkaConfig(p cloudformation.Properties) string {
	if _, present := p["SelfManagedEventSource"]; present {
		return "SelfManagedKafkaEventSourceConfig"
	}
	if source, err := arn.Parse(cfnComputeString(p, "EventSourceArn")); err == nil && source.Service == "kafka" {
		return "AmazonManagedKafkaEventSourceConfig"
	}
	return ""
}

func cfnLambdaMappingKafkaGroup(p cloudformation.Properties) string {
	config, _ := cfnComputeObject(p[cfnLambdaMappingKafkaConfig(p)])
	return cfnComputeString(config, "ConsumerGroupId")
}

func cfnLambdaMappingKafkaUpdate(mapping *api.EventSourceMappingConfiguration, p cloudformation.Properties) error {
	if mapping.SelfManagedEventSource == nil && mapping.AmazonManagedKafkaEventSourceConfig == nil {
		return nil
	}
	// Native CloudFormation rejects topic edits during the resource operation.
	// Compare the actual source so compensation can restore an unchanged mapping.
	topics, _ := p["Topics"].([]any)
	if len(topics) != len(mapping.Topics) {
		return fmt.Errorf("parameter 'Topics' cannot be updated")
	}
	for i, topic := range mapping.Topics {
		if topics[i] != string(topic) {
			return fmt.Errorf("parameter 'Topics' cannot be updated")
		}
	}
	return nil
}

func cfnLambdaMappingKafkaUpdateInput(input map[string]any, r cloudformation.ResourceRequest) {
	p := r.Properties
	delete(input, "Topics")
	configName := cfnLambdaMappingKafkaConfig(p)
	delete(input, configName)
	// Native CFN retains access settings when removed and ignores their
	// reintroduction. Edits while the property remains present do apply.
	if _, previous := r.Previous["SourceAccessConfigurations"]; !previous {
		delete(input, "SourceAccessConfigurations")
	}
	// The group identifies a physical incarnation. The replacement planner, not
	// UpdateEventSourceMapping, handles changes including removal of that group.
	config, _ := cfnComputeObject(p[configName])
	if registry, present := config["SchemaRegistryConfig"]; present {
		input[configName] = map[string]any{"SchemaRegistryConfig": registry}
	}
	input["BatchSize"] = cfnComputeDefault(p, "BatchSize", 100)
	input["Enabled"] = cfnComputeDefault(p, "Enabled", true)
	input["FilterCriteria"] = cfnComputeDefault(p, "FilterCriteria", map[string]any{})
	// Unlike Kinesis/DynamoDB, omission retains Kafka's batching window and
	// source-access settings. Never turn the initial 500ms window into zero.
}
