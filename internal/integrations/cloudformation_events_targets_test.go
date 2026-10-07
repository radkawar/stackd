package integrations

import (
	"encoding/json"
	"testing"

	api "stackd/internal/awsapi/eventbridge"
)

func TestCloudFormationRuleTargetsPreserveInputAndMapECSParameters(t *testing.T) {
	input := " {\n  \"message\": \"héllo\\nworld\"\n} "
	properties := map[string]any{"Targets": []any{
		map[string]any{"Id": "ecs", "Arn": "arn:aws:ecs:us-east-1:123456789012:cluster/worker", "Input": input, "EcsParameters": map[string]any{
			"TaskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/worker:1",
			"TaskCount":         2, "EnableECSManagedTags": true, "EnableExecuteCommand": true,
			"PlacementStrategies":  []any{map[string]any{"Type": "spread", "Field": "attribute:ecs.availability-zone"}},
			"TagList":              []any{map[string]any{"Key": "team", "Value": "operations"}},
			"NetworkConfiguration": map[string]any{"AwsVpcConfiguration": map[string]any{"Subnets": []any{"subnet-one"}, "SecurityGroups": []any{"sg-one"}, "AssignPublicIp": "DISABLED"}},
		}},
		map[string]any{"Id": "stream", "Arn": "arn:aws:kinesis:us-east-1:123456789012:stream/worker", "KinesisParameters": map[string]any{"PartitionKeyPath": "$.detail.account"}},
	}}
	before, err := json.Marshal(properties)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := cfnEventRuleTargets(properties)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	var native []api.Target
	if err := json.Unmarshal(encoded, &native); err != nil {
		t.Fatal(err)
	}
	if len(native) != 2 || cfnComputeValue(native[0].Input) != input {
		t.Fatalf("constant input changed: %#v", native)
	}
	ecs := native[0].EcsParameters
	if ecs == nil || len(ecs.PlacementStrategy) != 1 || cfnComputeValue(ecs.PlacementStrategy[0].Field) != "attribute:ecs.availability-zone" || len(ecs.Tags) != 1 || cfnComputeValue(ecs.Tags[0].Value) != "operations" {
		t.Fatalf("ECS native parameter mapping lost configuration: %#v", ecs)
	}
	if ecs.TaskCount == nil || *ecs.TaskCount != 2 || ecs.EnableECSManagedTags == nil || !*ecs.EnableECSManagedTags || ecs.EnableExecuteCommand == nil || !*ecs.EnableExecuteCommand {
		t.Fatalf("ECS scalar parameters lost: %#v", ecs)
	}
	if ecs.NetworkConfiguration == nil || ecs.NetworkConfiguration.AwsvpcConfiguration == nil || len(ecs.NetworkConfiguration.AwsvpcConfiguration.Subnets) != 1 || string(ecs.NetworkConfiguration.AwsvpcConfiguration.Subnets[0]) != "subnet-one" {
		t.Fatalf("ECS network parameters lost: %#v", ecs.NetworkConfiguration)
	}
	if native[1].KinesisParameters == nil || cfnComputeValue(native[1].KinesisParameters.PartitionKeyPath) != "$.detail.account" {
		t.Fatalf("Kinesis partition key mapping lost: %#v", native[1])
	}
	after, err := json.Marshal(properties)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("target conversion mutated the desired CloudFormation model")
	}
}
