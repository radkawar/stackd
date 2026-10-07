package integrations

import (
	"encoding/json"
	"strings"
	"testing"

	"stackd/internal/services/cloudformation"
)

// CloudFormation properties bind case-insensitively to owner members, coerce
// template strings to modeled scalars, and never silently drop a property.
func TestComputeServiceStrictOwnerBinding(t *testing.T) {
	input, err := cfnCSInput("autoscaling", "CreateAutoScalingGroup", map[string]any{
		"AutoScalingGroupName": "group", "MinSize": "1", "MaxSize": "2", "DefaultCooldown": "300",
		"LaunchTemplate": map[string]any{"LaunchTemplateId": "lt-1", "Version": "$Latest"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if input["MinSize"] != json.Number("1") || input["DefaultCooldown"] != json.Number("300") {
		t.Fatalf("string sizes were not coerced: %#v", input)
	}
	if _, err := cfnCSInput("autoscaling", "CreateAutoScalingGroup", map[string]any{"AutoScalingGroupName": "group", "MinSize": "one"}); err == nil {
		t.Fatal("non-numeric MinSize was admitted")
	}
	if _, err := cfnCSInput("autoscaling", "CreateAutoScalingGroup", map[string]any{"AutoScalingGroupName": "group", "NotificationConfigurations": []any{}}); err == nil || !strings.Contains(err.Error(), "NotificationConfigurations") {
		t.Fatalf("unmodeled property was not rejected: %v", err)
	}
	service, err := cfnCSInput("ecs", "CreateService", map[string]any{
		"ServiceName":          "web",
		"NetworkConfiguration": map[string]any{"AwsvpcConfiguration": map[string]any{"Subnets": []any{"subnet-1"}, "AssignPublicIp": "ENABLED"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	network, _ := service["networkConfiguration"].(map[string]any)
	if _, ok := network["awsvpcConfiguration"].(map[string]any); !ok {
		t.Fatalf("CloudFormation casing did not bind to the ECS member: %#v", service)
	}
	if _, err := cfnCSInput("ecs", "CreateService", map[string]any{"NetworkConfiguration": map[string]any{"Awsvpc": map[string]any{}}}); err == nil {
		t.Fatal("nested unmodeled property was admitted")
	}
}

func TestComputeServiceIdentifiers(t *testing.T) {
	key, policy, err := cfnAASPolicyIdentity("arn:aws:autoscaling:us-east-1:123456789012:scalingPolicy:ab12:resource/ecs/service/cluster/web:policyName/cpu|ecs:service:DesiredCount")
	if err != nil || key.Namespace != "ecs" || key.ResourceID != "service/cluster/web" || key.Dimension != "ecs:service:DesiredCount" || policy != "cpu" {
		t.Fatalf("application auto scaling policy = %+v %q %v", key, policy, err)
	}
	if key.id() != "service/cluster/web|ecs:service:DesiredCount|ecs" {
		t.Fatalf("scalable target Ref = %q", key.id())
	}
	cluster, id, err := cfnEKSPodIdentityARN("arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod/a-abcdefghijklmnop1")
	if err != nil || cluster != "prod" || id != "a-abcdefghijklmnop1" {
		t.Fatalf("pod identity = %q %q %v", cluster, id, err)
	}
	service, clusterName, err := cfnECSServiceIdentity("arn:aws:ecs:us-east-1:123456789012:service/prod/web")
	if err != nil || service != "arn:aws:ecs:us-east-1:123456789012:service/prod/web" || clusterName != "prod" {
		t.Fatalf("ecs service = %q %q %v", service, clusterName, err)
	}
}

// Generated ELB names satisfy the 32 character no-edge-hyphen naming rule.
func TestComputeServiceGeneratedELBName(t *testing.T) {
	r := cloudformation.ResourceRequest{StackID: "stack-id", StackName: "a-", LogicalID: "-", Token: "token", Properties: cloudformation.Properties{}}
	name := cfnELBName(r, "Name")
	if len(name) > 32 || strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") || strings.Contains(name, "--") {
		t.Fatalf("generated ELB name %q", name)
	}
}
