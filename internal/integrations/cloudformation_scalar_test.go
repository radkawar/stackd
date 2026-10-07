package integrations

import (
	"maps"
	"strings"
	"testing"
	"time"

	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
)

func TestCFNSecurityGroupNumericProtocolLifecycle(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	owner := ec2.New(ec2.Config{Repository: ec2.NewMemoryRepository(nil)})
	t.Cleanup(func() { _ = owner.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": owner})
	request := func(kind, name string, properties cloudformation.Properties) cloudformation.ResourceRequest {
		return cloudformation.ResourceRequest{StackID: "stack-scalars", StackName: "scalars", LogicalID: name, Type: "AWS::EC2::" + kind, Token: name + "-incarnation", Properties: properties}
	}
	vpcRequest := request("VPC", "VPC", cloudformation.Properties{"CidrBlock": "10.90.0.0/16"})
	vpc, err := (cfnEC2VPC{commands}).Create(ctx, vpcRequest)
	if err != nil {
		t.Fatal(err)
	}
	h := cfnEC2SecurityGroup{commands}
	r := request("SecurityGroup", "Group", cloudformation.Properties{"VpcId": vpc.PhysicalID, "GroupDescription": "numeric YAML protocol", "SecurityGroupIngress": []any{map[string]any{"IpProtocol": -1, "CidrIp": "10.90.0.0/16"}}, "SecurityGroupEgress": []any{map[string]any{"IpProtocol": float64(-1), "CidrIp": "0.0.0.0/0"}}})
	created, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = created.PhysicalID
	live, err := h.Read(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"SecurityGroupIngress", "SecurityGroupEgress"} {
		rules, ok := live[key].([]any)
		if !ok || len(rules) != 1 || rules[0].(cloudformation.Properties)["IpProtocol"] != "-1" {
			t.Fatalf("%s did not persist numeric YAML protocol: %+v", key, live[key])
		}
	}
	// Numeric and string representations must identify the same native rule.
	r.Previous = r.Properties
	r.Properties = maps.Clone(r.Properties)
	r.Properties["SecurityGroupIngress"] = []any{map[string]any{"IpProtocol": "-1", "CidrIp": "10.90.0.0/16"}}
	if _, err := h.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	rule := request("SecurityGroupIngress", "Rule", cloudformation.Properties{"GroupId": r.PhysicalID, "IpProtocol": -1, "CidrIp": "192.0.2.0/24"})
	ruleHandler := cfnEC2SecurityRule{commands: commands}
	result, err := ruleHandler.Create(ctx, rule)
	if err != nil {
		t.Fatal(err)
	}
	rule.PhysicalID = result.PhysicalID
	if err := ruleHandler.Delete(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if err := h.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{nil, true, []any{-1}, map[string]any{"value": -1}} {
		if err := cfnEC2SecurityRuleValidate(map[string]any{"IpProtocol": value, "CidrIp": "0.0.0.0/0"}, false, true); err == nil {
			t.Fatalf("IpProtocol accepted non-string/non-number %T", value)
		}
	}
}

func TestCFNMappingNumberParameterStringsReachNativeOwner(t *testing.T) {
	f, sources, _ := cfnLambdaMappingNativeFixture(t, "memory")
	h := cfnLambdaMapping{f.commands}
	r := cfnLambdaAdditionalRequest("AWS::Lambda::EventSourceMapping", cloudformation.Properties{"FunctionName": "configured", "EventSourceArn": sources[0], "Enabled": false, "MaximumBatchingWindowInSeconds": "3", "ScalingConfig": map[string]any{"MaximumConcurrency": "2"}})
	created, err := h.Create(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = created.PhysicalID
	record := cfnLambdaMappingNativeRecord(t, f, r.PhysicalID)
	if record.Settings.BatchingWindow != 3*time.Second || record.Settings.MaximumConcurrency == nil || *record.Settings.MaximumConcurrency != 2 {
		t.Fatalf("number parameter refs did not reach native owner: %+v", record.Settings)
	}
	r.Previous = r.Properties
	r.Properties = maps.Clone(r.Properties)
	r.Properties["MaximumBatchingWindowInSeconds"] = "7"
	if _, err := h.Update(f.ctx, r); err != nil {
		t.Fatal(err)
	}
	if ready, err := h.Stabilize(f.ctx, r); ready || err != nil {
		t.Fatalf("native mapping update admission: %v %v", ready, err)
	}
	if ready, err := h.Stabilize(f.ctx, r); !ready || err != nil {
		t.Fatalf("disabled native mapping did not converge: %v %v", ready, err)
	}
	if got := cfnLambdaMappingNativeRecord(t, f, r.PhysicalID).Settings.BatchingWindow; got != 7*time.Second {
		t.Fatalf("updated parameter ref was not normalized: %v", got)
	}
	for _, value := range []any{"nope", "1.5", "301", "2147483648", true, []any{3}} {
		r.Properties = maps.Clone(r.Properties)
		r.Properties["MaximumBatchingWindowInSeconds"] = value
		_, err := h.Update(f.ctx, r)
		if err == nil {
			_, err = h.Stabilize(f.ctx, r)
		}
		if err == nil || !strings.Contains(err.Error(), "MaximumBatchingWindowInSeconds") {
			t.Fatalf("invalid parameter %v did not produce a property validation error: %v", value, err)
		}
		if got := cfnLambdaMappingNativeRecord(t, f, r.PhysicalID).Settings.BatchingWindow; got != 7*time.Second {
			t.Fatalf("invalid parameter mutated native owner: %v", got)
		}
	}
}
