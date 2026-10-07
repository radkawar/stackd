package integrations

import (
	"context"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

func TestCFNEC2InstanceCreditRemovalAfterNonburstResize(t *testing.T) {
	commands := cfnEC2ComputeTestCommands(func(context.Context, awsapi.DecodedRequest) (any, *awswire.Error) {
		t.Fatal("removing credits from a nonburstable native instance issued an inapplicable credit command")
		return nil, nil
	})
	r := cfnEC2ComputeTestRequest("AWS::EC2::Instance")
	r.PhysicalID = "i-00000000000000001"
	r.Previous = cloudformation.Properties{"InstanceType": "t3.micro", "CreditSpecification": map[string]any{"CPUCredits": "standard"}}
	r.Properties = cloudformation.Properties{"InstanceType": "m1.small"}
	live := api.Instance{InstanceId: new(api.String(r.PhysicalID)), InstanceType: new(api.InstanceType("m1.small"))}
	if err := (cfnEC2Instance{commands}).liveAttributes(t.Context(), r, live); err != nil {
		t.Fatal(err)
	}
}
