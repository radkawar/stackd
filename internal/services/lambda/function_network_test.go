package lambda

import (
	"context"
	"testing"

	api "stackd/internal/awsapi/lambda"
)

func TestFunctionVpcConfigurationCloningAndProjection(t *testing.T) {
	key := FunctionKey{Scope: Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Name: "network"}
	repository := NewMemoryRepository(nil)
	function := FunctionRecord{Key: key, NetworkIncarnation: "immutable-create-incarnation", VpcConfig: FunctionNetworkConfiguration{VPCID: "vpc-owned", SubnetIDs: []string{"subnet-owned"}, SecurityGroupIDs: []string{"sg-owned"}}}
	if err := repository.Update(t.Context(), func(tx Transaction) error { return tx.PutFunction(function) }); err != nil {
		t.Fatal(err)
	}
	function.VpcConfig.SubnetIDs[0] = "subnet-mutated"
	function.VpcConfig.SecurityGroupIDs[0] = "sg-mutated"
	var retained FunctionRecord
	if err := repository.View(t.Context(), func(r Reader) error { var err error; retained, err = r.Function(key); return err }); err != nil {
		t.Fatal(err)
	}
	if retained.NetworkIncarnation != "immutable-create-incarnation" || retained.VpcConfig.SubnetIDs[0] != "subnet-owned" || retained.VpcConfig.SecurityGroupIDs[0] != "sg-owned" {
		t.Fatal("repository borrowed mutable VPC config or lost incarnation")
	}
	projection := functionVpcConfig(retained)
	if projection.VpcId == nil || string(*projection.VpcId) != "vpc-owned" || projection.Ipv6AllowedForDualStack == nil || bool(*projection.Ipv6AllowedForDualStack) {
		t.Fatal("configuration projection lost authoritative VPC or invented dual stack")
	}
	projection.SubnetIds[0] = api.SubnetId("subnet-response-mutated")
	if retained.VpcConfig.SubnetIDs[0] != "subnet-owned" {
		t.Fatal("API response borrowed deployment network configuration")
	}
}

func TestFunctionVpcAdmissionRejectsUnimplementedAndPartialPlacement(t *testing.T) {
	service := &Service{}
	for _, input := range []*api.VpcConfig{
		{Ipv6AllowedForDualStack: new(api.NullableBoolean(true))},
		{SubnetIds: api.SubnetIds{"subnet-owned"}},
		{SecurityGroupIds: api.SecurityGroupIds{"sg-owned"}},
		{SubnetIds: api.SubnetIds{""}, SecurityGroupIds: api.SecurityGroupIds{"sg-owned"}},
	} {
		function := FunctionRecord{NetworkIncarnation: "original"}
		if rejected := service.configureFunctionNetwork(t.Context(), &function, input); rejected == nil {
			t.Fatalf("unsupported placement admitted: %#v", input)
		}
		if function.NetworkIncarnation != "original" {
			t.Fatal("update replaced immutable function incarnation")
		}
	}
	function := FunctionRecord{NetworkIncarnation: "original", VpcConfig: FunctionNetworkConfiguration{VPCID: "vpc-owned", SubnetIDs: []string{"subnet-owned"}, SecurityGroupIDs: []string{"sg-owned"}}}
	if rejected := service.configureFunctionNetwork(t.Context(), &function, &api.VpcConfig{}); rejected != nil {
		t.Fatal(rejected)
	}
	if function.VpcConfig.VPCID != "" || len(function.VpcConfig.SubnetIDs) != 0 || len(function.VpcConfig.SecurityGroupIDs) != 0 || function.NetworkIncarnation != "original" {
		t.Fatal("explicit detach retained placement or changed incarnation")
	}
}

func TestNonVpcFunctionRecoveryRequiresNoEC2Authority(t *testing.T) {
	if err := (&Service{}).recoverFunctionNetwork(context.Background(), FunctionRecord{NetworkIncarnation: "non-vpc"}); err != nil {
		t.Fatal(err)
	}
}
