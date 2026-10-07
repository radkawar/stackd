package integrations

import (
	"testing"

	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
)

func TestCloudFormationEC2GatewayInPlaceMigrationAndDeleteReplay(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	owner := ec2.New(ec2.Config{})
	t.Cleanup(func() { _ = owner.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": owner})
	request := func(kind, name string, p cloudformation.Properties) cloudformation.ResourceRequest {
		return cloudformation.ResourceRequest{StackID: "stack-network", StackName: "network", LogicalID: name, Type: "AWS::EC2::" + kind, Token: name + "-token", Properties: p}
	}
	vpc := request("VPC", "VPC", cloudformation.Properties{"CidrBlock": "10.58.0.0/16"})
	out, err := (cfnEC2VPC{commands}).Create(ctx, vpc)
	if err != nil {
		t.Fatal(err)
	}
	vpc.PhysicalID = out.PhysicalID
	gatewayHandler := cfnEC2InternetGateway{commands}
	first := request("InternetGateway", "First", cloudformation.Properties{})
	out, err = gatewayHandler.Create(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	first.PhysicalID = out.PhysicalID
	second := request("InternetGateway", "Second", cloudformation.Properties{})
	out, err = gatewayHandler.Create(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	second.PhysicalID = out.PhysicalID
	attachment := request("VPCGatewayAttachment", "Attachment", cloudformation.Properties{"VpcId": vpc.PhysicalID, "InternetGatewayId": first.PhysicalID})
	h := cfnEC2GatewayAttachment{commands}
	out, err = h.Create(ctx, attachment)
	if err != nil {
		t.Fatal(err)
	}
	attachment.PhysicalID = out.PhysicalID
	attachment.Previous = attachment.Properties
	attachment.Properties = cloudformation.Properties{"VpcId": vpc.PhysicalID, "InternetGatewayId": second.PhysicalID}
	if replace, err := h.Replacement(attachment.Previous, attachment.Properties); err != nil || replace {
		t.Fatalf("IGW change is not an in-place attachment update: %v %v", replace, err)
	}
	for range 2 {
		updated, err := h.Update(ctx, attachment)
		if err != nil || updated.PhysicalID != attachment.PhysicalID {
			t.Fatalf("gateway migration/recovery lost physical incarnation: %+v %v", updated, err)
		}
	}
	live, err := h.Read(ctx, attachment)
	if err != nil || live["InternetGatewayId"] != second.PhysicalID {
		t.Fatalf("read used old gateway deployment snapshot: %+v %v", live, err)
	}
	for i := range 2 {
		if err = h.Delete(ctx, attachment); err != nil {
			t.Fatalf("delete replay %d: %v", i, err)
		}
	}
}

func TestCloudControlEC2EdgeCreateCannotAdoptExistingRoute(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	owner := ec2.New(ec2.Config{})
	t.Cleanup(func() { _ = owner.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": owner})
	vpc := cloudformation.ResourceRequest{StackID: "stack-edge", StackName: "edge", LogicalID: "VPC", Type: "AWS::EC2::VPC", Token: "vpc-token", Properties: cloudformation.Properties{"CidrBlock": "10.59.0.0/16"}}
	v, err := (cfnEC2VPC{commands}).Create(ctx, vpc)
	if err != nil {
		t.Fatal(err)
	}
	gateway := vpc
	gateway.Type = "AWS::EC2::InternetGateway"
	gateway.LogicalID = "IGW"
	gateway.Token = "igw-token"
	gateway.Properties = cloudformation.Properties{}
	g, err := (cfnEC2InternetGateway{commands}).Create(ctx, gateway)
	if err != nil {
		t.Fatal(err)
	}
	attach := vpc
	attach.Type = "AWS::EC2::VPCGatewayAttachment"
	attach.LogicalID = "Attachment"
	attach.Token = "attach-token"
	attach.Properties = cloudformation.Properties{"VpcId": v.Ref, "InternetGatewayId": g.Ref}
	if _, err = (cfnEC2GatewayAttachment{commands}).Create(ctx, attach); err != nil {
		t.Fatal(err)
	}
	table := vpc
	table.Type = "AWS::EC2::RouteTable"
	table.LogicalID = "Routes"
	table.Token = "table-token"
	table.Properties = cloudformation.Properties{"VpcId": v.Ref}
	rtb, err := (cfnEC2RouteTable{commands}).Create(ctx, table)
	if err != nil {
		t.Fatal(err)
	}
	if err = cfnComputeRun(ctx, commands, "ec2", "CreateRoute", map[string]any{"RouteTableId": rtb.Ref, "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": g.Ref}); err != nil {
		t.Fatal(err)
	}
	route := cloudformation.ResourceRequest{StackID: "cloudcontrol-create", LogicalID: "Resource", Type: "AWS::EC2::Route", Token: "direct-create", CloudControl: true, Properties: cloudformation.Properties{"RouteTableId": rtb.Ref, "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": g.Ref}}
	if _, err = (cfnEC2Route{commands}).Create(ctx, route); err == nil {
		t.Fatal("Cloud Control create adopted an unrelated existing route")
	}
}

func TestCloudControlRoutePrivateAdmissionRecoversCompositeIdentifier(t *testing.T) {
	f := cfnEC2RelationsFixture(t, "memory")
	r := f.request("Route", "cloudcontrol-route", cloudformation.Properties{"RouteTableId": f.table, "DestinationCidrBlock": "192.0.2.7/24", "GatewayId": f.routeGateway})
	r.CloudControl = true
	h := cfnEC2Route{f.commands}
	f.owner.operation, f.owner.armed = "CreateRoute", true
	admitted, err := h.Create(f.ctx, r)
	if err == nil || admitted.PhysicalID == "" {
		t.Fatalf("lost response forgot native route: %+v %v", admitted, err)
	}
	want := cfnEC2PairID(r, f.table, "192.0.2.0/24", "RouteTableId", "CidrBlock")
	if admitted.PhysicalID != want {
		t.Fatalf("receipt escaped composite identifier: %+v want=%q", admitted, want)
	}
	recovered, err := h.RecoverCreation(f.ctx, r)
	if err != nil || recovered.PhysicalID != want {
		t.Fatalf("exact CloudControl recovery: %+v %v", recovered, err)
	}
	replayed, err := h.Create(f.ctx, r)
	if err != nil || replayed.PhysicalID != want {
		t.Fatalf("same-token CloudControl replay: %+v %v", replayed, err)
	}
	r.PhysicalID = want
	if err := h.Delete(f.ctx, r); err != nil {
		t.Fatal(err)
	}
}
