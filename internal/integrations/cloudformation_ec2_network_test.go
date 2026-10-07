package integrations

import (
	"database/sql"
	"path/filepath"
	"testing"

	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
)

// These are local behavior regressions, not fabricated native AWS captures.
// All controls below run without an InstanceRuntime or external packet backend.
func TestCloudFormationEC2NetworkOwnersRecoveryAndCurrentState(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			var repo ec2.Repository = ec2.NewMemoryRepository(nil)
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "ec2.sqlite")
			open := func() {
				var err error
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				repo = sqlec2.New(db)
			}
			if backend == "sqlite" {
				open()
				t.Cleanup(func() { _ = db.Close() })
			}
			var owner *ec2.Service
			var commands StepFunctionsCommands
			assemble := func() {
				owner = ec2.New(ec2.Config{Repository: repo})
				commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": owner})
			}
			assemble()
			t.Cleanup(func() { _ = owner.Close() })
			request := func(kind, name string, p cloudformation.Properties) cloudformation.ResourceRequest {
				return cloudformation.ResourceRequest{StackID: "arn:aws:cloudformation:us-east-1:123456789012:stack/networks/owner", StackName: "networks", LogicalID: name, Type: "AWS::EC2::" + kind, Token: name + "-incarnation", Properties: p}
			}
			create := func(h cloudformation.ResourceHandler, r *cloudformation.ResourceRequest) cloudformation.ResourceResult {
				t.Helper()
				out, err := h.Create(ctx, *r)
				if err != nil {
					t.Fatalf("create %s: %v", r.Type, err)
				}
				r.PhysicalID = out.PhysicalID
				return out
			}
			vpc := request("VPC", "VPC", cloudformation.Properties{"CidrBlock": "10.46.0.0/16", "EnableDnsHostnames": true})
			vpcHandler := cfnEC2VPC{commands}
			created := create(vpcHandler, &vpc)
			if created.Ref != vpc.PhysicalID || created.Attributes["VpcId"] != vpc.PhysicalID || cfnComputeString(created.Attributes, "DefaultSecurityGroup") == "" || cfnComputeString(created.Attributes, "DefaultNetworkAcl") == "" {
				t.Fatalf("VPC refs/default owners: %+v", created)
			}
			subnet := request("Subnet", "Subnet", cloudformation.Properties{"VpcId": vpc.PhysicalID, "CidrBlock": "10.46.1.0/24", "MapPublicIpOnLaunch": true})
			subnetHandler := cfnEC2Subnet{commands}
			subnetResult := create(subnetHandler, &subnet)
			if subnetResult.Attributes["SubnetId"] != subnet.PhysicalID || subnetResult.Attributes["VpcId"] != vpc.PhysicalID {
				t.Fatalf("subnet references: %+v", subnetResult)
			}
			gateway := request("InternetGateway", "IGW", cloudformation.Properties{})
			gatewayHandler := cfnEC2InternetGateway{commands}
			create(gatewayHandler, &gateway)
			attach := request("VPCGatewayAttachment", "Attachment", cloudformation.Properties{"VpcId": vpc.PhysicalID, "InternetGatewayId": gateway.PhysicalID})
			attachHandler := cfnEC2GatewayAttachment{commands}
			create(attachHandler, &attach)
			table := request("RouteTable", "Table", cloudformation.Properties{"VpcId": vpc.PhysicalID})
			tableHandler := cfnEC2RouteTable{commands}
			create(tableHandler, &table)
			route := request("Route", "DefaultRoute", cloudformation.Properties{"RouteTableId": table.PhysicalID, "DestinationCidrBlock": "0.0.0.1/0", "GatewayId": gateway.PhysicalID})
			routeHandler := cfnEC2Route{commands}
			create(routeHandler, &route)
			association := request("SubnetRouteTableAssociation", "Association", cloudformation.Properties{"SubnetId": subnet.PhysicalID, "RouteTableId": table.PhysicalID})
			associationHandler := cfnEC2RouteAssociation{commands}
			create(associationHandler, &association)
			if backend == "sqlite" {
				_ = owner.Close()
				_ = db.Close()
				open()
			} else {
				_ = owner.Close()
			}
			assemble()
			vpcHandler = cfnEC2VPC{commands}
			subnetHandler = cfnEC2Subnet{commands}
			gatewayHandler = cfnEC2InternetGateway{commands}
			attachHandler = cfnEC2GatewayAttachment{commands}
			tableHandler = cfnEC2RouteTable{commands}
			routeHandler = cfnEC2Route{commands}
			associationHandler = cfnEC2RouteAssociation{commands}
			for _, item := range []struct {
				h cloudformation.ResourceHandler
				r cloudformation.ResourceRequest
			}{{vpcHandler, vpc}, {subnetHandler, subnet}, {gatewayHandler, gateway}, {attachHandler, attach}, {tableHandler, table}, {routeHandler, route}, {associationHandler, association}} {
				retry := item.r
				retry.PhysicalID = ""
				out, err := item.h.Create(ctx, retry)
				if err != nil || out.PhysicalID != item.r.PhysicalID {
					t.Fatalf("recovery created another %s: %+v %v", item.r.Type, out, err)
				}
			}
			table.Previous = table.Properties
			table.Properties = cloudformation.Properties{"VpcId": vpc.PhysicalID, "Tags": []any{map[string]any{"Key": "changed", "Value": "yes"}}}
			if _, err := tableHandler.Update(ctx, table); err != nil {
				t.Fatal(err)
			}
			live, err := routeHandler.Read(ctx, route)
			if err != nil || live["DestinationCidrBlock"] != "0.0.0.0/0" {
				t.Fatalf("tag update removed edge ownership/canonical live route: %+v %v", live, err)
			}
			foreign := route
			foreign.Token = "foreign-incarnation"
			if err = routeHandler.Delete(ctx, foreign); err == nil {
				t.Fatal("foreign incarnation deleted live route")
			}
			wrongRegion := awsctx.FromContext(ctx)
			wrongRegion.Region = "us-west-2"
			if _, err = vpcHandler.Read(awsctx.WithMetadata(ctx, wrongRegion), vpc); err == nil {
				t.Fatal("cross-region read found another scope's VPC")
			}
			vpc.Previous = vpc.Properties
			vpc.Properties = cloudformation.Properties{"CidrBlock": "10.46.0.0/16", "EnableDnsHostnames": false, "EnableDnsSupport": false}
			if _, err = vpcHandler.Update(ctx, vpc); err != nil {
				t.Fatal(err)
			}
			state, err := vpcHandler.Read(ctx, vpc)
			if err != nil || state["EnableDnsSupport"] != false || state["EnableDnsHostnames"] != false {
				t.Fatalf("read echoed stale template DNS: %+v %v", state, err)
			}
			if err = vpcHandler.Delete(ctx, vpc); err == nil {
				t.Fatal("VPC deletion ignored dependent owner resources")
			}
			for _, item := range []struct {
				h cloudformation.ResourceHandler
				r cloudformation.ResourceRequest
			}{{associationHandler, association}, {routeHandler, route}, {tableHandler, table}, {attachHandler, attach}, {gatewayHandler, gateway}, {subnetHandler, subnet}, {vpcHandler, vpc}} {
				if err = item.h.Delete(ctx, item.r); err != nil {
					t.Fatalf("delete %s: %v", item.r.Type, err)
				}
			}
		})
	}
}

func TestCloudFormationEC2RouteIdentityCanonicalization(t *testing.T) {
	h := cfnEC2Route{}
	before := cloudformation.Properties{"RouteTableId": "rtb-example", "DestinationCidrBlock": "10.10.4.7/24", "GatewayId": "igw-example"}
	after := cloudformation.Properties{"RouteTableId": "rtb-example", "DestinationCidrBlock": "10.10.4.0/24", "GatewayId": "igw-example"}
	if replace, err := h.Replacement(before, after); err != nil || replace {
		t.Fatalf("equivalent route CIDR replaced: %v %v", replace, err)
	}
	if err := h.Validate(cloudformation.Properties{"RouteTableId": "rtb-example", "DestinationCidrBlock": "2001:db8::/64", "GatewayId": "igw-example"}); err == nil {
		t.Fatal("IPv6 CIDR accepted as IPv4 destination")
	}
}

func TestCloudFormationEC2TopOwnersPrivateRecoveryAndMutableCustomerTags(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := cfnEC2RelationsFixture(t, backend)
			rows := []struct {
				kind, operation string
				properties      cloudformation.Properties
			}{
				{"VPC", "CreateVpc", cloudformation.Properties{"CidrBlock": "10.84.0.0/16"}},
				{"Subnet", "CreateSubnet", cloudformation.Properties{"VpcId": f.vpc, "CidrBlock": "10.82.2.0/24"}},
				{"InternetGateway", "CreateInternetGateway", cloudformation.Properties{}},
				{"NatGateway", "CreateNatGateway", cloudformation.Properties{"SubnetId": f.subnet, "ConnectivityType": "private"}},
				{"VPCEndpoint", "CreateVpcEndpoint", cloudformation.Properties{"VpcId": f.vpc, "ServiceName": "com.amazonaws.us-east-1.s3", "VpcEndpointType": "Gateway"}},
				{"NetworkAcl", "CreateNetworkAcl", cloudformation.Properties{"VpcId": f.vpc}},
				{"DHCPOptions", "CreateDhcpOptions", cloudformation.Properties{"DomainName": "private.internal"}},
				{"NetworkInterface", "CreateNetworkInterface", cloudformation.Properties{"SubnetId": f.subnet}},
			}
			for _, row := range rows {
				t.Run(row.kind, func(t *testing.T) {
					r := f.request(row.kind, "private-owner-"+row.kind, row.properties)
					r.Properties["Tags"] = []any{map[string]any{"Key": "stackd:cloudformation:stack-id", "Value": "customer"}, map[string]any{"Key": "stackd:cloudformation:incarnation", "Value": "customer-incarnation"}}
					h := CloudFormationEC2Handlers(f.commands)[r.Type]
					f.owner.operation, f.owner.armed = row.operation, true
					if _, err := h.Create(f.ctx, r); err == nil {
						t.Fatal("interrupted native admission returned success")
					}
					f.reopen()
					h = CloudFormationEC2Handlers(f.commands)[r.Type]
					recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
					if err != nil || recovered.PhysicalID == "" {
						t.Fatalf("exact receipt recovery: %+v %v", recovered, err)
					}
					r.PhysicalID = recovered.PhysicalID
					mismatched := r
					mismatched.PhysicalID = "foreign-" + r.PhysicalID
					if out, err := h.Create(f.ctx, mismatched); err == nil || out.PhysicalID != "" {
						t.Fatalf("create silently replaced supplied physical identity: %+v %v", out, err)
					}
					if out, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, mismatched); err == nil || out.PhysicalID != "" {
						t.Fatalf("recovery silently replaced supplied physical identity: %+v %v", out, err)
					}
					reader := h.(cloudformation.ResourceReader)
					p, err := reader.Read(f.ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					projected, ok := p["Tags"].([]map[string]string)
					tags := map[string]string{}
					for _, tag := range projected {
						tags[tag["Key"]] = tag["Value"]
					}
					if !ok || len(tags) != 2 || tags["stackd:cloudformation:stack-id"] != "customer" || tags["stackd:cloudformation:incarnation"] != "customer-incarnation" {
						t.Fatalf("customer marker-key projection or emitted owner markers: %#v", p["Tags"])
					}
					if err := cfnComputeRun(f.ctx, f.commands, "ec2", "DeleteTags", map[string]any{"Resources": []string{r.PhysicalID}, "Tags": []map[string]any{{"Key": "stackd:cloudformation:stack-id"}, {"Key": "stackd:cloudformation:incarnation"}}}); err != nil {
						t.Fatal(err)
					}
					if _, err := reader.Read(f.ctx, r); err != nil {
						t.Fatalf("public tag removal lost private ownership: %v", err)
					}
					listRequest := r
					listRequest.PhysicalID = ""
					if listed, err := reader.List(f.ctx, listRequest); err != nil || len(listed) != 1 || listed[0].Identifier != r.PhysicalID {
						t.Fatalf("list did not observe actual native row ID: %+v %v", listed, err)
					}
					foreign := r
					foreign.Token = "forged-incarnation"
					if err := cfnComputeRun(f.ctx, f.commands, "ec2", "CreateTags", map[string]any{"Resources": []string{r.PhysicalID}, "Tags": cfnComputeTagList(cfnComputeOwnedTags(foreign))}); err != nil {
						t.Fatal(err)
					}
					if _, err := reader.Read(f.ctx, foreign); err == nil {
						t.Fatal("forged public tags authorized foreign read")
					}
					if _, err := h.Create(f.ctx, foreign); err == nil {
						t.Fatal("supplied foreign ID was adopted")
					}
					if err := h.Delete(f.ctx, foreign); err == nil {
						t.Fatal("forged public tags authorized foreign deletion")
					}
					foreign.PhysicalID = ""
					if listed, err := reader.List(f.ctx, foreign); err != nil || len(listed) != 0 {
						t.Fatalf("list trusted forged public markers: %+v %v", listed, err)
					}
					replayed, err := h.Create(f.ctx, r)
					if err != nil || replayed.PhysicalID != r.PhysicalID {
						t.Fatalf("private replay changed row: %+v %v", replayed, err)
					}
					if err := h.Delete(f.ctx, r); err != nil {
						t.Fatal(err)
					}
					if _, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err == nil {
						t.Fatal("deleted incarnation recovered as live")
					}
				})
			}
		})
	}
}
