package integrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"stackd/internal/awsapi"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
)

type cfnEC2LostAssociationResponse struct {
	*ec2.Service
	operation  string
	armed      bool
	rejectTags bool
}

func (o *cfnEC2LostAssociationResponse) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	if o.rejectTags && (string(r.Operation.Name) == "CreateTags" || string(r.Operation.Name) == "DeleteTags") {
		return nil, &awswire.Error{Code: "UnauthorizedOperation", Message: "relation lifecycle must not mutate customer tags", StatusCode: 403}
	}
	out, err := o.Service.ExecuteCommand(ctx, r)
	if err == nil && o.armed && string(r.Operation.Name) == o.operation {
		o.armed = false
		return nil, &awswire.Error{Code: "InvalidParameterValue", Message: "response interrupted after native admission", StatusCode: 400}
	}
	return out, err
}

type cfnEC2RelationFixture struct {
	ctx                                                                            context.Context
	commands                                                                       StepFunctionsCommands
	owner                                                                          *cfnEC2LostAssociationResponse
	vpc, subnet, table, acl, dhcp, address, eni, gateway, gatewayVpc, routeGateway string
	reopen                                                                         func()
}

func cfnEC2RelationsFixture(t *testing.T, backend string) *cfnEC2RelationFixture {
	t.Helper()
	f := &cfnEC2RelationFixture{ctx: awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})}
	var repository ec2.Repository = ec2.NewMemoryRepository(nil)
	var db *sql.DB
	path := filepath.Join(t.TempDir(), "relations.sqlite")
	open := func() {
		if backend == "sqlite" {
			var err error
			db, err = sqlite.Open(f.ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			repository = sqlec2.New(db)
		}
		f.owner = &cfnEC2LostAssociationResponse{Service: ec2.New(ec2.Config{Repository: repository})}
		f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": f.owner})
	}
	open()
	t.Cleanup(func() {
		_ = f.owner.Close()
		if db != nil {
			_ = db.Close()
		}
	})
	f.reopen = func() {
		_ = f.owner.Close()
		if db != nil {
			_ = db.Close()
		}
		open()
	}
	create := func(kind, name string, p cloudformation.Properties) string {
		t.Helper()
		r := cloudformation.ResourceRequest{StackID: "stack-relations", StackName: "relations", LogicalID: name, Type: "AWS::EC2::" + kind, Token: name + "-token", Properties: p}
		h := CloudFormationEC2Handlers(f.commands)[r.Type]
		out, err := h.Create(f.ctx, r)
		if err != nil {
			t.Fatalf("fixture %s: %v", kind, err)
		}
		return out.PhysicalID
	}
	f.vpc = create("VPC", "VPC", cloudformation.Properties{"CidrBlock": "10.82.0.0/16"})
	f.subnet = create("Subnet", "Subnet", cloudformation.Properties{"VpcId": f.vpc, "CidrBlock": "10.82.1.0/24"})
	f.table = create("RouteTable", "Table", cloudformation.Properties{"VpcId": f.vpc})
	f.acl = create("NetworkAcl", "ACL", cloudformation.Properties{"VpcId": f.vpc})
	f.dhcp = create("DHCPOptions", "DHCP", cloudformation.Properties{"DomainName": "relations.internal"})
	f.address = create("EIP", "Address", cloudformation.Properties{"Domain": "vpc"})
	f.eni = create("NetworkInterface", "Interface", cloudformation.Properties{"SubnetId": f.subnet})
	gateway := create("InternetGateway", "Gateway", cloudformation.Properties{})
	f.routeGateway = gateway
	create("VPCGatewayAttachment", "GatewayAttachment", cloudformation.Properties{"VpcId": f.vpc, "InternetGatewayId": gateway})
	f.gatewayVpc = create("VPC", "ExclusiveGatewayVPC", cloudformation.Properties{"CidrBlock": "10.83.0.0/16"})
	f.gateway = create("InternetGateway", "ExclusiveGateway", cloudformation.Properties{})
	return f
}
func (f *cfnEC2RelationFixture) requests() []struct {
	kind, operation string
	valid, rejected cloudformation.Properties
} {
	return []struct {
		kind, operation string
		valid, rejected cloudformation.Properties
	}{
		{"Route", "CreateRoute", cloudformation.Properties{"RouteTableId": f.table, "DestinationCidrBlock": "192.0.2.7/24", "GatewayId": f.routeGateway}, cloudformation.Properties{"RouteTableId": f.table, "DestinationCidrBlock": "192.0.2.7/24", "GatewayId": "igw-0000000000000ffff"}},
		{"SubnetRouteTableAssociation", "AssociateRouteTable", cloudformation.Properties{"SubnetId": f.subnet, "RouteTableId": f.table}, cloudformation.Properties{"SubnetId": f.subnet, "RouteTableId": "rtb-0000000000000ffff"}},
		{"NetworkAclEntry", "CreateNetworkAclEntry", cloudformation.Properties{"NetworkAclId": f.acl, "RuleNumber": 100, "Protocol": -1, "RuleAction": "allow", "CidrBlock": "10.82.0.0/16"}, cloudformation.Properties{"NetworkAclId": f.acl, "RuleNumber": 100, "Protocol": -1, "RuleAction": "invalid", "CidrBlock": "10.82.0.0/16"}},
		{"SubnetNetworkAclAssociation", "ReplaceNetworkAclAssociation", cloudformation.Properties{"SubnetId": f.subnet, "NetworkAclId": f.acl}, cloudformation.Properties{"SubnetId": f.subnet, "NetworkAclId": "acl-0000000000000ffff"}},
		{"VPCDHCPOptionsAssociation", "AssociateDhcpOptions", cloudformation.Properties{"VpcId": f.vpc, "DhcpOptionsId": f.dhcp}, cloudformation.Properties{"VpcId": f.vpc, "DhcpOptionsId": "dopt-0000000000000ffff"}},
		{"EIPAssociation", "AssociateAddress", cloudformation.Properties{"AllocationId": f.address, "NetworkInterfaceId": f.eni}, cloudformation.Properties{"AllocationId": f.address, "NetworkInterfaceId": "eni-0000000000000ffff"}},
		{"VPCGatewayAttachment", "AttachInternetGateway", cloudformation.Properties{"VpcId": f.gatewayVpc, "InternetGatewayId": f.gateway}, cloudformation.Properties{"VpcId": "vpc-0000000000000ffff", "InternetGatewayId": f.gateway}},
	}
}
func (f *cfnEC2RelationFixture) request(kind, token string, p cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{StackID: "stack-relations", StackName: "relations", LogicalID: kind, Type: "AWS::EC2::" + kind, Token: token, Properties: p}
}

func TestEC2ExclusiveRejectedReplacementAllowsFreshRollbackOwner(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := cfnEC2RelationsFixture(t, backend)
			for _, row := range f.requests() {
				t.Run(row.kind, func(t *testing.T) {
					h := CloudFormationEC2Handlers(f.commands)["AWS::EC2::"+row.kind]
					original := f.request(row.kind, "original-incarnation", row.valid)
					out, err := h.Create(f.ctx, original)
					if err != nil {
						t.Fatal(err)
					}
					original.PhysicalID = out.PhysicalID
					if err := h.Delete(f.ctx, original); err != nil {
						t.Fatal(err)
					}
					replacement := f.request(row.kind, "rejected-incarnation", row.rejected)
					failed, err := h.Create(f.ctx, replacement)
					if err == nil || failed.PhysicalID != "" {
						t.Fatalf("native rejection was accepted or invented identity: %+v %v", failed, err)
					}
					if recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, replacement); !cfnEC2Missing(err) || recovered.PhysicalID != "" {
						t.Fatalf("rejected creation did not certify cleaned nonadmission: %+v %v", recovered, err)
					}
					restored := f.request(row.kind, "fresh-rollback-incarnation", row.valid)
					out, err = h.Create(f.ctx, restored)
					if err != nil || out.PhysicalID == "" {
						t.Fatalf("rejected claim blocked actual fresh rollback owner: %+v %v", out, err)
					}
					restored.PhysicalID = out.PhysicalID
					if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, restored); err != nil {
						t.Fatal(err)
					}
					if err := h.Delete(f.ctx, original); err == nil && (row.kind == "Route" || row.kind == "NetworkAclEntry" || row.kind == "VPCDHCPOptionsAssociation" || row.kind == "VPCGatewayAttachment") {
						t.Fatal("old incarnation deleted restored same-identifier native relation")
					}
					if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, restored); err != nil {
						t.Fatalf("old rollback cleanup damaged fresh native owner: %v", err)
					}
					if err := h.Delete(f.ctx, restored); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestEC2ExclusiveModeledFailureRetainsRealAdmissionAcrossRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := cfnEC2RelationsFixture(t, backend)
			for _, row := range f.requests() {
				t.Run(row.kind, func(t *testing.T) {
					r := f.request(row.kind, "interrupted-incarnation", row.valid)
					h := CloudFormationEC2Handlers(f.commands)[r.Type]
					f.owner.operation, f.owner.armed = row.operation, true
					admitted, err := h.Create(f.ctx, r)
					if err == nil || admitted.PhysicalID == "" {
						t.Fatalf("modeled response loss forgot real native admission: %+v %v", admitted, err)
					}
					f.reopen()
					h = CloudFormationEC2Handlers(f.commands)[r.Type]
					recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
					if err != nil || recovered.PhysicalID != admitted.PhysicalID {
						t.Fatalf("native admission receipt did not survive restart: %+v %v", recovered, err)
					}
					replayed, err := h.Create(f.ctx, r)
					if err != nil || replayed.PhysicalID != admitted.PhysicalID {
						t.Fatalf("same-token replay replaced admitted incarnation: %+v %v", replayed, err)
					}
					r.PhysicalID = admitted.PhysicalID
					empty := r
					empty.PhysicalID = ""
					if err := h.Delete(f.ctx, empty); err == nil {
						t.Fatal("empty-ID deletion did not fail closed")
					}
					if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, r); err != nil {
						t.Fatalf("empty-ID deletion changed admitted owner: %v", err)
					}
					if err := h.Delete(f.ctx, r); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestEC2ExclusiveMutableTagsCannotForgePrivateNativeIncarnation(t *testing.T) {
	f := cfnEC2RelationsFixture(t, "memory")
	for _, row := range f.requests() {
		if row.kind != "Route" && row.kind != "NetworkAclEntry" && row.kind != "VPCDHCPOptionsAssociation" && row.kind != "VPCGatewayAttachment" {
			continue
		}
		t.Run(row.kind, func(t *testing.T) {
			r := f.request(row.kind, "admitted-incarnation", row.valid)
			h := CloudFormationEC2Handlers(f.commands)[r.Type]
			out, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = out.PhysicalID
			switch row.kind {
			case "Route":
				if err := cfnComputeRun(f.ctx, f.commands, "ec2", "ReplaceRoute", (cfnEC2Route{f.commands}).input(row.valid)); err != nil {
					t.Fatal(err)
				}
			case "NetworkAclEntry":
				if err := cfnComputeRun(f.ctx, f.commands, "ec2", "ReplaceNetworkAclEntry", cfnEC2AncillaryEntryInput(row.valid)); err != nil {
					t.Fatal(err)
				}
			case "VPCDHCPOptionsAssociation":
				if err := cfnComputeRun(f.ctx, f.commands, "ec2", "AssociateDhcpOptions", cfnComputeCopy(row.valid, "VpcId", "DhcpOptionsId")); err != nil {
					t.Fatal(err)
				}
			case "VPCGatewayAttachment":
				for _, operation := range []string{"DetachInternetGateway", "AttachInternetGateway"} {
					if err := cfnComputeRun(f.ctx, f.commands, "ec2", operation, cfnComputeCopy(row.valid, "VpcId", "InternetGatewayId")); err != nil {
						t.Fatal(err)
					}
				}
			}
			forged := r
			forged.Token = "forged-incarnation"
			parent, slot := f.gateway, f.gateway
			if row.kind == "Route" {
				destination, _ := cfnEC2RouteDestination(r.Properties)
				parent = f.table
				slot = f.table + "|" + destination
			} else if row.kind != "VPCGatewayAttachment" {
				var err error
				parent, slot, _, _, err = (cfnEC2AncillaryRelation{f.commands, row.kind}).snapshot(f.ctx, r)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := cfnComputeRun(f.ctx, f.commands, "ec2", "CreateTags", map[string]any{"Resources": []string{parent}, "Tags": []map[string]string{{"Key": cfnComputeTagPrefix + "edge-" + cfnComputeHash(forged.Type+"/"+slot), "Value": forged.StackID + "/" + forged.LogicalID + "/" + forged.Token}}}); err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(f.ctx, forged); err == nil {
				t.Fatal("forged public claim deleted foreign native state")
			}
			if adopted, err := h.Create(f.ctx, forged); err == nil || adopted.PhysicalID != "" {
				t.Fatalf("forged public claim adopted an independent native relation: %+v %v", adopted, err)
			}
			if err := h.Delete(f.ctx, r); err == nil {
				t.Fatal("stale exact public claim deleted directly mutated native state")
			}
			if recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r); err == nil || cfnEC2Missing(err) || recovered.PhysicalID != r.PhysicalID {
				t.Fatalf("foreign identical native replacement was adopted or falsely absent: %+v %v", recovered, err)
			}
			direct := r
			direct.CloudControl = true
			if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, direct); err != nil {
				t.Fatalf("foreign native edge was damaged: %v", err)
			}
		})
	}
}

func TestEC2ExclusiveDependencyObservationFailureRetainsAdmissionWithoutCertifyingAbsence(t *testing.T) {
	f := cfnEC2RelationsFixture(t, "memory")
	for _, row := range f.requests() {
		t.Run(row.kind, func(t *testing.T) {
			r := f.request(row.kind, "admitted-incarnation", row.valid)
			h := CloudFormationEC2Handlers(f.commands)[r.Type]
			admitted, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = admitted.PhysicalID
			missing := r
			missing.PhysicalID = ""
			missing.Properties = cloudformation.Properties{}
			for key, value := range r.Properties {
				missing.Properties[key] = value
			}
			switch row.kind {
			case "Route":
				missing.Properties["RouteTableId"] = "rtb-0000000000000ffff"
			case "SubnetRouteTableAssociation", "SubnetNetworkAclAssociation":
				missing.Properties["SubnetId"] = "subnet-0000000000000ffff"
			case "NetworkAclEntry":
				missing.Properties["NetworkAclId"] = "acl-0000000000000ffff"
			case "VPCDHCPOptionsAssociation":
				missing.Properties["VpcId"] = "vpc-0000000000000ffff"
			case "EIPAssociation":
				missing.Properties["AllocationId"] = "eipalloc-0000000000000ffff"
			case "VPCGatewayAttachment":
				missing.Properties["InternetGatewayId"] = "igw-0000000000000ffff"
			}
			recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, missing)
			if err == nil || cfnEC2Missing(err) || recovered.PhysicalID != admitted.PhysicalID {
				t.Fatalf("dependency absence forgot admission or certified nonadmission: %+v %v", recovered, err)
			}
			replayed, err := h.Create(f.ctx, missing)
			if err == nil || replayed.PhysicalID != admitted.PhysicalID {
				t.Fatalf("same-token rejected convergence lost authentic ID: %+v %v", replayed, err)
			}
			missing.Token = "never-admitted-incarnation"
			if recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, missing); err == nil || cfnEC2Missing(err) || recovered.PhysicalID != "" {
				t.Fatalf("missing dependency was treated as nonadmission proof: %+v %v", recovered, err)
			}
			if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, r); err != nil {
				t.Fatalf("recovery altered real admitted relation: %v", err)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEC2GatewayInPlaceMigrationRecoversPrivateOwnerAfterResponseLoss(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := cfnEC2RelationsFixture(t, backend)
			r := f.request("VPCGatewayAttachment", "gateway-incarnation", cloudformation.Properties{"VpcId": f.gatewayVpc, "InternetGatewayId": f.gateway})
			h := cfnEC2GatewayAttachment{f.commands}
			created, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			nextRequest := f.request("InternetGateway", "destination-gateway", cloudformation.Properties{})
			nextRequest.LogicalID = "DestinationGateway"
			next, err := (cfnEC2InternetGateway{f.commands}).Create(f.ctx, nextRequest)
			if err != nil {
				t.Fatal(err)
			}
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"VpcId": f.gatewayVpc, "InternetGatewayId": next.PhysicalID}
			f.owner.operation, f.owner.armed = "AttachInternetGateway", true
			migrated, err := h.Update(f.ctx, r)
			if err == nil || migrated.PhysicalID != created.PhysicalID {
				t.Fatalf("in-place native admission loss changed identity: %+v %v", migrated, err)
			}
			f.reopen()
			h = cfnEC2GatewayAttachment{f.commands}
			for range 2 {
				replayed, err := h.Update(f.ctx, r)
				if err != nil || replayed.PhysicalID != created.PhysicalID {
					t.Fatalf("migration replay lost exact current native owner: %+v %v", replayed, err)
				}
			}
			recovered, err := h.RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("migration creation receipt no longer identifies actual owner: %+v %v", recovered, err)
			}
			live, err := h.Read(f.ctx, r)
			if err != nil || live["InternetGatewayId"] != next.PhysicalID {
				t.Fatalf("migration reads stale gateway snapshot: %+v %v", live, err)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCloudControlGatewayAdmissionReturnsExistingCompositeIdentifier(t *testing.T) {
	f := cfnEC2RelationsFixture(t, "memory")
	r := f.request("VPCGatewayAttachment", "cloudcontrol-gateway-incarnation", cloudformation.Properties{"VpcId": f.gatewayVpc, "InternetGatewayId": f.gateway})
	r.CloudControl = true
	h := cfnEC2GatewayAttachment{f.commands}
	f.owner.operation, f.owner.armed = "AttachInternetGateway", true
	admitted, err := h.Create(f.ctx, r)
	if err == nil || admitted.PhysicalID == "" {
		t.Fatalf("CloudControl forgot native gateway admission: %+v %v", admitted, err)
	}
	want := cfnEC2PairID(r, "INTERNET_GATEWAY", f.gatewayVpc, "AttachmentType", "VpcId")
	if admitted.PhysicalID != want {
		t.Fatalf("native receipt escaped the composite consumer identifier: %+v want=%q", admitted, want)
	}
	replayed, err := h.Create(f.ctx, r)
	if err != nil || replayed.PhysicalID != want {
		t.Fatalf("CloudControl gateway replay: %+v %v", replayed, err)
	}
	r.PhysicalID = want
	if err := h.Delete(f.ctx, r); err != nil {
		t.Fatal(err)
	}
}

func TestEC2PrivateRelationsNeedNoPublicTagAdmission(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := cfnEC2RelationsFixture(t, backend)
			f.owner.rejectTags = true
			for _, row := range f.requests() {
				t.Run(row.kind, func(t *testing.T) {
					r := f.request(row.kind, "private-no-tags", row.valid)
					h := CloudFormationEC2Handlers(f.commands)[r.Type]
					created, err := h.Create(f.ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					r.PhysicalID = created.PhysicalID
					if _, err := h.(cloudformation.ResourceReader).Read(f.ctx, r); err != nil {
						t.Fatal(err)
					}
					recovered, err := h.(cloudformation.ResourceCreationRecoverer).RecoverCreation(f.ctx, r)
					if err != nil || recovered.PhysicalID != created.PhysicalID {
						t.Fatalf("private receipt recovery: %+v %v", recovered, err)
					}
					r.Previous = r.Properties
					if _, err := h.Update(f.ctx, r); err != nil {
						t.Fatal(err)
					}
					if err := h.Delete(f.ctx, r); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}
