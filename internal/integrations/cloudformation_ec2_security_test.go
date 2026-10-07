package integrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
)

type cfnEC2SecurityFixture struct {
	ctx      context.Context
	commands StepFunctionsCommands
	owner    *cfnEC2LostAssociationResponse
	vpc      string
	reopen   func()
}

func cfnEC2SecurityNativeFixture(t *testing.T, backend string) *cfnEC2SecurityFixture {
	t.Helper()
	f := &cfnEC2SecurityFixture{ctx: awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})}
	var repo ec2.Repository = ec2.NewMemoryRepository(nil)
	var db *sql.DB
	path := filepath.Join(t.TempDir(), "security.sqlite")
	open := func() {
		if backend == "sqlite" {
			var err error
			db, err = sqlite.Open(f.ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			repo = sqlec2.New(db)
		}
		f.owner = &cfnEC2LostAssociationResponse{Service: ec2.New(ec2.Config{Repository: repo})}
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
	vpc, err := cfnComputeCall[api.CreateVpcResult](f.ctx, f.commands, "ec2", "CreateVpc", map[string]any{"CidrBlock": "10.84.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	f.vpc = cfnComputeValue(vpc.Vpc.VpcId)
	return f
}
func TestEC2SecurityGroupExplicitEgressUsesPrivateNativeDefault(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := cfnEC2SecurityNativeFixture(t, backend)
			r := cfnEC2AncillaryTestRequest("SecurityGroup", cloudformation.Properties{"GroupDescription": "group", "VpcId": f.vpc, "SecurityGroupEgress": []any{map[string]any{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}}})
			h := cfnEC2SecurityGroup{f.commands}
			out, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = out.PhysicalID
			rules, err := (cfnEC2SecurityRule{f.commands, true}).rules(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			var id string
			for _, rule := range rules {
				if cfnComputeValue(rule.GroupId) == r.PhysicalID {
					if id != "" {
						t.Fatal("explicit default created multiple egress rules")
					}
					id = cfnComputeValue(rule.SecurityGroupRuleId)
					if len(rule.Tags) != 0 {
						t.Fatalf("default rule emitted metadata ownership: %+v", rule.Tags)
					}
				}
			}
			if id == "" {
				t.Fatal("native default egress missing")
			}
			if err := cfnEC2NativeOwned(f.ctx, f.commands, r, id); err != nil {
				t.Fatal(err)
			}
			f.reopen()
			h = cfnEC2SecurityGroup{f.commands}
			retry, err := h.Create(f.ctx, r)
			if err != nil || retry.PhysicalID != r.PhysicalID {
				t.Fatalf("restart replay: %+v %v", retry, err)
			}
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"GroupDescription": "group", "VpcId": f.vpc, "SecurityGroupEgress": []any{}}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			rules, err = (cfnEC2SecurityRule{f.commands, true}).rules(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range rules {
				if cfnComputeValue(rule.GroupId) == r.PhysicalID {
					t.Fatal("explicit empty egress retained native default")
				}
			}
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"GroupDescription": "group", "VpcId": f.vpc}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			rules, err = (cfnEC2SecurityRule{f.commands, true}).rules(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			restored := false
			for _, rule := range rules {
				if cfnComputeValue(rule.GroupId) == r.PhysicalID {
					restored = true
					if err := cfnEC2NativeOwned(f.ctx, f.commands, r, cfnComputeValue(rule.SecurityGroupRuleId)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if !restored {
				t.Fatal("removing explicit egress did not restore SG-owned default")
			}
		})
	}
}
func TestEC2SecurityGroupInlineDescriptionUsesLiveRuleID(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := cfnEC2SecurityNativeFixture(t, backend)
			permission := map[string]any{"IpProtocol": "tcp", "FromPort": float64(80), "ToPort": float64(80), "CidrIp": "10.0.0.0/24", "Description": "before"}
			r := cfnEC2AncillaryTestRequest("SecurityGroup", cloudformation.Properties{"GroupDescription": "group", "VpcId": f.vpc, "SecurityGroupIngress": []any{permission}})
			h := cfnEC2SecurityGroup{f.commands}
			out, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = out.PhysicalID
			rh := cfnEC2SecurityRule{f.commands, false}
			rules, err := rh.rules(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			var id string
			for _, rule := range rules {
				if cfnComputeValue(rule.GroupId) == r.PhysicalID {
					id = cfnComputeValue(rule.SecurityGroupRuleId)
				}
			}
			if id == "" {
				t.Fatal("inline rule missing")
			}
			if err := cfnEC2NativeOwned(f.ctx, f.commands, r, id); err != nil {
				t.Fatal(err)
			}
			standalone := r
			standalone.Type = "AWS::EC2::SecurityGroupIngress"
			standalone.PhysicalID = id
			if _, err := rh.Read(f.ctx, standalone); err == nil {
				t.Fatal("standalone type observed SG-owned inline rule")
			}
			f.reopen()
			h = cfnEC2SecurityGroup{f.commands}
			rh = cfnEC2SecurityRule{f.commands, false}
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"GroupDescription": "group", "VpcId": f.vpc, "SecurityGroupIngress": []any{map[string]any{"IpProtocol": "tcp", "FromPort": float64(80), "ToPort": float64(80), "CidrIp": "10.0.0.0/24", "Description": "after"}}}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			rules, err = rh.rules(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, rule := range rules {
				if cfnComputeValue(rule.SecurityGroupRuleId) == id {
					found = true
					if cfnComputeValue(rule.Description) != "after" {
						t.Fatal("description not updated")
					}
				}
			}
			if !found {
				t.Fatal("description update replaced inline rule")
			}
			foreign := r
			foreign.Token = "foreign"
			if _, err := h.Update(f.ctx, foreign); err == nil {
				t.Fatal("foreign SG identity mutated inline rules")
			}
		})
	}
}
func TestEC2SecurityGroupCustomerMarkersNeverAdmitOwnership(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := cfnEC2SecurityNativeFixture(t, backend)
			h := cfnEC2SecurityGroup{f.commands}
			r := cfnEC2AncillaryTestRequest("SecurityGroup", cloudformation.Properties{"GroupName": "private-group", "GroupDescription": "group", "VpcId": f.vpc, "Tags": []any{map[string]any{"Key": "stackd:cloudformation:stack-id", "Value": "customer"}}})
			out, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = out.PhysicalID
			p, err := h.Read(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(p["Tags"], []map[string]string{{"Key": "stackd:cloudformation:stack-id", "Value": "customer"}}) {
				t.Fatalf("customer marker was emitted, hidden or rewritten: %#v", p["Tags"])
			}
			if err := cfnComputeRun(f.ctx, f.commands, "ec2", "DeleteTags", map[string]any{"Resources": []string{r.PhysicalID}, "Tags": []map[string]string{{"Key": "stackd:cloudformation:stack-id"}}}); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Read(f.ctx, r); err != nil {
				t.Fatalf("metadata removal erased private ownership: %v", err)
			}
			forged, err := cfnComputeCall[api.CreateSecurityGroupResult](f.ctx, f.commands, "ec2", "CreateSecurityGroup", map[string]any{"GroupName": "unclaimed-group", "Description": "group", "VpcId": f.vpc, "TagSpecifications": []map[string]any{{"ResourceType": "security-group", "Tags": cfnComputeTagList(cfnComputeOwnedTags(r))}}})
			if err != nil {
				t.Fatal(err)
			}
			imported := r
			imported.PhysicalID = cfnComputeValue(forged.GroupId)
			if _, err := h.Read(f.ctx, imported); err == nil {
				t.Fatal("forged metadata admitted ordinary SG")
			}
			if err := h.Delete(f.ctx, imported); err == nil {
				t.Fatal("forged metadata allowed deletion")
			}
			created := imported
			created.Token = "new"
			created.Properties = cloudformation.Properties{"GroupName": "unclaimed-group", "GroupDescription": "group", "VpcId": f.vpc}
			if _, err := h.Create(f.ctx, created); err == nil {
				t.Fatal("create adopted ordinary unclaimed SG")
			}
			listed, err := h.List(f.ctx, r)
			if err != nil || len(listed) != 1 || listed[0].Identifier != r.PhysicalID {
				t.Fatalf("private list IDs: %+v %v", listed, err)
			}
			permission := map[string]any{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "CidrIp": "10.1.0.0/24"}
			foreignRule, err := cfnComputeCall[api.AuthorizeSecurityGroupIngressResult](f.ctx, f.commands, "ec2", "AuthorizeSecurityGroupIngress", map[string]any{"GroupId": r.PhysicalID, "IpPermissions": []map[string]any{cfnEC2SecurityPermission(permission, false)}, "TagSpecifications": []map[string]any{{"ResourceType": "security-group-rule", "Tags": cfnComputeTagList(cfnComputeOwnedTags(r))}}})
			if err != nil {
				t.Fatal(err)
			}
			ruleID := cfnComputeValue(foreignRule.SecurityGroupRules[0].SecurityGroupRuleId)
			if err := cfnEC2NativeOwned(f.ctx, f.commands, r, ruleID); err == nil {
				t.Fatal("forged rule tags admitted inline ownership")
			}
			standalone := cfnEC2AncillaryTestRequest("SecurityGroupIngress", cloudformation.Properties{"GroupId": r.PhysicalID, "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "CidrIp": "10.1.0.0/24"})
			standalone.PhysicalID = ruleID
			rh := cfnEC2SecurityRule{f.commands, false}
			if _, err := rh.Read(f.ctx, standalone); err == nil {
				t.Fatal("ordinary rule admitted standalone import")
			}
			standalone.PhysicalID = ""
			if _, err := rh.Create(f.ctx, standalone); err == nil {
				t.Fatal("standalone create adopted ordinary matching rule")
			}
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"GroupName": "private-group", "GroupDescription": "group", "VpcId": f.vpc, "SecurityGroupIngress": []any{permission}}
			if _, err := h.Update(f.ctx, r); err == nil {
				t.Fatal("inline synchronization adopted foreign matching rule")
			}
			r.Properties = cloudformation.Properties{"GroupName": "private-group", "GroupDescription": "group", "VpcId": f.vpc, "SecurityGroupIngress": []any{}}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			live, err := cfnComputeCall[api.DescribeSecurityGroupRulesResult](f.ctx, f.commands, "ec2", "DescribeSecurityGroupRules", map[string]any{"SecurityGroupRuleIds": []string{ruleID}})
			if err != nil || len(live.SecurityGroupRules) != 1 {
				t.Fatalf("inline cleanup removed foreign rule: %+v %v", live, err)
			}
		})
	}
}
func TestEC2SecurityNativeCreateRecoveryAndCloudControlMutation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, cloudControl := range []bool{false, true} {
				mode := "stack"
				if cloudControl {
					mode = "cloudcontrol"
				}
				t.Run(mode, func(t *testing.T) {
					f := cfnEC2SecurityNativeFixture(t, backend)
					r := cfnEC2AncillaryTestRequest("SecurityGroup", cloudformation.Properties{"GroupDescription": "group", "VpcId": f.vpc})
					r.CloudControl = cloudControl
					h := cfnEC2SecurityGroup{f.commands}
					f.owner.operation, f.owner.armed = "CreateSecurityGroup", true
					if _, err := h.Create(f.ctx, r); err == nil {
						t.Fatal("interrupted SG creation unexpectedly succeeded")
					}
					id, err := cfnEC2NativeRecover(f.ctx, f.commands, r)
					if err != nil || id == "" {
						t.Fatalf("native SG receipt missing: %q %v", id, err)
					}
					f.reopen()
					h = cfnEC2SecurityGroup{f.commands}
					out, err := h.Create(f.ctx, r)
					if err != nil || out.PhysicalID != id {
						t.Fatalf("SG replay replaced native receipt: %+v %v", out, err)
					}
					r.PhysicalID = id
					stackView := r
					stackView.CloudControl = false
					if _, err := h.Read(f.ctx, stackView); err != nil {
						t.Fatalf("creation did not keep private SG identity: %v", err)
					}
					wrong := r
					wrong.Properties = cloudformation.Properties{"GroupDescription": "other", "VpcId": f.vpc}
					if _, err := h.Create(f.ctx, wrong); err == nil {
						t.Fatal("SG receipt recovered mismatching native group")
					}
					for _, egress := range []bool{false, true} {
						kind := "SecurityGroupIngress"
						if egress {
							kind = "SecurityGroupEgress"
						}
						rr := cfnEC2AncillaryTestRequest(kind, cloudformation.Properties{"GroupId": id, "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "10.2.0.0/24", "Description": "before"})
						rr.CloudControl = cloudControl
						rh := cfnEC2SecurityRule{f.commands, egress}
						rule, err := rh.Create(f.ctx, rr)
						if err != nil {
							t.Fatal(err)
						}
						retry, err := rh.Create(f.ctx, rr)
						if err != nil || retry.PhysicalID != rule.PhysicalID {
							t.Fatalf("rule replay: %+v %v", retry, err)
						}
						rr.PhysicalID = rule.PhysicalID
						if cloudControl {
							direct := rr
							direct.Token = "direct-mutation"
							direct.Previous = rr.Properties
							direct.Properties = cloudformation.Properties{"GroupId": id, "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "10.2.0.0/24", "Description": "after"}
							if _, err := rh.Update(f.ctx, direct); err != nil {
								t.Fatal(err)
							}
							original := rr
							original.CloudControl = false
							if _, err := rh.Read(f.ctx, original); err != nil {
								t.Fatalf("direct CloudControl mutation stole original claim: %v", err)
							}
						}
						if err := rh.Delete(f.ctx, rr); err != nil {
							t.Fatal(err)
						}
					}
					if err := h.Delete(f.ctx, r); err != nil {
						t.Fatal(err)
					}
					if _, err := h.Create(f.ctx, r); err == nil {
						t.Fatal("deleted SG receipt admitted replacement")
					}
				})
			}
		})
	}
}
func TestEC2AncillaryEIPAssociationCloudControlRetryClaimsBeforeEffect(t *testing.T) {
	f := cfnEC2RelationsFixture(t, "memory")
	r := f.request("EIPAssociation", "cloudcontrol-incarnation", cloudformation.Properties{"AllocationId": f.address, "NetworkInterfaceId": f.eni})
	r.CloudControl = true
	h := cfnEC2AncillaryRelation{f.commands, "EIPAssociation"}
	f.owner.operation, f.owner.armed = "AssociateAddress", true
	first, err := h.Create(f.ctx, r)
	if err == nil || first.PhysicalID == "" {
		t.Fatalf("CloudControl response loss forgot admitted native association: %+v %v", first, err)
	}
	second, err := h.Create(f.ctx, r)
	if err != nil || first.PhysicalID != second.PhysicalID {
		t.Fatalf("CloudControl replay changed admitted association: %+v %v", second, err)
	}
	r.PhysicalID = second.PhysicalID
	if _, err := h.Read(f.ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := h.Delete(f.ctx, r); err != nil {
		t.Fatal(err)
	}
}
func TestEC2AncillaryNetworkInterfaceSecondaryCountUsesOwnerAssignment(t *testing.T) {
	r := cfnEC2AncillaryTestRequest("NetworkInterface", cloudformation.Properties{"SubnetId": "subnet-00000000000000001", "SecondaryPrivateIpAddressCount": float64(3)})
	item := cfnEC2AncillaryItem{id: "eni-00000000000000001", properties: cloudformation.Properties{"SecondaryPrivateIpAddresses": []any{"10.0.0.3"}}}
	assigned := int64(0)
	commands := cfnEC2AncillaryTestCommands(func(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
		if string(request.Operation.Name) != "AssignPrivateIpAddresses" {
			t.Fatalf("count update did not use real assignment: %s", request.Operation.Name)
		}
		in := request.Input.(*api.AssignPrivateIpAddressesRequest)
		assigned = int64(*in.SecondaryPrivateIpAddressCount)
		return struct{}{}, nil
	})
	if err := (cfnEC2AncillaryOwner{commands, "NetworkInterface"}).addresses(context.Background(), r, item); err != nil {
		t.Fatal(err)
	}
	if assigned != 2 {
		t.Fatalf("assigned %d additional addresses, want 2", assigned)
	}
}
func TestEC2AncillaryNetworkInterfacePrimaryListDoesNotEraseCountAllocation(t *testing.T) {
	r := cfnEC2AncillaryTestRequest("NetworkInterface", cloudformation.Properties{"SubnetId": "subnet-00000000000000001", "SecondaryPrivateIpAddressCount": float64(2), "PrivateIpAddresses": []any{map[string]any{"PrivateIpAddress": "10.0.0.2", "Primary": true}}})
	item := cfnEC2AncillaryItem{id: "eni-00000000000000001", properties: cloudformation.Properties{"SecondaryPrivateIpAddresses": []any{"10.0.0.3", "10.0.0.4"}}}
	commands := cfnEC2AncillaryTestCommands(func(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
		t.Fatalf("create recovery changed already allocated secondary addresses: %s", request.Operation.Name)
		return nil, nil
	})
	h := cfnEC2AncillaryOwner{commands, "NetworkInterface"}
	if err := h.Validate(r.Properties); err != nil {
		t.Fatal(err)
	}
	if err := h.addresses(context.Background(), r, item); err != nil {
		t.Fatal(err)
	}
}
