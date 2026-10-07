package integrations

import (
	"context"
	"reflect"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscommands"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

type cfnEC2AncillaryTestExecutor struct {
	call func(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}

func (e cfnEC2AncillaryTestExecutor) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	return e.call(ctx, r)
}
func cfnEC2AncillaryTestCommands(fn func(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)) StepFunctionsCommands {
	return NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": cfnEC2AncillaryTestExecutor{fn}})
}
func cfnEC2AncillaryTestRequest(kind string, p cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{StackID: "stack", StackName: "network", LogicalID: "Resource", Token: "incarnation", Type: "AWS::EC2::" + kind, Properties: p}
}

func TestEC2AncillaryRegistryAndReadContracts(t *testing.T) {
	handlers := CloudFormationEC2AncillaryHandlers(StepFunctionsCommands{})
	kinds := []string{"SecurityGroup", "SecurityGroupIngress", "SecurityGroupEgress", "NetworkAcl", "NetworkAclEntry", "SubnetNetworkAclAssociation", "NetworkInterface", "EIP", "EIPAssociation", "DHCPOptions", "VPCDHCPOptionsAssociation"}
	if len(handlers) != len(kinds) {
		t.Fatalf("registry has %d handlers", len(handlers))
	}
	for _, kind := range kinds {
		h := handlers["AWS::EC2::"+kind]
		if h == nil {
			t.Fatalf("missing %s", kind)
		}
		if _, ok := h.(cloudformation.ResourceReader); !ok {
			t.Fatalf("%s has no live reader", kind)
		}
		if _, ok := h.(cloudformation.ResourceStabilizer); !ok {
			t.Fatalf("%s has no stabilization", kind)
		}
		if _, ok := h.(cloudformation.ResourceDeletionStabilizer); !ok {
			t.Fatalf("%s has no deletion stabilization", kind)
		}
	}
	if _, ok := handlers["AWS::EC2::NetworkInterfaceAttachment"]; ok {
		t.Fatal("unimplemented ENI attachment must not be advertised")
	}
}
func TestEC2AncillaryHonestOwnerPropertyErrors(t *testing.T) {
	rows := []struct {
		kind string
		p    cloudformation.Properties
	}{
		{"NetworkInterface", cloudformation.Properties{"SubnetId": "subnet", "Ipv6AddressCount": float64(1)}},
		{"NetworkInterface", cloudformation.Properties{"SubnetId": "subnet", "InterfaceType": "efa"}},
		{"NetworkInterface", cloudformation.Properties{"SubnetId": "subnet", "SecondaryPrivateIpAddressCount": float64(-1)}},
		{"NetworkInterface", cloudformation.Properties{"SubnetId": "subnet", "GroupSet": []any{}}},
		{"EIP", cloudformation.Properties{"Domain": "standard"}},
		{"EIP", cloudformation.Properties{"IpamPoolId": "pool"}},
		{"NetworkAclEntry", cloudformation.Properties{"NetworkAclId": "acl", "RuleNumber": float64(100), "Protocol": float64(-1), "RuleAction": "allow", "Ipv6CidrBlock": "::/0"}},
		{"SecurityGroupIngress", cloudformation.Properties{"GroupId": "sg", "IpProtocol": "-1", "SourcePrefixListId": "prefix"}},
		{"SecurityGroupIngress", cloudformation.Properties{"GroupId": "sg", "IpProtocol": "-1", "SourceSecurityGroupName": "source"}},
	}
	handlers := CloudFormationEC2AncillaryHandlers(StepFunctionsCommands{})
	for _, row := range rows {
		if err := handlers["AWS::EC2::"+row.kind].Validate(row.p); err == nil {
			t.Fatalf("%s accepted unsupported properties %#v", row.kind, row.p)
		}
	}
	if err := handlers["AWS::EC2::SecurityGroupIngress"].Validate(cloudformation.Properties{"GroupId": "sg", "IpProtocol": "-1", "CidrIpv6": "2001:db8::/64"}); err != nil {
		t.Fatalf("implemented IPv6 security rules rejected: %v", err)
	}
}
func TestEC2AncillaryReplacementAndPermissionProjection(t *testing.T) {
	h := cfnEC2AncillaryOwner{kind: "NetworkInterface"}
	before := cloudformation.Properties{"SubnetId": "subnet", "PrivateIpAddresses": []any{map[string]any{"PrivateIpAddress": "10.0.0.2", "Primary": true}, map[string]any{"PrivateIpAddress": "10.0.0.3", "Primary": false}}}
	after := cloudformation.Properties{"SubnetId": "subnet", "PrivateIpAddresses": []any{map[string]any{"PrivateIpAddress": "10.0.0.2", "Primary": true}, map[string]any{"PrivateIpAddress": "10.0.0.4", "Primary": false}}}
	if replace, err := h.Replacement(before, after); err != nil || replace {
		t.Fatalf("secondary IP update replacement=%v err=%v", replace, err)
	}
	after["PrivateIpAddresses"] = []any{map[string]any{"PrivateIpAddress": "10.0.0.5", "Primary": true}}
	if replace, err := h.Replacement(before, after); err != nil || !replace {
		t.Fatalf("primary IP update replacement=%v err=%v", replace, err)
	}
	rule := cloudformation.Properties{"IpProtocol": "tcp", "FromPort": float64(443), "ToPort": float64(443), "CidrIp": "10.0.0.23/24", "Description": "tls"}
	live := cloudformation.Properties{"IpProtocol": "6", "FromPort": int64(443), "ToPort": int64(443), "CidrIp": "10.0.0.0/24"}
	if !reflect.DeepEqual(cfnEC2SecurityRuleIdentity(rule), cfnEC2SecurityRuleIdentity(live)) {
		t.Fatal("canonical service rule identity differs")
	}
	permission := cfnEC2SecurityPermission(cloudformation.Properties{"IpProtocol": "-1", "CidrIpv6": "2001:db8::/64", "Description": "v6"}, false)
	if _, ok := permission["Ipv6Ranges"]; !ok {
		t.Fatalf("missing real IPv6 permission: %#v", permission)
	}
	entry := cfnEC2AncillaryEntryInput(cloudformation.Properties{"NetworkAclId": "acl", "RuleNumber": float64(100), "Protocol": float64(1), "RuleAction": "allow", "CidrBlock": "10.0.0.0/24", "Icmp": map[string]any{"Type": float64(-1), "Code": float64(-1)}})
	if entry["Protocol"] != "1" || entry["Egress"] != false || entry["IcmpTypeCode"] == nil {
		t.Fatalf("wrong owner ACL input: %#v", entry)
	}
}
func TestEC2AncillaryEIPRecoveryOwnershipAndCompositeRead(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := cfnEC2RelationsFixture(t, backend)
			r := f.request("EIP", "address-incarnation", cloudformation.Properties{"Domain": "vpc", "Tags": []any{map[string]any{"Key": "stackd:cloudformation:stack-id", "Value": "customer"}}})
			h := cfnEC2AncillaryOwner{f.commands, "EIP"}
			f.owner.operation, f.owner.armed = "AllocateAddress", true
			if _, err := h.Create(f.ctx, r); err == nil {
				t.Fatal("lost native reply succeeded")
			}
			f.reopen()
			h = cfnEC2AncillaryOwner{f.commands, "EIP"}
			first, err := h.RecoverCreation(f.ctx, r)
			if err != nil || first.PhysicalID == "" {
				t.Fatalf("native receipt recovery: %+v %v", first, err)
			}
			second, err := h.Create(f.ctx, r)
			if err != nil || first.PhysicalID != second.PhysicalID {
				t.Fatalf("recovery=%#v err=%v", second, err)
			}
			foreign := r
			foreign.PhysicalID = first.PhysicalID
			foreign.Token = "another-incarnation"
			if err := h.Delete(f.ctx, foreign); err == nil {
				t.Fatal("foreign incarnation released native address")
			}
			direct := foreign
			direct.CloudControl = true
			direct.PhysicalID = cfnEC2AncillaryComposite(first.Attributes, "PublicIp", "AllocationId")
			p, err := h.Read(f.ctx, direct)
			if err != nil || p["PublicIp"] != first.Ref {
				t.Fatalf("composite read %#v %v", p, err)
			}
			rows, err := h.List(f.ctx, direct)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, row := range rows {
				if row.Identifier == direct.PhysicalID {
					found = true
				}
			}
			if !found {
				t.Fatalf("live list omitted admitted address: %#v", rows)
			}
			owned := r
			owned.PhysicalID = first.PhysicalID
			if err := cfnComputeRun(f.ctx, f.commands, "ec2", "DeleteTags", map[string]any{"Resources": []string{first.PhysicalID}, "Tags": []map[string]any{{"Key": "stackd:cloudformation:stack-id"}}}); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Read(f.ctx, owned); err != nil {
				t.Fatalf("customer tag removal changed private claim: %v", err)
			}
			if err := h.Delete(f.ctx, owned); err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(f.ctx, owned); err != nil {
				t.Fatal(err)
			}
			if _, err := h.RecoverCreation(f.ctx, r); err == nil {
				t.Fatal("deleted receipt allowed creation recovery")
			}
		})
	}
}
func TestEC2AncillaryOwnerAuthorizationFailureIsNotAbsence(t *testing.T) {
	denied := &awswire.Error{Code: "UnauthorizedOperation", Message: "current role denied"}
	commands := cfnEC2AncillaryTestCommands(func(context.Context, awsapi.DecodedRequest) (any, *awswire.Error) { return nil, denied })
	h := cfnEC2AncillaryOwner{commands, "EIP"}
	r := cfnEC2AncillaryTestRequest("EIP", cloudformation.Properties{})
	r.PhysicalID = "eipalloc-00000000000000001"
	if err := h.Delete(context.Background(), r); err != denied {
		t.Fatalf("authorization swallowed: %v", err)
	}
	if ready, err := h.StabilizeDeletion(context.Background(), r); ready || err != denied {
		t.Fatalf("denial treated as stabilization: %v %v", ready, err)
	}
}
func TestEC2AncillaryNetworkACLClaimBeforeEffectAndRecovery(t *testing.T) {
	f := cfnEC2RelationsFixture(t, "memory")
	r := f.request("NetworkAclEntry", "entry-incarnation", cloudformation.Properties{"NetworkAclId": f.acl, "RuleNumber": 100, "Protocol": -1, "RuleAction": "allow", "CidrBlock": "10.82.0.0/16"})
	h := cfnEC2AncillaryRelation{f.commands, "NetworkAclEntry"}
	f.owner.operation, f.owner.armed = "CreateNetworkAclEntry", true
	first, err := h.Create(f.ctx, r)
	if err == nil || first.PhysicalID == "" {
		t.Fatalf("response loss forgot native ACL entry admission: %+v %v", first, err)
	}
	second, err := h.Create(f.ctx, r)
	if err != nil || first.PhysicalID != second.PhysicalID {
		t.Fatalf("same-token replay changed native entry: %+v %v", second, err)
	}
	r.PhysicalID = first.PhysicalID
	foreign := r
	foreign.Token = "foreign"
	if err := h.Delete(f.ctx, foreign); err == nil {
		t.Fatal("foreign incarnation deleted native ACL entry")
	}
	p, err := h.Read(f.ctx, r)
	if err != nil || p["RuleNumber"] != int64(100) {
		t.Fatalf("authoritative native ACL entry: %+v %v", p, err)
	}
	for range 2 {
		if err := h.Delete(f.ctx, r); err != nil {
			t.Fatal(err)
		}
	}
}
func TestEC2AncillaryRejectsUnclaimedExistingEntry(t *testing.T) {
	f := cfnEC2RelationsFixture(t, "memory")
	r := f.request("NetworkAclEntry", "unrelated-incarnation", cloudformation.Properties{"NetworkAclId": f.acl, "RuleNumber": 100, "Protocol": -1, "RuleAction": "allow", "CidrBlock": "10.82.0.0/16"})
	if err := cfnComputeRun(f.ctx, f.commands, "ec2", "CreateNetworkAclEntry", cfnEC2AncillaryEntryInput(r.Properties)); err != nil {
		t.Fatal(err)
	}
	h := cfnEC2AncillaryRelation{f.commands, "NetworkAclEntry"}
	if result, err := h.Create(f.ctx, r); err == nil || result.PhysicalID != "" {
		t.Fatalf("unclaimed native entry was adopted: %+v %v", result, err)
	}
	direct := r
	direct.CloudControl = true
	direct.PhysicalID = cfnEC2AncillaryEntryID(f.acl, false, 100)
	if p, err := h.Read(f.ctx, direct); err != nil || p["RuleAction"] != "allow" {
		t.Fatalf("rejected adoption damaged foreign entry: %+v %v", p, err)
	}
}
func TestEC2AncillarySecurityRuleRecoveryAndDescriptionUpdate(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, egress := range []bool{false, true} {
				kind := "SecurityGroupIngress"
				if egress {
					kind = "SecurityGroupEgress"
				}
				t.Run(kind, func(t *testing.T) {
					f := cfnEC2SecurityNativeFixture(t, backend)
					group, err := cfnComputeCall[api.CreateSecurityGroupResult](f.ctx, f.commands, "ec2", "CreateSecurityGroup", map[string]any{"GroupName": "standalone-rules", "Description": "group", "VpcId": f.vpc})
					if err != nil {
						t.Fatal(err)
					}
					groupID := cfnComputeValue(group.GroupId)
					properties := cloudformation.Properties{"GroupId": groupID, "IpProtocol": "tcp", "FromPort": float64(443), "ToPort": float64(443), "CidrIp": "10.0.0.0/24", "Description": "before"}
					r := cfnEC2AncillaryTestRequest(kind, properties)
					h := cfnEC2SecurityRule{f.commands, egress}
					f.owner.operation, f.owner.armed = h.operation("Authorize"), true
					if _, err := h.Create(f.ctx, r); err == nil {
						t.Fatal("native response interruption was swallowed")
					}
					recoveredID, err := cfnEC2NativeRecover(f.ctx, f.commands, r)
					if err != nil || recoveredID == "" {
						t.Fatalf("missing exact native admission: %q %v", recoveredID, err)
					}
					f.reopen()
					h = cfnEC2SecurityRule{f.commands, egress}
					result, err := h.Create(f.ctx, r)
					if err != nil || result.PhysicalID != recoveredID {
						t.Fatalf("rule recovery=%#v err=%v receipt=%q", result, err, recoveredID)
					}
					r.PhysicalID = result.PhysicalID
					rule, err := h.item(f.ctx, r)
					if err != nil || len(rule.Tags) != 0 {
						t.Fatalf("standalone rule emitted ownership metadata: %+v %v", rule, err)
					}
					wrong := r
					wrong.Type = "AWS::EC2::SecurityGroup"
					if err := cfnEC2NativeOwned(f.ctx, f.commands, wrong, r.PhysicalID); err == nil {
						t.Fatal("SG type observed standalone rule ownership")
					}
					changed := r
					changed.Properties = cloudformation.Properties{"GroupId": groupID, "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "10.1.0.0/24"}
					if _, err := h.Create(f.ctx, changed); err == nil {
						t.Fatal("recovery accepted different live permission")
					}
					r.Previous = r.Properties
					r.Properties = cloudformation.Properties{"GroupId": groupID, "IpProtocol": "tcp", "FromPort": float64(443), "ToPort": float64(443), "CidrIp": "10.0.0.0/24", "Description": "after"}
					if _, err := h.Update(f.ctx, r); err != nil {
						t.Fatal(err)
					}
					p, err := h.Read(f.ctx, r)
					if err != nil || p["Description"] != "after" {
						t.Fatalf("live description %#v %v", p, err)
					}
					if err := cfnComputeRun(f.ctx, f.commands, "ec2", "CreateTags", map[string]any{"Resources": []string{r.PhysicalID}, "Tags": cfnComputeTagList(cfnComputeOwnedTags(r))}); err != nil {
						t.Fatal(err)
					}
					foreign := r
					foreign.Token = "other"
					if err := h.Delete(f.ctx, foreign); err == nil {
						t.Fatal("forged public metadata authorized foreign revoke")
					}
					if err := cfnComputeRun(f.ctx, f.commands, "ec2", "DeleteTags", map[string]any{"Resources": []string{r.PhysicalID}, "Tags": cfnComputeTagList(cfnComputeOwnedTags(r))}); err != nil {
						t.Fatal(err)
					}
					if _, err := h.Read(f.ctx, r); err != nil {
						t.Fatalf("tag removal erased rule ownership: %v", err)
					}
					list, err := h.List(f.ctx, r)
					if err != nil || len(list) != 1 || list[0].Identifier != r.PhysicalID {
						t.Fatalf("list did not use exact rule row: %+v %v", list, err)
					}
					if err := h.Delete(f.ctx, r); err != nil {
						t.Fatal(err)
					}
					if _, err := h.Create(f.ctx, r); err == nil {
						t.Fatal("deleted claim silently admitted another rule")
					}
				})
			}
		})
	}
}
