package ec2

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

// This regression checks the specification consumed by the real guest backend:
// one owner's bridge/ACL/DHCP and the participant's security group. No grant or
// subnet copy is used to keep an admitted interface alive after unsharing.
func TestSharedSubnetNativeNetworkOwnership(t *testing.T) {
	repo := NewMemoryRepository(nil)
	owner := Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	participant := Scope{Partition: "aws", AccountID: "222222222222", Region: owner.Region}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: participant.Partition, AccountID: participant.AccountID, Region: participant.Region})
	subnet := SubnetRecord{Key: ResourceKey{Scope: owner, ID: "subnet-0123456789abcdef0"}, Data: api.Subnet{SubnetId: new(api.String("subnet-0123456789abcdef0")), VpcId: new(api.String("vpc-0123456789abcdef0")), CidrBlock: new(api.String("10.42.1.0/24"))}}
	group := SecurityGroupRecord{Key: ResourceKey{Scope: participant, ID: "sg-0123456789abcdef0"}, VPCOwnerAccountID: owner.AccountID, Data: api.SecurityGroup{GroupId: new(api.String("sg-0123456789abcdef0")), VpcId: subnet.Data.VpcId, IpPermissions: api.IpPermissionList{{IpProtocol: new(api.String("tcp")), FromPort: new(api.Integer(443)), ToPort: new(api.Integer(443)), IpRanges: api.IpRangeList{{CidrIp: new(api.String("10.42.0.0/16"))}}}}}}
	eni := NetworkInterfaceRecord{Key: ResourceKey{Scope: participant, ID: "eni-0123456789abcdef0"}, SubnetOwnerAccountID: owner.AccountID, Data: api.NetworkInterface{SubnetId: subnet.Data.SubnetId, VpcId: subnet.Data.VpcId, PrivateIpAddress: new(api.String("10.42.1.4")), MacAddress: new(api.String("02:00:00:00:00:01")), Groups: api.GroupIdentifierList{{GroupId: group.Data.GroupId}}}}
	acl := NetworkACLRecord{Key: ResourceKey{Scope: owner, ID: "acl-0123456789abcdef0"}, Data: api.NetworkAcl{VpcId: subnet.Data.VpcId, Associations: api.NetworkAclAssociationList{{SubnetId: subnet.Data.SubnetId}}, Entries: api.NetworkAclEntryList{{CidrBlock: new(api.String("0.0.0.0/0")), Protocol: new(api.String("-1")), RuleNumber: new(api.Integer(100)), RuleAction: new(api.RuleAction("allow")), Egress: new(api.Boolean(false))}}}}
	if err := repo.Update(ctx, func(tx Transaction) error {
		if err := tx.PutVPC(VPCRecord{Key: ResourceKey{Scope: owner, ID: str(subnet.Data.VpcId)}, Data: api.Vpc{CidrBlock: new(api.String("10.42.0.0/16")), DhcpOptionsId: new(api.String("dopt-0123456789abcdef0"))}, DNSSupport: true}); err != nil {
			return err
		}
		if err := tx.PutDHCPOptions(DHCPOptionsRecord{Key: ResourceKey{Scope: owner, ID: "dopt-0123456789abcdef0"}, Data: api.DhcpOptions{DhcpConfigurations: api.DhcpConfigurationList{{Key: new(api.String("domain-name-servers")), Values: api.DhcpConfigurationValueList{{Value: new(api.String("AmazonProvidedDNS"))}}}}}}); err != nil {
			return err
		}
		if err := tx.PutSubnet(subnet); err != nil {
			return err
		}
		if err := tx.PutNetworkACL(acl); err != nil {
			return err
		}
		if err := tx.PutSecurityGroup(group); err != nil {
			return err
		}
		return tx.PutNetworkInterface(eni)
	}); err != nil {
		t.Fatal(err)
	}
	check := func(ctx context.Context, port int, allow bool) {
		t.Helper()
		if err := repo.View(ctx, func(tx Reader) error {
			spec, err := networkSpecification(tx.Context(), tx, eni)
			if err != nil {
				return err
			}
			if spec.NetworkID != resourceARN(owner, "vpc", str(subnet.Data.VpcId)) || spec.Address != netip.MustParseAddr("10.42.1.4") || spec.Pool != netip.MustParsePrefix("10.42.0.0/16") || spec.Policy.Subnet != netip.MustParsePrefix("10.42.1.0/24") {
				t.Fatalf("participant network moved away from owner: %+v", spec)
			}
			if len(spec.DNS) != 1 || spec.DNS[0] != netip.MustParseAddr("10.42.0.2") {
				t.Fatalf("owner DHCP was not used: %+v", spec.DNS)
			}
			if len(spec.Policy.SecurityIngress) != 1 || spec.Policy.SecurityIngress[0].FromPort != port || len(spec.Policy.ACLIngress) != 1 || spec.Policy.ACLIngress[0].Allow != allow {
				t.Fatalf("current participant SG/owner ACL not composed: %+v", spec.Policy)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check(ctx, 443, true)
	if err := repo.Update(ctx, func(tx Transaction) error {
		group.Data.IpPermissions[0].FromPort = new(api.Integer(8443))
		group.Data.IpPermissions[0].ToPort = new(api.Integer(8443))
		acl.Data.Entries[0].RuleAction = new(api.RuleAction("deny"))
		if err := tx.PutSecurityGroup(group); err != nil {
			return err
		}
		return tx.PutNetworkACL(acl)
	}); err != nil {
		t.Fatal(err)
	}
	check(ctx, 8443, false)
	if err := repo.Update(ctx, func(tx Transaction) error { return tx.DeleteSubnet(subnet.Key) }); err != nil {
		t.Fatal(err)
	}
	if err := repo.View(ctx, func(tx Reader) error { _, err := networkSpecification(tx.Context(), tx, eni); return err }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retained ENI acquired a missing subnet: %v", err)
	}
}

func TestSubnetSharingRejectsDefaultVPCAndDefaultSubnet(t *testing.T) {
	repo := NewMemoryRepository(nil)
	service := New(Config{Repository: repo})
	t.Cleanup(func() { _ = service.Close() })
	scope := Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	vpc := VPCRecord{Key: ResourceKey{Scope: scope, ID: "vpc-0123456789abcdef0"}, Data: api.Vpc{IsDefault: new(api.Boolean(true))}}
	subnet := SubnetRecord{Key: ResourceKey{Scope: scope, ID: "subnet-0123456789abcdef0"}, Data: api.Subnet{VpcId: new(api.String(vpc.Key.ID)), State: new(api.SubnetState("available"))}}
	arn := resourceARN(scope, "subnet", subnet.Key.ID)
	put := func() {
		t.Helper()
		if err := repo.Update(t.Context(), func(tx Transaction) error {
			if err := tx.PutVPC(vpc); err != nil {
				return err
			}
			return tx.PutSubnet(subnet)
		}); err != nil {
			t.Fatal(err)
		}
	}
	put()
	if _, err := service.ResolveShareableSubnet(t.Context(), arn); !errors.Is(err, ErrSubnetNotShareable) {
		t.Fatalf("default VPC admitted: %v", err)
	}
	vpc.Data.IsDefault = new(api.Boolean(false))
	subnet.Data.DefaultForAz = new(api.Boolean(true))
	put()
	if _, err := service.ResolveShareableSubnet(t.Context(), arn); !errors.Is(err, ErrSubnetNotShareable) {
		t.Fatalf("default subnet admitted: %v", err)
	}
	subnet.Data.DefaultForAz = new(api.Boolean(false))
	put()
	identity, err := service.ResolveShareableSubnet(t.Context(), arn)
	if err != nil || identity.ARN != arn || identity.Key != subnet.Key {
		t.Fatalf("ordinary subnet identity: %+v, %v", identity, err)
	}
}
