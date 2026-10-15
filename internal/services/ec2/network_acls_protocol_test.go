package ec2

import (
	"testing"

	api "stackd/internal/awsapi/ec2"
)

// CreateNetworkAclEntry documents that all-protocol and other IP-protocol rules
// ignore transport ports and ICMP selectors. The Terraform provider sends 0..0
// for protocol -1; retaining that range would incorrectly deny real application
// ports. See https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAclEntry.html.
func TestNetworkACLEntryIgnoresInapplicableProtocolSelectors(t *testing.T) {
	for _, protocol := range []string{"-1", "47", "58", "6", "17", "1"} {
		t.Run(protocol, func(t *testing.T) {
			entry, err := networkACLEntry(&api.CreateNetworkAclEntryRequest{
				RuleNumber: new(api.Integer(100)), Egress: new(api.Boolean(false)),
				Protocol: new(api.String(protocol)), RuleAction: new(api.RuleActionAllow),
				CidrBlock:    new(api.String("10.0.0.0/24")),
				PortRange:    &api.PortRange{From: new(api.Integer(40)), To: new(api.Integer(42))},
				IcmpTypeCode: &api.IcmpTypeCode{Type: new(api.Integer(8)), Code: new(api.Integer(0))},
			})
			if err != nil {
				t.Fatal(err)
			}
			if protocol == "6" || protocol == "17" {
				if entry.PortRange == nil || *entry.PortRange.From != 40 || *entry.PortRange.To != 42 {
					t.Fatalf("transport range lost: %+v", entry)
				}
			} else if entry.PortRange != nil {
				t.Fatalf("non-transport rule retained a port restriction: %+v", entry)
			}
			if protocol == "1" {
				if entry.IcmpTypeCode == nil || *entry.IcmpTypeCode.Type != 8 || *entry.IcmpTypeCode.Code != 0 {
					t.Fatalf("ICMP selector lost: %+v", entry)
				}
			} else if entry.IcmpTypeCode != nil {
				t.Fatalf("non-ICMP rule retained an ICMP restriction: %+v", entry)
			}
		})
	}
}
