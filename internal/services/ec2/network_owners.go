package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	api "stackd/internal/awsapi/ec2"
)

func registerNetworkOwners(s *Service) {
	register(s, "CreateNatGateway", s.createNatGateway)
	register(s, "DeleteNatGateway", s.deleteNatGateway)
	register(s, "DescribeNatGateways", s.describeNatGateways)
	register(s, "AssociateNatGatewayAddress", s.associateNatGatewayAddress)
	register(s, "DisassociateNatGatewayAddress", s.disassociateNatGatewayAddress)
	register(s, "AssignPrivateNatGatewayAddress", s.assignPrivateNatGatewayAddress)
	register(s, "UnassignPrivateNatGatewayAddress", s.unassignPrivateNatGatewayAddress)
	register(s, "CreateVpcEndpoint", s.createVPCEndpoint)
	register(s, "ModifyVpcEndpoint", s.modifyVPCEndpoint)
	register(s, "DeleteVpcEndpoints", s.deleteVPCEndpoints)
	register(s, "DescribeVpcEndpoints", s.describeVPCEndpoints)
}

func networkOwnerFingerprint(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(b)), nil
}
func networkOwnerReplay(tx Reader, scope Scope, action, token, fingerprint string) (string, error) {
	if token == "" {
		return "", nil
	}
	if len(token) > 64 {
		return "", failure("InvalidParameterValue", "ClientToken must not exceed 64 characters.")
	}
	previous, err := tx.NetworkOwnerCreation(NetworkCreationKey{Scope: scope, Action: action, Token: token})
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if previous.Fingerprint != fingerprint {
		return "", networkInterfaceTokenMismatch()
	}
	return previous.ResourceID, nil
}
func retainNetworkOwner(tx Transaction, scope Scope, action, token, id, fingerprint string) error {
	if token == "" {
		return nil
	}
	return tx.PutNetworkOwnerCreation(NetworkOwnerCreationRecord{Key: NetworkCreationKey{Scope: scope, Action: action, Token: token}, ResourceID: id, Fingerprint: fingerprint})
}

// Control ENIs reserve actual subnet capacity and are protected by ordinary
// requester-managed ENI commands. They do not represent a packet-forwarding guest.
func createNetworkOwnerENI(ctx context.Context, tx Transaction, subnet SubnetRecord, owner, kind, ip string, groups []SecurityGroupRecord) (NetworkInterfaceRecord, error) {
	pool, err := networkInterfaceAddressPool(ctx, tx, subnet)
	if err != nil {
		return NetworkInterfaceRecord{}, err
	}
	if ip == "" {
		ip, err = pool.allocate()
	} else {
		err = pool.reserveExplicit(ip, false)
	}
	if err != nil {
		return NetworkInterfaceRecord{}, err
	}
	id, err := tx.NextID(scopeFor(ctx), "eni")
	if err != nil {
		return NetworkInterfaceRecord{}, err
	}
	digest := sha256.Sum256([]byte(id))
	v := NetworkInterfaceRecord{Key: key(ctx, id), SubnetOwnerAccountID: subnet.Key.Scope.AccountID, NetworkControlOwnerID: owner, Data: api.NetworkInterface{
		NetworkInterfaceId: new(api.String(id)), SubnetId: copyPointer(subnet.Data.SubnetId), VpcId: copyPointer(subnet.Data.VpcId),
		AvailabilityZone: copyPointer(subnet.Data.AvailabilityZone), AvailabilityZoneId: copyPointer(subnet.Data.AvailabilityZoneId),
		OwnerId: new(api.String(scopeFor(ctx).AccountID)), RequesterManaged: new(api.Boolean(true)),
		Description: new(api.String("Managed by " + owner)), InterfaceType: new(api.NetworkInterfaceType(kind)), Status: new(api.NetworkInterfaceStatus("in-use")),
		SourceDestCheck: new(api.Boolean(kind != "nat_gateway")), PrivateIpAddress: new(api.String(ip)),
		PrivateIpAddresses: api.NetworkInterfacePrivateIpAddressList{newNetworkInterfaceAddress(ip, true)}, Groups: networkInterfaceGroupIdentifiers(groups),
		MacAddress: new(api.String(fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", digest[0], digest[1], digest[2], digest[3], digest[4]))), TagSet: api.TagList{},
	}}
	if err = changeNetworkInterfaceCapacity(tx, subnet, -1); err != nil {
		return v, err
	}
	return v, tx.PutNetworkInterface(v)
}
func deleteNetworkOwnerENI(ctx context.Context, tx Transaction, id, owner string) error {
	eni, err := tx.NetworkInterface(key(ctx, id))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !boolValue(eni.Data.RequesterManaged) || eni.NetworkControlOwnerID != owner {
		return failure("DependencyViolation", "Network interface has a different control owner.")
	}
	subnet, err := tx.Subnet(interfaceSubnetKey(eni))
	if err != nil {
		return err
	}
	if err = changeNetworkInterfaceCapacity(tx, subnet, len(eni.Data.PrivateIpAddresses)); err != nil {
		return err
	}
	return tx.DeleteNetworkInterface(eni.Key)
}
func networkOwnerMissing(kind, id string) error {
	if kind == "natgateway" {
		return failure("NatGatewayNotFound", "NAT gateway '"+id+"' does not exist.")
	}
	return failure("InvalidVpcEndpointId.NotFound", "VPC endpoint '"+id+"' does not exist.")
}
