package ec2

import (
	"testing"

	api "stackd/internal/awsapi/ec2"
)

func TestPublicAddressLifecycleAndPacketAuthority(t *testing.T) {
	local := newMetadataTestInstance(t)
	s, ctx := local.service, local.ctx
	var eni NetworkInterfaceRecord
	var elastic PublicAddressRecord
	var initial string
	mutate := func(fn func(Transaction) error) {
		t.Helper()
		if err := s.repository.Update(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}
	mutate(func(tx Transaction) error {
		vpc, err := s.createVPC(ctx, tx, &api.CreateVpcRequest{CidrBlock: new(api.String("10.231.0.0/24"))})
		if err != nil {
			return err
		}
		subnet, err := s.createSubnet(ctx, tx, &api.CreateSubnetRequest{VpcId: new(api.VpcId(str(vpc.Vpc.VpcId))), CidrBlock: new(api.String("10.231.0.0/25"))})
		if err != nil {
			return err
		}
		created, err := s.createNetworkInterface(ctx, tx, &api.CreateNetworkInterfaceRequest{SubnetId: new(api.SubnetId(str(subnet.Subnet.SubnetId)))})
		if err != nil {
			return err
		}
		eni, err = tx.NetworkInterface(key(ctx, str(created.NetworkInterface.NetworkInterfaceId)))
		if err != nil {
			return err
		}
		eni.Data.Attachment = &api.NetworkInterfaceAttachment{InstanceId: local.record.Data.InstanceId, DeviceIndex: new(api.Integer(0)), DeleteOnTermination: new(api.Boolean(true))}
		if err := tx.PutNetworkInterface(eni); err != nil {
			return err
		}
		local.record.Data.NetworkInterfaces = api.InstanceNetworkInterfaceList{instanceNetworkData(eni.Data)}
		if err := tx.PutInstance(local.record); err != nil {
			return err
		}
		gateway, err := s.createInternetGateway(ctx, tx, &api.CreateInternetGatewayRequest{})
		if err != nil {
			return err
		}
		if _, err = s.attachInternetGateway(ctx, tx, &api.AttachInternetGatewayRequest{InternetGatewayId: new(api.InternetGatewayId(str(gateway.InternetGateway.InternetGatewayId))), VpcId: new(api.VpcId(str(vpc.Vpc.VpcId)))}); err != nil {
			return err
		}
		tables, err := tx.RouteTables(scopeFor(ctx))
		if err != nil {
			return err
		}
		_, err = s.createRoute(ctx, tx, &api.CreateRouteRequest{RouteTableId: new(api.RouteTableId(tables[0].Key.ID)), DestinationCidrBlock: new(api.String("0.0.0.0/0")), GatewayId: new(api.RouteGatewayId(str(gateway.InternetGateway.InternetGatewayId)))})
		return err
	})
	check := func(wantPublic bool) string {
		t.Helper()
		var ip string
		if err := s.repository.View(ctx, func(tx Reader) error {
			spec, err := networkSpecification(ctx, tx, eni)
			if err != nil {
				return err
			}
			projected, err := instanceProjection(ctx, tx, local.record)
			if err != nil {
				return err
			}
			ip = str(projected.PublicIpAddress)
			if (ip != "") != wantPublic || spec.Policy.PublicEgress != wantPublic || spec.Policy.PublicIPv4.IsValid() != wantPublic {
				t.Fatalf("projection=%q public policy=%+v", ip, spec.Policy)
			}
			if wantPublic && spec.Policy.PublicIPv4.String() != ip {
				t.Fatalf("packet address %s != Describe/IMDS address %s", spec.Policy.PublicIPv4, ip)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return ip
	}
	// An attached IGW/default route is not a public-address path.
	check(false)
	mutate(func(tx Transaction) error { return admitAutomaticPublicIPv4(ctx, tx, eni) })
	initial = check(true)
	mutate(func(tx Transaction) error { return s.changeInstanceState(ctx, tx, &local.record, "stopped") })
	check(false)
	mutate(func(tx Transaction) error { return s.changeInstanceState(ctx, tx, &local.record, "pending") })
	if check(true) == initial {
		t.Fatal("stopped ephemeral IPv4 was retained")
	}
	mutate(func(tx Transaction) error {
		allocated, err := s.allocateAddress(ctx, tx, &api.AllocateAddressRequest{})
		if err != nil {
			return err
		}
		_, err = s.associateAddress(ctx, tx, &api.AssociateAddressRequest{AllocationId: new(api.AllocationId(str(allocated.AllocationId))), NetworkInterfaceId: new(api.NetworkInterfaceId(eni.Key.ID))})
		if err != nil {
			return err
		}
		elastic, err = tx.PublicAddress(key(ctx, str(allocated.AllocationId)))
		return err
	})
	if check(true) != str(elastic.Data.PublicIp) {
		t.Fatal("elastic address did not replace ephemeral projection")
	}
	mutate(func(tx Transaction) error { return s.changeInstanceState(ctx, tx, &local.record, "stopped") })
	if check(true) != str(elastic.Data.PublicIp) {
		t.Fatal("stopping released elastic address")
	}
	mutate(func(tx Transaction) error { return s.changeInstanceState(ctx, tx, &local.record, "pending") })
	mutate(func(tx Transaction) error {
		_, err := s.disassociateAddress(ctx, tx, &api.DisassociateAddressRequest{AssociationId: new(api.ElasticIpAssociationId(str(elastic.Data.AssociationId)))})
		return err
	})
	restored := check(true)
	if restored == str(elastic.Data.PublicIp) || restored == initial {
		t.Fatal("disassociation failed to acquire new ephemeral address")
	}
	mutate(func(tx Transaction) error { return releaseInstanceNetworks(ctx, tx, local.record) })
	if err := s.repository.View(ctx, func(tx Reader) error {
		rows, err := tx.PublicAddresses(scopeFor(ctx))
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Automatic || rows[0].Data.AssociationId != nil || str(rows[0].Data.PublicIp) != str(elastic.Data.PublicIp) {
			t.Fatalf("termination did not preserve only the unassociated EIP: %+v", rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
