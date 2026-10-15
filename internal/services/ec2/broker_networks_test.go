package ec2_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
)

// These exercise EC2 reservations/policy and durable ownership. The Kafka owner
// must separately prove Docker endpoint attachment and actual broker packets.
func TestBrokerNetworkOwnershipPolicyAndReopen(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
			broker := awsctx.WithMetadata(root, awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012", InvokedBy: "kafka.amazonaws.com", IssuerARN: "arn:aws:iam::123456789012:role/aws-service-role/kafka.amazonaws.com/AWSServiceRoleForKafka"})
			var repository ec2.Repository = ec2.NewMemoryRepository(nil)
			var db *sql.DB
			var service *ec2.Service
			path := filepath.Join(t.TempDir(), "brokers.sqlite")
			open := func() {
				t.Helper()
				if backend == "sqlite" {
					var err error
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					repository = sqlec2.New(db)
				}
				service = ec2.New(ec2.Config{Repository: repository})
			}
			close := func() {
				if service != nil {
					_ = service.Close()
				}
				if db != nil {
					_ = db.Close()
					db = nil
				}
			}
			open()
			t.Cleanup(close)
			vpc := subnetResult[api.CreateVpcResult](t, root, service, "ec2", "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.181.0.0/16"))}).Vpc
			var subnets []string
			for i, zone := range []string{"us-east-1a", "us-east-1b"} {
				cidr := []string{"10.181.1.0/24", "10.181.2.0/24"}[i]
				subnet := subnetResult[api.CreateSubnetResult](t, root, service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(*vpc.VpcId)), CidrBlock: new(api.String(cidr)), AvailabilityZone: new(api.String(zone))}).Subnet
				subnets = append(subnets, string(*subnet.SubnetId))
			}
			group := subnetResult[api.CreateSecurityGroupResult](t, root, service, "ec2", "CreateSecurityGroup", &api.CreateSecurityGroupRequest{VpcId: new(api.VpcId(*vpc.VpcId)), GroupName: new(api.String("brokers")), Description: new(api.String("native brokers"))})
			slices.Sort(subnets)
			identity := ec2.BrokerNetworkIdentity{ClusterARN: "arn:aws:kafka:us-east-1:123456789012:cluster/native/11111111-1111-4111-8111-111111111111-2", Incarnation: "retained-incarnation", BrokerID: 1}
			request := ec2.BrokerNetworkRequest{Identity: identity, SubnetIDs: subnets, SecurityGroups: []string{string(*group.GroupId)}}
			if _, err := service.AllocateBrokerNetwork(root, request); err == nil {
				t.Fatal("public caller obtained broker authority")
			}
			bad := request
			bad.SubnetIDs = []string{subnets[0], subnets[0]}
			if _, err := service.AllocateBrokerNetwork(broker, bad); err == nil {
				t.Fatal("duplicate subnet admitted")
			}
			first, err := service.AllocateBrokerNetwork(broker, request)
			if err != nil {
				t.Fatal(err)
			}
			id := string(*first.Interface.NetworkInterfaceId)
			if string(*first.Interface.SubnetId) != subnets[0] || !first.Network.Policy.Subnet.Contains(first.Network.Address) || string(*first.Interface.AvailabilityZone) == "" {
				t.Fatalf("not genuine selected subnet capacity: %#v", first)
			}
			again, err := service.AllocateBrokerNetwork(broker, request)
			if err != nil || string(*again.Interface.NetworkInterfaceId) != id {
				t.Fatalf("replay changed identity: %#v %v", again, err)
			}
			secondRequest := request
			secondRequest.Identity.BrokerID = 2
			second, err := service.AllocateBrokerNetwork(broker, secondRequest)
			if err != nil || string(*second.Interface.SubnetId) != subnets[1] {
				t.Fatalf("DEFAULT distribution lost AZ: %#v %v", second, err)
			}
			foreign := identity
			foreign.Incarnation = "different-incarnation"
			if err := service.ReleaseBrokerNetwork(broker, foreign, id); err == nil {
				t.Fatal("foreign incarnation released interface")
			}
			if _, err := subnetCommand(t, root, service, "ec2", "DeleteNetworkInterface", &api.DeleteNetworkInterfaceRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(id))}); err == nil {
				t.Fatal("public caller deleted requester-managed broker ENI")
			}
			subnetResult[api.AuthorizeSecurityGroupIngressResult](t, root, service, "ec2", "AuthorizeSecurityGroupIngress", &api.AuthorizeSecurityGroupIngressRequest{GroupId: new(api.SecurityGroupId(*group.GroupId)), IpPermissions: api.IpPermissionList{{IpProtocol: new(api.String("tcp")), FromPort: new(api.Integer(9092)), ToPort: new(api.Integer(9092)), IpRanges: api.IpRangeList{{CidrIp: new(api.String("10.181.0.0/16"))}}}}})
			close()
			open()
			observed, err := service.ObserveBrokerNetwork(broker, identity, id)
			if err != nil || observed.Network.Address != first.Network.Address || len(observed.Network.Policy.SecurityIngress) != 1 || observed.Network.Policy.SecurityIngress[0].FromPort != 9092 {
				t.Fatalf("reopen/current packet authority lost: %#v %v", observed, err)
			}
			if err := service.ReleaseBrokerNetwork(broker, identity, id); err != nil {
				t.Fatal(err)
			}
			if err := service.ReleaseBrokerNetwork(broker, identity, id); err != nil {
				t.Fatalf("idempotent release: %v", err)
			}
			if _, err := service.ObserveBrokerNetwork(broker, identity, id); !errors.Is(err, ec2.ErrNotFound) {
				t.Fatalf("released interface observable: %v", err)
			}
			if _, err := service.AllocateBrokerNetwork(broker, request); err == nil {
				t.Fatal("late retry resurrected released incarnation")
			}
			request.Identity = foreign
			replacement, err := service.AllocateBrokerNetwork(broker, request)
			if err != nil || replacement.Network.Address != first.Network.Address || string(*replacement.Interface.NetworkInterfaceId) == id {
				t.Fatalf("capacity not returned: %#v %v", replacement, err)
			}
			if err := service.ReleaseBrokerNetwork(broker, identity, id); err != nil {
				t.Fatal(err)
			}
			if _, err := service.ObserveBrokerNetwork(broker, foreign, string(*replacement.Interface.NetworkInterfaceId)); err != nil {
				t.Fatalf("stale release damaged replacement: %v", err)
			}
			if err := service.ReleaseBrokerNetwork(broker, foreign, string(*replacement.Interface.NetworkInterfaceId)); err != nil {
				t.Fatal(err)
			}
			if err := service.ReleaseBrokerNetwork(broker, secondRequest.Identity, string(*second.Interface.NetworkInterfaceId)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
