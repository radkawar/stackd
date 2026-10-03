package stackd_test

import (
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	asgtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"stackd/clock"
)

func TestAutoScalingSubnetUpdateDerivesAvailabilityZones(t *testing.T) {
	fixture := asgFixture(t, "controls")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Calls[0].StartedAt.Add(-time.Minute))
			bindings := map[string]string{}
			clients, reopen := asgRetainedCloud(t, backend, fixture, source, bindings, nil)
			asgPrerequisite(t, clients, fixture.Region, fixture.row(t, "create-template"), bindings, nil)
			ec2client := asgEC2(clients, fixture.Region)
			vpc, err := ec2client.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.236.0.0/16")})
			if err != nil {
				t.Fatal(err)
			}
			otherVpc, err := ec2client.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.237.0.0/16")})
			if err != nil {
				t.Fatal(err)
			}
			oldSubnet, err := ec2client.CreateSubnet(t.Context(), &ec2.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: aws.String("10.236.1.0/24"), AvailabilityZone: aws.String("us-east-1a")})
			if err != nil {
				t.Fatal(err)
			}
			newSubnet, err := ec2client.CreateSubnet(t.Context(), &ec2.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: aws.String("10.236.2.0/24"), AvailabilityZone: aws.String("us-east-1b")})
			if err != nil {
				t.Fatal(err)
			}
			otherSubnet, err := ec2client.CreateSubnet(t.Context(), &ec2.CreateSubnetInput{VpcId: otherVpc.Vpc.VpcId, CidrBlock: aws.String("10.237.1.0/24"), AvailabilityZone: aws.String("us-east-1a")})
			if err != nil {
				t.Fatal(err)
			}
			client := asgClient(clients, fixture.Region, asgRoot(), clients.server.Client())
			template := ecsControlBody(t, fixture.row(t, "create-template").Output)["LaunchTemplate"].(map[string]any)["LaunchTemplateId"].(string)
			name := aws.String("placement-update")
			if _, err := client.CreateAutoScalingGroup(t.Context(), &autoscaling.CreateAutoScalingGroupInput{AutoScalingGroupName: name, MinSize: aws.Int32(0), MaxSize: aws.Int32(2), DesiredCapacity: aws.Int32(0), VPCZoneIdentifier: oldSubnet.Subnet.SubnetId, LaunchTemplate: &asgtypes.LaunchTemplateSpecification{LaunchTemplateId: aws.String(bindings[template])}}); err != nil {
				t.Fatal(err)
			}
			assertPlacement := func(subnet *ec2.CreateSubnetOutput) {
				t.Helper()
				out, err := client.DescribeAutoScalingGroups(t.Context(), &autoscaling.DescribeAutoScalingGroupsInput{AutoScalingGroupNames: []string{*name}})
				if err != nil {
					t.Fatal(err)
				}
				if len(out.AutoScalingGroups) != 1 {
					t.Fatalf("group inventory=%+v", out.AutoScalingGroups)
				}
				g := out.AutoScalingGroups[0]
				if aws.ToString(g.VPCZoneIdentifier) != aws.ToString(subnet.Subnet.SubnetId) || !slices.Equal(g.AvailabilityZones, []string{aws.ToString(subnet.Subnet.AvailabilityZone)}) || !slices.Equal(g.AvailabilityZoneIds, []string{aws.ToString(subnet.Subnet.AvailabilityZoneId)}) || aws.ToInt32(g.DesiredCapacity) != 0 {
					t.Fatalf("incorrect derived placement or changed capacity: %+v", g)
				}
			}
			for _, rejected := range []struct {
				name, subnets string
				zones         []string
			}{
				{"explicit-zone-mismatch", *newSubnet.Subnet.SubnetId, []string{"us-east-1a"}},
				{"mixed-vpcs", *oldSubnet.Subnet.SubnetId + "," + *otherSubnet.Subnet.SubnetId, nil},
			} {
				t.Run(rejected.name, func(t *testing.T) {
					_, err := client.UpdateAutoScalingGroup(t.Context(), &autoscaling.UpdateAutoScalingGroupInput{AutoScalingGroupName: name, VPCZoneIdentifier: aws.String(rejected.subnets), AvailabilityZones: rejected.zones})
					assertAPIError(t, err, "ValidationError")
					assertPlacement(oldSubnet)
				})
			}
			// VPCZoneIdentifier is the only changed placement property. Old derived
			// zones must not become explicit constraints on this request.
			if _, err := client.UpdateAutoScalingGroup(t.Context(), &autoscaling.UpdateAutoScalingGroupInput{AutoScalingGroupName: name, VPCZoneIdentifier: newSubnet.Subnet.SubnetId}); err != nil {
				t.Fatalf("subnet-only update retained old AvailabilityZones: %v", err)
			}
			assertPlacement(newSubnet)
			clients = reopen()
			client = asgClient(clients, fixture.Region, asgRoot(), clients.server.Client())
			assertPlacement(newSubnet)
		})
	}
}
