package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type availabilityCapture struct {
	Label, Operation, Region, Code string
	Input                          json.RawMessage
	Output                         struct {
		AvailabilityZones []ec2types.AvailabilityZone
		Regions           []ec2types.Region
		Subnet            *ec2types.Subnet
	}
}

func availabilityCaptures(t *testing.T) []availabilityCapture {
	t.Helper()
	var captures []availabilityCapture
	for _, name := range []string{"availability_zones.json", "availability_zones_supplement.json"} {
		data, err := os.ReadFile("../testdata/aws/ec2/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct{ Calls []availabilityCapture }
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		for index := range fixture.Calls {
			if fixture.Calls[index].Label == "" {
				fixture.Calls[index].Label = fmt.Sprintf("%s-%d", name, index)
			}
		}
		captures = append(captures, fixture.Calls...)
	}
	return captures
}

func availabilityClient(c cloudClients, region, accountID string) *ec2.Client {
	return ec2.New(ec2.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(accountID, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func availabilityIdentity(zones []ec2types.AvailabilityZone) map[string]string {
	out := map[string]string{}
	for _, zone := range zones {
		out[aws.ToString(zone.ZoneId)] = aws.ToString(zone.ZoneName)
	}
	return out
}

// Physical IDs are fixture expectations, never identity placeholders. Account
// names are bound by physical ID because the native legacy account's names must
// not become a universal mapping for every emulator account.
func TestEC2NativeAvailabilitySelectionAndPlacement(t *testing.T) {
	captures := availabilityCaptures(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount})
			client := availabilityClient(clients, "us-east-1", "test")
			all, err := client.DescribeAvailabilityZones(t.Context(), &ec2.DescribeAvailabilityZonesInput{AllAvailabilityZones: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			identities := availabilityIdentity(all.AvailabilityZones)
			names := map[string]string{}
			for _, capture := range captures {
				if capture.Label != "all-zones-us-east-1" {
					continue
				}
				for _, native := range capture.Output.AvailabilityZones {
					id := aws.ToString(native.ZoneId)
					name, ok := identities[id]
					if !ok || name == "" {
						t.Fatalf("missing captured physical zone %s", id)
					}
					names[aws.ToString(native.ZoneName)] = name
				}
				if len(names) != len(identities) {
					t.Fatalf("physical zone set differs from native: %v", identities)
				}
			}
			for _, zone := range all.AvailabilityZones {
				if parent := aws.ToString(zone.ParentZoneId); parent != "" && aws.ToString(zone.ParentZoneName) != identities[parent] {
					t.Fatalf("parent name/ID mismatch: %+v", zone)
				}
			}
			for _, capture := range captures {
				if capture.Region != "us-east-1" || capture.Operation != "describe-availability-zones" {
					continue
				}
				t.Run(capture.Label, func(t *testing.T) {
					input := ec2AuditReplace(t, capture.Input, names)
					var request ec2.DescribeAvailabilityZonesInput
					if err := json.Unmarshal(input, &request); err != nil {
						t.Fatal(err)
					}
					got, err := client.DescribeAvailabilityZones(t.Context(), &request)
					if capture.Code != "Success" {
						assertAPIError(t, err, capture.Code)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					want := make([]string, 0, len(capture.Output.AvailabilityZones))
					actual := make([]string, 0, len(got.AvailabilityZones))
					for _, zone := range capture.Output.AvailabilityZones {
						want = append(want, aws.ToString(zone.ZoneId))
					}
					for _, zone := range got.AvailabilityZones {
						id := aws.ToString(zone.ZoneId)
						if identities[id] != aws.ToString(zone.ZoneName) {
							t.Fatalf("selection changed zone mapping: %+v", zone)
						}
						actual = append(actual, id)
					}
					slices.Sort(want)
					slices.Sort(actual)
					if !reflect.DeepEqual(want, actual) {
						t.Fatalf("filtered physical IDs %v, native %v", actual, want)
					}
				})
			}
			vpc, err := client.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.234.0.0/16")})
			if err != nil {
				t.Fatal(err)
			}
			for _, capture := range captures {
				if capture.Operation != "create-subnet" {
					continue
				}
				t.Run(capture.Label, func(t *testing.T) {
					var request ec2.CreateSubnetInput
					if err := json.Unmarshal(ec2AuditReplace(t, capture.Input, names), &request); err != nil {
						t.Fatal(err)
					}
					request.VpcId = vpc.Vpc.VpcId
					got, err := client.CreateSubnet(t.Context(), &request)
					if capture.Code != "Success" {
						assertAPIError(t, err, capture.Code)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					id, name := aws.ToString(got.Subnet.AvailabilityZoneId), aws.ToString(got.Subnet.AvailabilityZone)
					if name == "" || identities[id] != name {
						t.Fatalf("subnet not placed in discovered physical zone: %+v", got.Subnet)
					}
					if request.AvailabilityZone != nil || request.AvailabilityZoneId != nil {
						if id != aws.ToString(capture.Output.Subnet.AvailabilityZoneId) {
							t.Fatalf("explicit subnet placement %s, native %s", id, aws.ToString(capture.Output.Subnet.AvailabilityZoneId))
						}
					}
					clients = reopen()
					client = availabilityClient(clients, "us-east-1", "test")
					retained, err := client.DescribeSubnets(t.Context(), &ec2.DescribeSubnetsInput{SubnetIds: []string{aws.ToString(got.Subnet.SubnetId)}})
					if err != nil || len(retained.Subnets) != 1 {
						t.Fatalf("retained subnet: %+v %v", retained, err)
					}
					if aws.ToString(retained.Subnets[0].AvailabilityZoneId) != id || aws.ToString(retained.Subnets[0].AvailabilityZone) != name {
						t.Fatal("reopen changed subnet placement")
					}
					after, err := client.DescribeAvailabilityZones(t.Context(), &ec2.DescribeAvailabilityZonesInput{AllAvailabilityZones: aws.Bool(true)})
					if err != nil || !reflect.DeepEqual(identities, availabilityIdentity(after.AvailabilityZones)) {
						t.Fatalf("reopen changed physical mapping: %+v %v", after, err)
					}
					if _, err := client.DeleteSubnet(t.Context(), &ec2.DeleteSubnetInput{SubnetId: got.Subnet.SubnetId}); err != nil {
						t.Fatal(err)
					}
				})
			}
			west := availabilityClient(clients, "us-west-2", "test")
			_, err = west.DescribeAvailabilityZones(t.Context(), &ec2.DescribeAvailabilityZonesInput{ZoneIds: []string{aws.ToString(all.AvailabilityZones[0].ZoneId)}})
			assertAPIError(t, err, "InvalidParameterValue")
			other := availabilityClient(clients, "us-east-1", "999999999999")
			otherZones, err := other.DescribeAvailabilityZones(t.Context(), &ec2.DescribeAvailabilityZonesInput{AllAvailabilityZones: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, zone := range otherZones.AvailabilityZones {
				id, name := aws.ToString(zone.ZoneId), aws.ToString(zone.ZoneName)
				if identities[id] == "" || seen[name] {
					t.Fatalf("other account fabricated or aliased zone: %+v", zone)
				}
				seen[name] = true
			}
			_, err = other.DescribeVpcs(t.Context(), &ec2.DescribeVpcsInput{VpcIds: []string{aws.ToString(vpc.Vpc.VpcId)}})
			assertAPIError(t, err, "InvalidVpcID.NotFound")
			if _, err := client.DeleteVpc(t.Context(), &ec2.DeleteVpcInput{VpcId: vpc.Vpc.VpcId}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEC2NativeRegionsAndAccountOptIn(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source})
			client := availabilityClient(clients, "us-east-1", "test")
			for _, capture := range availabilityCaptures(t) {
				if capture.Operation != "describe-regions" || capture.Label == "regions-default" {
					continue
				}
				action := "DescribeRegions"
				_, err := awstest.CallSDK(t.Context(), client, action, capture.Input)
				if capture.Code != "Success" {
					assertAPIError(t, err, capture.Code)
				} else if err != nil {
					t.Fatal(err)
				}
			}
			region := "af-south-1"
			check := func(enabled bool) {
				t.Helper()
				got, err := client.DescribeRegions(t.Context(), &ec2.DescribeRegionsInput{Filters: []ec2types.Filter{{Name: aws.String("region-name"), Values: []string{region}}}})
				if err != nil {
					t.Fatal(err)
				}
				if (len(got.Regions) == 1) != enabled {
					t.Fatalf("region enabled=%t: %+v", enabled, got.Regions)
				}
				explicit, err := client.DescribeRegions(t.Context(), &ec2.DescribeRegionsInput{RegionNames: []string{region}})
				if err != nil || len(explicit.Regions) != 1 {
					t.Fatalf("explicit disabled-region selection: %+v %v", explicit, err)
				}
				want := "not-opted-in"
				if enabled {
					want = "opted-in"
				}
				if aws.ToString(explicit.Regions[0].OptInStatus) != want {
					t.Fatalf("region opt-in status %+v, want %s", explicit.Regions[0], want)
				}
			}
			check(false)
			if _, err := clients.account("test", "test", "").EnableRegion(t.Context(), &account.EnableRegionInput{RegionName: &region}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 3*time.Minute)
			clients = reopen()
			client = availabilityClient(clients, "us-east-1", "test")
			check(true)
			zones, err := availabilityClient(clients, region, "test").DescribeAvailabilityZones(t.Context(), &ec2.DescribeAvailabilityZonesInput{})
			if err != nil {
				t.Fatal(err)
			}
			for _, zone := range zones.AvailabilityZones {
				if aws.ToString(zone.RegionName) != region {
					t.Fatalf("cross-region physical zone: %+v", zone)
				}
			}
			other := availabilityClient(clients, "us-east-1", "999999999999")
			otherRegions, err := other.DescribeRegions(t.Context(), &ec2.DescribeRegionsInput{RegionNames: []string{region}})
			if err != nil || len(otherRegions.Regions) != 1 || aws.ToString(otherRegions.Regions[0].OptInStatus) != "not-opted-in" {
				t.Fatalf("account opt-in leaked: %+v %v", otherRegions, err)
			}
			for _, missing := range []string{"ap-east-2", "me-south-1"} {
				if _, err := clients.account("test", "test", "").EnableRegion(t.Context(), &account.EnableRegionInput{RegionName: &missing}); err != nil {
					t.Fatal(err)
				}
				advanceClock(t, source, 3*time.Minute)
				_, err := availabilityClient(clients, missing, "test").DescribeAvailabilityZones(t.Context(), &ec2.DescribeAvailabilityZonesInput{})
				assertAPIError(t, err, "UnsupportedOperation")
			}
			all, err := client.DescribeRegions(t.Context(), &ec2.DescribeRegionsInput{AllRegions: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			gotRegions := map[string]string{}
			for _, item := range all.Regions {
				gotRegions[aws.ToString(item.RegionName)] = aws.ToString(item.Endpoint)
			}
			for _, capture := range availabilityCaptures(t) {
				if capture.Label != "regions-all" {
					continue
				}
				wantRegions := map[string]string{}
				for _, item := range capture.Output.Regions {
					wantRegions[aws.ToString(item.RegionName)] = aws.ToString(item.Endpoint)
				}
				if !reflect.DeepEqual(gotRegions, wantRegions) {
					t.Fatalf("region catalogue differs from native: got %v, want %v", gotRegions, wantRegions)
				}
			}
		})
	}
}
