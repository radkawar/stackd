package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"stackd"
)

func TestEC2NativeNetworkInterfaces(t *testing.T) {
	for _, name := range []string{"network_interfaces", "network_interface_addresses", "network_interface_types"} {
		t.Run(name, func(t *testing.T) { replayEC2NetworkInterfaceFixture(t, name) })
	}
}

func replayEC2NetworkInterfaceFixture(t *testing.T, name string) {
	t.Helper()
	body, err := os.ReadFile("../testdata/aws/ec2/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		StartedAt  time.Time `json:"started_at"`
		Calls      []ec2NetworkCapture
		CloudTrail struct {
			CorrelatedEvents []struct{ Event map[string]any } `json:"correlated_events"`
		}
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	events := make(map[string]map[string]any, len(fixture.CloudTrail.CorrelatedEvents))
	for _, correlated := range fixture.CloudTrail.CorrelatedEvents {
		events[correlated.Event["requestID"].(string)] = correlated.Event
	}
	for index := range fixture.Calls {
		fixture.Calls[index].Audit = events[fixture.Calls[index].RequestID]
		if fixture.Calls[index].StartedAt.IsZero() {
			fixture.Calls[index].StartedAt = fixture.StartedAt
		}
	}
	// The shared harness calls the real SDK against memory and reopened SQLite,
	// and compares native responses and correlated audit records independently.
	replayEC2NetworkRows(t, fixture.Calls)
}

func TestEC2NativeNetworkInterfaceCreationTokens(t *testing.T) {
	body, err := os.ReadFile("../testdata/aws/ec2/network_interface_idempotency.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Captures []struct {
			StartedAt time.Time `json:"started_at"`
			Calls     []ec2NetworkCapture
		}
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	for index, capture := range fixture.Captures {
		t.Run(fmt.Sprintf("capture_%d", index+1), func(t *testing.T) {
			rows := make([]ec2NetworkCapture, 0, len(capture.Calls))
			for _, row := range capture.Calls {
				if row.Operation == "create-network-interface" && row.Code == "InternalError" {
					var input struct{ ClientToken *string }
					if err := json.Unmarshal(row.Input, &input); err != nil {
						t.Fatal(err)
					}
					if input.ClientToken != nil && strings.TrimSpace(*input.ClientToken) == "" {
						t.Run(row.Label, func(t *testing.T) {
							t.Skip("native blank ClientToken requests failed internally; fixture retained, AWS crash behavior is not a supported idempotency contract")
						})
						continue
					}
				}
				if row.Label == "token-case" {
					t.Run(row.Label, func(t *testing.T) {
						t.Skip("native case-only token mismatch remains an unverified boundary; fixture retained, no case-folding behavior claimed")
					})
					continue
				}
				if row.StartedAt.IsZero() {
					row.StartedAt = capture.StartedAt
				}
				rows = append(rows, row)
			}
			replayEC2NetworkRows(t, rows)
		})
	}
}

func TestEC2NetworkInterfaceVPCPolicy(t *testing.T) {
	body, err := os.ReadFile("../testdata/ec2/network_interface_authorization.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name          string
			Policy, Input json.RawMessage
			Error         string
		}
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount})
			clientFor := func(key, secret string) *ec2.Client {
				return ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			root := clientFor(eventDeliveryAccount, "test")
			var replacements, subnetIDs []string
			for index, name := range []string{"ALLOWED", "FOREIGN"} {
				cidr := fmt.Sprintf("10.%d.0.0/28", 244+index)
				vpc, err := root.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String(fmt.Sprintf("10.%d.0.0/24", 244+index))})
				if err != nil {
					t.Fatal(err)
				}
				subnet, err := root.CreateSubnet(t.Context(), &ec2.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: &cidr})
				if err != nil {
					t.Fatal(err)
				}
				groups, err := root.DescribeSecurityGroups(t.Context(), &ec2.DescribeSecurityGroupsInput{Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{aws.ToString(vpc.Vpc.VpcId)}}}})
				if err != nil || len(groups.SecurityGroups) != 1 {
					t.Fatalf("default group: %+v %v", groups, err)
				}
				subnetIDs = append(subnetIDs, aws.ToString(subnet.Subnet.SubnetId))
				replacements = append(replacements,
					"$"+name+"_VPC_ARN", "arn:aws:ec2:us-east-1:"+eventDeliveryAccount+":vpc/"+aws.ToString(vpc.Vpc.VpcId),
					"$"+name+"_SUBNET", aws.ToString(subnet.Subnet.SubnetId),
					"$"+name+"_GROUP", aws.ToString(groups.SecurityGroups[0].GroupId))
			}
			_, accessKey, secretKey := clients.user(t, eventDeliveryAccount, "NetworkDelegated")
			clients = reopen()
			root = clientFor(eventDeliveryAccount, "test")
			delegated := clientFor(accessKey, secretKey)
			bind := strings.NewReplacer(replacements...)
			for _, test := range fixture.Cases {
				t.Run(test.Name, func(t *testing.T) {
					putUserPolicy(t, clients.iam(eventDeliveryAccount, "test", ""), "NetworkDelegated", bind.Replace(string(test.Policy)))
					var input ec2.CreateNetworkInterfaceInput
					if err := json.Unmarshal([]byte(bind.Replace(string(test.Input))), &input); err != nil {
						t.Fatal(err)
					}
					created, err := delegated.CreateNetworkInterface(t.Context(), &input)
					if test.Error != "" {
						assertAPIError(t, err, test.Error)
					} else {
						if err != nil {
							t.Fatal(err)
						}
						if aws.ToString(created.NetworkInterface.SubnetId) != aws.ToString(input.SubnetId) {
							t.Fatalf("created interface escaped requested subnet: %+v", created.NetworkInterface)
						}
						if _, err := root.DeleteNetworkInterface(t.Context(), &ec2.DeleteNetworkInterfaceInput{NetworkInterfaceId: created.NetworkInterface.NetworkInterfaceId}); err != nil {
							t.Fatal(err)
						}
					}
					interfaces, err := root.DescribeNetworkInterfaces(t.Context(), &ec2.DescribeNetworkInterfacesInput{})
					if err != nil || len(interfaces.NetworkInterfaces) != 0 {
						t.Fatalf("authorization/deletion left an interface: %+v %v", interfaces, err)
					}
					subnets, err := root.DescribeSubnets(t.Context(), &ec2.DescribeSubnetsInput{SubnetIds: subnetIDs})
					if err != nil || len(subnets.Subnets) != len(subnetIDs) {
						t.Fatalf("retained subnets: %+v %v", subnets, err)
					}
					for _, subnet := range subnets.Subnets {
						if aws.ToInt32(subnet.AvailableIpAddressCount) != 11 {
							t.Fatalf("denial or deletion leaked subnet capacity: %+v", subnet)
						}
					}
				})
			}
		})
	}
}
