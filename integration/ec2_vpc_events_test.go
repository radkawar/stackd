package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"stackd"
	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
)

func ec2VPCServiceEvents(t *testing.T, client *cloudtrail.Client, name string) []trailtypes.Event {
	t.Helper()
	out, err := client.LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: &name}}})
	if err != nil {
		t.Fatal(err)
	}
	return out.Events
}

func TestEC2NativeVPCServiceEventsAcrossReopen(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/ec2/audit.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Events []struct{ Event map[string]any }
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	native := map[string]map[string]any{}
	for _, row := range fixture.Events {
		if row.Event["eventType"] == "AwsServiceEvent" {
			name := row.Event["eventName"].(string)
			if native[name] == nil {
				native[name] = row.Event
			}
		}
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 16, 10, 0, 0, 123000000, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source})
			client := ec2AuditClient(clients)
			created, err := client.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.240.0.0/24")})
			if err != nil {
				t.Fatal(err)
			}
			filters := []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{aws.ToString(created.Vpc.VpcId)}}}
			groups, err := client.DescribeSecurityGroups(t.Context(), &ec2.DescribeSecurityGroupsInput{Filters: filters})
			if err != nil || len(groups.SecurityGroups) != 1 {
				t.Fatalf("default group: %+v %v", groups, err)
			}
			routes, err := client.DescribeRouteTables(t.Context(), &ec2.DescribeRouteTablesInput{Filters: filters})
			if err != nil || len(routes.RouteTables) != 1 {
				t.Fatalf("main route: %+v %v", routes, err)
			}
			acls, err := client.DescribeNetworkAcls(t.Context(), &ec2.DescribeNetworkAclsInput{Filters: filters})
			if err != nil || len(acls.NetworkAcls) != 1 {
				t.Fatalf("default ACL: %+v %v", acls, err)
			}
			ids := map[string]string{"AWS::EC2::SecurityGroup": aws.ToString(groups.SecurityGroups[0].GroupId), "AWS::EC2::RouteTable": aws.ToString(routes.RouteTables[0].RouteTableId), "AWS::EC2::NetworkAcl": aws.ToString(acls.NetworkAcls[0].NetworkAclId)}
			clients = reopen()
			client = ec2AuditClient(clients)
			if _, err := client.DeleteVpc(t.Context(), &ec2.DeleteVpcInput{VpcId: created.Vpc.VpcId}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			for _, name := range []string{"CreateVpcResourceCreation", "DeleteVpcResourceDeletion"} {
				rows := ec2VPCServiceEvents(t, trailNativeClient(clients), name)
				if len(rows) != 1 {
					t.Fatalf("%s: got %d events", name, len(rows))
				}
				if rows[0].Username != nil || len(rows[0].Resources) != 0 {
					t.Fatalf("service event acquired customer lookup identity: %+v", rows[0])
				}
				var got map[string]any
				if err := json.Unmarshal([]byte(aws.ToString(rows[0].CloudTrailEvent)), &got); err != nil {
					t.Fatal(err)
				}
				expected := native[name]
				if expected == nil {
					t.Fatalf("missing retained %s", name)
				}
				bindings := map[string]string{"000000000000": eventDeliveryAccount, expected["serviceEventDetails"].(map[string]any)["vpcId"].(string): aws.ToString(created.Vpc.VpcId)}
				for _, value := range expected["resources"].([]any) {
					resource := value.(map[string]any)
					arn := resource["ARN"].(string)
					bindings[arn[strings.LastIndex(arn, "/")+1:]] = ids[resource["type"].(string)]
				}
				encoded, err := json.Marshal(expected)
				if err != nil {
					t.Fatal(err)
				}
				var want map[string]any
				if err := json.Unmarshal(ec2AuditReplace(t, encoded, bindings), &want); err != nil {
					t.Fatal(err)
				}
				want["eventTime"] = source.Now().UTC().Format(time.RFC3339)
				want["eventID"], want["requestID"] = got["eventID"], got["requestID"]
				if got["eventID"] != aws.ToString(rows[0].EventId) {
					t.Fatalf("history identity differs from retained body: %+v", rows[0])
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s differs from native\n got %#v\nwant %#v", name, got, want)
				}
			}
		})
	}
}

type rejectVPCServiceEvent struct{ journal.Storage }

func (sink rejectVPCServiceEvent) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if call.ServiceEvent {
		return errors.New("injected VPC service event append failure")
	}
	return sink.Storage.AppendAPICallCompleted(ctx, envelope, call)
}

func TestEC2VPCServiceEventFailureRollsBackDefaultResources(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "vpc.sqlite"))
			}
			backends.Journal = rejectVPCServiceEvent{backends.Journal}
			_, clients, _ := startEventDeliveryCloud(t, backends, clock.NewManual(time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)))
			client := ec2AuditClient(clients)
			_, err := client.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.240.0.0/24")})
			assertAPIError(t, err, "InternalError")
			vpcs, err := client.DescribeVpcs(t.Context(), &ec2.DescribeVpcsInput{})
			if err != nil || len(vpcs.Vpcs) != 0 {
				t.Fatalf("failed VPC committed: %+v %v", vpcs, err)
			}
			groups, err := client.DescribeSecurityGroups(t.Context(), &ec2.DescribeSecurityGroupsInput{})
			if err != nil || len(groups.SecurityGroups) != 0 {
				t.Fatalf("failed default groups committed: %+v %v", groups, err)
			}
			routes, err := client.DescribeRouteTables(t.Context(), &ec2.DescribeRouteTablesInput{})
			if err != nil || len(routes.RouteTables) != 0 {
				t.Fatalf("failed main routes committed: %+v %v", routes, err)
			}
			acls, err := client.DescribeNetworkAcls(t.Context(), &ec2.DescribeNetworkAclsInput{})
			if err != nil || len(acls.NetworkAcls) != 0 {
				t.Fatalf("failed default ACLs committed: %+v %v", acls, err)
			}
			if events := ec2VPCServiceEvents(t, trailNativeClient(clients), "CreateVpcResourceCreation"); len(events) != 0 {
				t.Fatalf("rolled-back outcome visible: %+v", events)
			}
		})
	}
}
