package stackd_test

import (
	"encoding/json"
	"fmt"
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
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/storage"
)

// The fixture retains actual SQS envelopes and identical regional-history bodies.
// Its bounded fresh-trail probe did not observe these records in S3; S3 delivery
// and ReadOnly selector exclusion follow the cited CloudTrail logging contract,
// not an inferred native absence or a claimed native S3 capture.
func TestCloudTrailEC2NativeServiceEventDeliveryAcrossReopen(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/ec2/service_event_delivery.json")
	if err != nil {
		t.Fatal(err)
	}
	var native struct {
		Account  string
		VPC      string
		Records  []map[string]any
		Messages []map[string]any
	}
	if err := json.Unmarshal(data, &native); err != nil {
		t.Fatal(err)
	}
	if len(native.Records) != 2 || len(native.Messages) != 2 {
		t.Fatal("native fixture must retain both VPC service-event deliveries")
	}
	controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
	objects := s3NativeLoad(t, "s3", "owned_object_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC))
			path := filepath.Join(t.TempDir(), "service-events.sqlite")
			backends := storage.NewMemory()
			closeDB := func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			t.Cleanup(func() { closeDB() })
			cloud, clients, closeStack := startEventDeliveryCloud(t, backends, source)
			reopen := func() {
				closeStack()
				if backend == "sqlite" {
					closeDB()
					backends, closeDB = openSQLiteBackends(t, path)
				}
				cloud, clients, closeStack = startEventDeliveryCloud(t, backends, source)
			}
			trailNativeProvision(t, clients, controls, objects, false)
			setSelector := func(kind trailtypes.ReadWriteType) {
				_, err := trailNativeClient(clients).PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{
					TrailName:      aws.String(controls.Identity["trail_name"]),
					EventSelectors: []trailtypes.EventSelector{{IncludeManagementEvents: aws.Bool(true), ReadWriteType: kind}},
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			setSelector(trailtypes.ReadWriteTypeWriteOnly)
			s3NativeReplay(t, trailNativeClient(clients), controls, "start-logging")
			queues := clients.sqs(eventDeliveryAccount, "test", "")
			queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("vpc-service-events")})
			if err != nil {
				t.Fatal(err)
			}
			rules := eventDeliveryClient(clients, eventDeliveryAccount)
			rule, err := rules.PutRule(t.Context(), &eventbridge.PutRuleInput{
				Name: aws.String("vpc-service-events"), State: eventtypes.RuleStateEnabled,
				EventPattern: aws.String(`{"source":["aws.ec2"],"detail":{"eventName":["CreateVpcResourceCreation","DeleteVpcResourceDeletion"]}}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			queueARN := "arn:aws:sqs:us-east-1:" + eventDeliveryAccount + ":vpc-service-events"
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, queueARN, aws.ToString(rule.RuleArn))
			if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
				t.Fatal(err)
			}
			targets, err := rules.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String("vpc-service-events"), Targets: []eventtypes.Target{{Id: aws.String("queue"), Arn: &queueARN}}})
			if err != nil || targets.FailedEntryCount != 0 {
				t.Fatalf("service-event target: %+v %v", targets, err)
			}
			client := ec2AuditClient(clients)
			created, err := client.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.243.0.0/24")})
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
			bindings := map[string]string{native.Account: eventDeliveryAccount, native.VPC: aws.ToString(created.Vpc.VpcId)}
			for _, resource := range native.Records[0]["resources"].([]any) {
				row := resource.(map[string]any)
				arn := row["ARN"].(string)
				bindings[arn[strings.LastIndex(arn, "/")+1:]] = ids[row["type"].(string)]
			}
			// Retain creation before default-resource deletion, then retain deletion
			// and both accepted deliveries before any delivery worker runs.
			reopen()
			client = ec2AuditClient(clients)
			if _, err := client.DeleteVpc(t.Context(), &ec2.DeleteVpcInput{VpcId: created.Vpc.VpcId}); err != nil {
				t.Fatal(err)
			}
			setSelector(trailtypes.ReadWriteTypeReadOnly)
			excluded, err := client.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.244.0.0/24")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.DeleteVpc(t.Context(), &ec2.DeleteVpcInput{VpcId: excluded.Vpc.VpcId}); err != nil {
				t.Fatal(err)
			}
			reopen()
			currentQueue, err := clients.sqs(eventDeliveryAccount, "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("vpc-service-events")})
			if err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 5*time.Minute)
			trailNativeDrain(t, cloud)
			messages := trailQueueMessages(t, clients, currentQueue.QueueUrl)
			if len(messages) != 2 {
				t.Fatalf("selected service-event messages: got %d want 2", len(messages))
			}
			logs := trailNativeRecords(t, trailNativeObjects(t, s3NativeClient(clients, eventDeliveryAccount, "test"), objects.Identity["log_bucket"], "owned/AWSLogs/"))
			delivered := make(map[string]map[string]any)
			for _, record := range logs {
				if record["eventType"] != "AwsServiceEvent" {
					continue
				}
				name := record["eventName"].(string)
				if delivered[name] != nil {
					t.Fatalf("duplicate or selector-excluded service-event delivery: %#v", record)
				}
				delivered[name] = record
			}
			if len(delivered) != 2 {
				t.Fatalf("selected service-event log records: %#v", delivered)
			}
			for _, expected := range native.Records {
				name := expected["eventName"].(string)
				got := delivered[name]
				encoded, err := json.Marshal(expected)
				if err != nil {
					t.Fatal(err)
				}
				var want map[string]any
				if err := json.Unmarshal(ec2AuditReplace(t, encoded, bindings), &want); err != nil {
					t.Fatal(err)
				}
				want["eventTime"] = "2026-09-16T12:00:00Z"
				want["eventID"], want["requestID"] = got["eventID"], got["requestID"]
				if got["eventID"] == nil || got["eventID"] == "" || got["requestID"] == nil || got["requestID"] == "" || !reflect.DeepEqual(got, want) {
					t.Fatalf("%s S3 record differs from native\n got %#v\nwant %#v", name, got, want)
				}
				// Selector exclusion controls delivery, not regional event history.
				history := ec2VPCServiceEvents(t, trailNativeClient(clients), name)
				if len(history) != 2 {
					t.Fatalf("%s history lost selected/excluded outcome: %+v", name, history)
				}
				foundSelected, foundExcluded := false, false
				for _, row := range history {
					var record map[string]any
					if err := json.Unmarshal([]byte(aws.ToString(row.CloudTrailEvent)), &record); err != nil {
						t.Fatal(err)
					}
					vpcID := record["serviceEventDetails"].(map[string]any)["vpcId"]
					switch vpcID {
					case aws.ToString(created.Vpc.VpcId):
						foundSelected = true
						if !reflect.DeepEqual(record, got) || record["eventID"] != aws.ToString(row.EventId) {
							t.Fatalf("%s history and consumer identities differ: %#v %#v", name, record, got)
						}
					case aws.ToString(excluded.Vpc.VpcId):
						foundExcluded = true
					default:
						t.Fatalf("unrelated VPC service event: %#v", record)
					}
				}
				if !foundSelected || !foundExcluded {
					t.Fatalf("%s history did not retain both VPC identities", name)
				}
			}
			seen := make(map[string]bool)
			for _, message := range messages {
				detail := message["detail"].(map[string]any)
				name := detail["eventName"].(string)
				if seen[name] || !reflect.DeepEqual(detail, delivered[name]) {
					t.Fatalf("EventBridge detail duplicated or differs from delivered S3 record: %#v", message)
				}
				seen[name] = true
				for _, expected := range native.Messages {
					if expected["detail"].(map[string]any)["eventName"] != name {
						continue
					}
					encoded, err := json.Marshal(expected)
					if err != nil {
						t.Fatal(err)
					}
					var want map[string]any
					if err := json.Unmarshal(ec2AuditReplace(t, encoded, bindings), &want); err != nil {
						t.Fatal(err)
					}
					want["id"], want["time"], want["detail"] = message["id"], detail["eventTime"], detail
					if message["id"] == nil || message["id"] == "" || !reflect.DeepEqual(message, want) {
						t.Fatalf("%s EventBridge envelope differs from native\n got %#v\nwant %#v", name, message, want)
					}
				}
			}
		})
	}
}
