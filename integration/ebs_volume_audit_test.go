package stackd_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd"
	ebsdomain "stackd/internal/services/ebs"
	"stackd/storage"
)

func TestEBSVolumeNativeAuditDelivery(t *testing.T) {
	var native ebsVolumeConformanceFixture
	awsReadFixture(t, "ebs/volume_data.json", &native)
	rows := map[string]ebsNativeCall{}
	for _, row := range native.Calls {
		rows[row.Label] = row
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var cloud *stackd.Stack
			var backends *storage.Backends
			v := newEBSVolumeReplay(t, native.ebsCopyFixture, backend, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				backends = config.Storage
				var server *httptest.Server
				cloud, server = startPublicCloud(t, config)
				return cloud, server
			})
			trail := func(account string) *cloudtrail.Client {
				return cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: aws.String(v.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: v.clients.server.Client(), RetryMaxAttempts: 1})
			}
			bucketClient := func(account string) *s3.Client {
				return s3NativeClient(v.clients, account, "test")
			}
			for _, account := range []string{"111111111111", "222222222222"} {
				bucket := "volume-audit-" + account
				client := bucketClient(account)
				if _, err := client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
					t.Fatal(err)
				}
				policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::%s","Condition":{"StringEquals":{"aws:SourceArn":"arn:aws:cloudtrail:us-east-1:%s:trail/volume-audit"}}},{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/AWSLogs/%s/*","Condition":{"StringEquals":{"aws:SourceArn":"arn:aws:cloudtrail:us-east-1:%s:trail/volume-audit","s3:x-amz-acl":"bucket-owner-full-control"}}}]}`, bucket, account, bucket, account, account)
				if _, err := client.PutBucketPolicy(t.Context(), &s3.PutBucketPolicyInput{Bucket: aws.String(bucket), Policy: aws.String(policy)}); err != nil {
					t.Fatal(err)
				}
				if _, err := trail(account).CreateTrail(t.Context(), &cloudtrail.CreateTrailInput{Name: aws.String("volume-audit"), S3BucketName: aws.String(bucket)}); err != nil {
					t.Fatal(err)
				}
				selectors := []trailtypes.AdvancedEventSelector{
					{Name: aws.String("management"), FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Management"}}}},
					{Name: aws.String("snapshot-data"), FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Data"}}, {Field: aws.String("resources.type"), Equals: []string{"AWS::EC2::Snapshot"}}}},
				}
				if _, err := trail(account).PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{TrailName: aws.String("volume-audit"), AdvancedEventSelectors: selectors}); err != nil {
					t.Fatal(err)
				}
				if _, err := trail(account).StartLogging(t.Context(), &cloudtrail.StartLoggingInput{Name: aws.String("volume-audit")}); err != nil {
					t.Fatal(err)
				}
			}
			invoke := func(label string) {
				t.Helper()
				row, ok := rows[label]
				if !ok {
					t.Fatalf("missing native audit prerequisite %s", label)
				}
				ebsVolumeCallRows(t, v, &backends, row)
				if row.Operation == "ModifySnapshotAttribute" {
					v.clock.Advance(ebsdomain.SharingDelay)
				}
			}
			for _, label := range []string{"source-key", "owner-target-key", "disabled-target-key", "disable-target-key", "plain-source", "plain-source-put", "plain-source-complete", "plain-source-snapshot-state-1", "plain-share", "encrypted-source", "encrypted-source-put", "encrypted-source-complete", "encrypted-source-snapshot-state-0"} {
				invoke(label)
			}
			// Keep the resulting LookupEvents documents for an independent check
			// against configured, compressed CloudTrail delivery after reopen.
			wanted := map[string]map[string]any{}
			for _, label := range []string{"member-plain", "plain-custom-encrypted", "encrypted-inherited", "disabled-key", "plain-custom-encrypted-snapshot", "encrypted-inherited-snapshot", "encrypted-inherited-snapshot-before-source-delete-list-0", "encrypted-inherited-snapshot-before-source-delete-get-7"} {
				t.Run(label, func(t *testing.T) {
					row, ok := rows[label]
					if !ok {
						t.Fatalf("missing native audit call %s", label)
					}
					var expectedEC2 []map[string]any
					for _, item := range native.CloudTrail.Events {
						if item.Label == label && item.Event["eventSource"] == "ec2.amazonaws.com" {
							expectedEC2 = append(expectedEC2, ebsVolumeCloneDocument(t, item.Event))
						}
					}
					if row.Service == "ec2" && len(expectedEC2) == 0 {
						t.Fatalf("native audit evidence missing for %s", label)
					}
					// Botocore generated this token outside the captured public input.
					// Supplying it explicitly makes the native audit request comparable.
					if row.Operation == "CreateVolume" {
						var input map[string]any
						awsDecodeJSON(t, row.Input, &input)
						input["ClientToken"] = expectedEC2[0]["requestParameters"].(map[string]any)["clientToken"]
						row.Input, _ = json.Marshal(input)
					}
					observed := ebsVolumeCallRows(t, v, &backends, row)
					var paired []map[string]any
					kmsNames := map[string]int{}
					for _, event := range observed {
						call := event.APICallCompleted
						if call == nil || (call.EventSource != "ec2.amazonaws.com" && call.EventSource != "kms.amazonaws.com") {
							continue
						}
						actual := auditLookupRecord(t, trail(event.AccountID), event.RequestID, call.EventName)
						wanted[actual["eventID"].(string)] = actual
						if call.EventSource == "kms.amazonaws.com" {
							kmsNames[call.EventName]++
							ebsVolumeCompareKMSAudit(t, v, native, row, actual)
							continue
						}
						var expected map[string]any
						for _, candidate := range expectedEC2 {
							if v.bindings[candidate["recipientAccountId"].(string)] == event.AccountID {
								expected = candidate
								break
							}
						}
						if expected == nil {
							t.Fatalf("unexpected EC2 audit recipient %s for %s", event.AccountID, label)
						}
						ebsVolumeCompareEC2Audit(t, v, row, expected, actual)
						paired = append(paired, actual)
					}
					if len(paired) != len(expectedEC2) {
						t.Fatalf("%s: observed %d native EC2 recipients, want %d", label, len(paired), len(expectedEC2))
					}
					if label == "member-plain" {
						if len(paired) != 2 || paired[0]["sharedEventID"] == nil || paired[0]["sharedEventID"] != paired[1]["sharedEventID"] || paired[0]["eventID"] == paired[1]["eventID"] || paired[0]["requestID"] != paired[1]["requestID"] {
							t.Fatalf("shared CreateVolume lost paired audit identity: %#v", paired)
						}
					}
					if label == "plain-custom-encrypted" && !reflect.DeepEqual(kmsNames, map[string]int{"GenerateDataKeyWithoutPlaintext": 1, "CreateGrant": 1, "Decrypt": 1, "RetireGrant": 1}) {
						t.Fatalf("volume key lifecycle audit = %#v", kmsNames)
					}
					if label == "encrypted-inherited" && !reflect.DeepEqual(kmsNames, map[string]int{"ReEncrypt": 1}) {
						t.Fatalf("owned same-CMK volume unexpectedly regenerated a key: %#v", kmsNames)
					}
					if row.Operation == "CreateSnapshot" && len(kmsNames) != 0 {
						t.Fatalf("volume snapshot unexpectedly called KMS: %#v", kmsNames)
					}
					// Positive Decrypt evidence does not establish absence of
					// independent metadata authorization/audit operations.
					if row.Operation == "GetSnapshotBlock" && kmsNames["Decrypt"] != 1 {
						t.Fatalf("inherited-context block read audit = %#v", kmsNames)
					}
				})
			}
			v.clients = v.reopen()
			v.clock.Advance(6 * time.Minute)
			trailNativeDrain(t, cloud)
			found := map[string]bool{}
			for _, account := range []string{"111111111111", "222222222222"} {
				objects := trailNativeObjects(t, bucketClient(account), "volume-audit-"+account, "AWSLogs/")
				for _, actual := range trailNativeRecords(t, objects) {
					id, _ := actual["eventID"].(string)
					if expected := wanted[id]; expected != nil {
						if actual["recipientAccountId"] != account {
							t.Fatalf("cross-account trail leak: %#v", actual)
						}
						if !reflect.DeepEqual(expected, actual) {
							t.Fatalf("durable volume audit changed during delivery\nlookup %#v\nS3 %#v", expected, actual)
						}
						found[id] = true
					}
				}
			}
			for id, event := range wanted {
				if !found[id] {
					t.Fatalf("configured CloudTrail did not deliver %s event %s", event["eventName"], id)
				}
			}
		})
	}
}

func ebsVolumeCloneDocument(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var copied map[string]any
	awsDecodeJSON(t, encoded, &copied)
	return copied
}

func ebsVolumeCompareEC2Audit(t *testing.T, v *ebsVolumeReplay, row ebsNativeCall, expected, actual map[string]any) {
	t.Helper()
	for _, field := range []string{"eventName", "eventSource", "awsRegion", "eventType", "eventCategory", "readOnly", "managementEvent", "errorCode", "resources"} {
		ec2NetworkCompare(t, "volume-audit."+field, expected[field], actual[field], v.bindings)
	}
	request := expected["requestParameters"].(map[string]any)
	if zone, ok := request["zone"].(string); ok {
		request["zone"] = v.zones[v.zoneScope(row)][zone]
	}
	response := expected["responseElements"].(map[string]any)
	if zone, ok := response["zone"].(string); ok {
		response["zone"] = v.zones[v.zoneScope(row)][zone]
	}
	if zoneID, ok := response["availabilityZoneId"].(string); ok {
		response["availabilityZoneId"] = v.zones[v.zoneScope(row)][zoneID]
	}
	if nativeID, ok := response["volumeId"].(string); ok && row.Operation == "CreateVolume" {
		response["createTime"] = float64(v.volumes[nativeID].created.Truncate(time.Second).UnixMilli())
	}
	if nativeID, ok := response["snapshotId"].(string); ok && row.Operation == "CreateSnapshot" {
		response["startTime"] = float64(v.snapshots[nativeID].created.UnixMilli())
	}
	for _, field := range []string{"requestParameters", "responseElements"} {
		body, err := json.Marshal(expected[field])
		if err != nil {
			t.Fatal(err)
		}
		var normalized any
		awsDecodeJSON(t, ec2AuditReplace(t, body, v.bindings), &normalized)
		if !reflect.DeepEqual(normalized, actual[field]) {
			t.Fatalf("%s %s\nnative %#v\nlocal %#v", row.Label, field, normalized, actual[field])
		}
	}
	if identity, _ := expected["userIdentity"].(map[string]any); identity["type"] == "AWSAccount" {
		observed := actual["userIdentity"].(map[string]any)
		if observed["type"] != "AWSAccount" || observed["arn"] != nil || observed["accessKeyId"] != nil || observed["sessionContext"] != nil {
			t.Fatalf("shared volume owner saw caller credentials: %#v", observed)
		}
		if actual["requestParameters"].(map[string]any)["tagSpecificationSet"] != "HIDDEN_DUE_TO_SECURITY_REASONS" || actual["responseElements"].(map[string]any)["tagSet"] != "HIDDEN_DUE_TO_SECURITY_REASONS" {
			t.Fatalf("shared volume owner saw private tags: %#v", actual)
		}
	}
}

func ebsVolumeCompareKMSAudit(t *testing.T, v *ebsVolumeReplay, native ebsVolumeConformanceFixture, row ebsNativeCall, actual map[string]any) {
	t.Helper()
	name := actual["eventName"].(string)
	actualIdentity := actual["userIdentity"].(map[string]any)
	var expected map[string]any
	for _, item := range native.CloudTrail.Events {
		candidate := item.Event
		if candidate["eventSource"] != "kms.amazonaws.com" || candidate["eventName"] != name || candidate["errorCode"] != actual["errorCode"] {
			continue
		}
		identity := candidate["userIdentity"].(map[string]any)
		if identity["invokedBy"] != actualIdentity["invokedBy"] || (identity["type"] == "AWSService") != (actualIdentity["type"] == "AWSService") {
			continue
		}
		request := ebsVolumeCloneDocument(t, candidate)
		// AAD and ciphertext are opaque provider-specific cryptographic data.
		if params, ok := request["requestParameters"].(map[string]any); ok {
			delete(params, "sourceAAD")
			delete(params, "destinationAAD")
		}
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var normalized map[string]any
		awsDecodeJSON(t, ec2AuditReplace(t, body, v.bindings), &normalized)
		if name == "RetireGrant" {
			if !reflect.DeepEqual(normalized["responseElements"], actual["responseElements"]) || !reflect.DeepEqual(normalized["additionalEventData"], actual["additionalEventData"]) {
				continue
			}
		} else if !reflect.DeepEqual(normalized["requestParameters"], actual["requestParameters"]) {
			continue
		}
		expected = request
		break
	}
	if expected == nil {
		t.Fatalf("no native %s KMS audit matches %s: %#v", name, row.Label, actual)
	}
	for _, field := range []string{"eventName", "eventSource", "awsRegion", "eventType", "eventCategory", "readOnly", "managementEvent", "errorCode", "resources", "requestParameters", "responseElements", "userAgent"} {
		if name == "CreateGrant" && field == "responseElements" {
			nativeResponse := expected[field].(map[string]any)
			localResponse := actual[field].(map[string]any)
			v.bind(t, nativeResponse["grantId"].(string), localResponse["grantId"].(string))
		}
		ec2NetworkCompare(t, "volume-kms-audit."+field, expected[field], actual[field], v.bindings)
	}
	if name == "RetireGrant" {
		if actual["requestParameters"] != nil || actualIdentity["type"] != "AWSService" || actualIdentity["invokedBy"] != "AWS Internal" {
			t.Fatalf("grant retirement lost native privacy: %#v", actual)
		}
		ec2NetworkCompare(t, "volume-kms-retirement.additionalEventData", expected["additionalEventData"], actual["additionalEventData"], v.bindings)
	}
	encoded, _ := json.Marshal(actual)
	for _, secret := range []string{"grantToken", "ciphertextBlob", "plaintext", "CiphertextBlob", "Plaintext"} {
		if strings.Contains(string(encoded), `"`+secret+`"`) {
			t.Fatalf("KMS audit leaked cryptographic field %s", secret)
		}
	}
	if name == "Decrypt" && row.Operation == "GetSnapshotBlock" {
		request := actual["requestParameters"].(map[string]any)
		context := request["encryptionContext"].(map[string]any)
		if !strings.HasPrefix(context["aws:ebs:id"].(string), "vol-") || actualIdentity["invokedBy"] != "ebs.amazonaws.com" {
			t.Fatalf("volume-derived block read lost volume context: %#v", actual)
		}
	}
}
