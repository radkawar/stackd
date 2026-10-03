package stackd_test

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd"
	"stackd/internal/awstest"
)

func TestECSNativeServiceRoleLifecycle(t *testing.T) {
	var workflows []struct {
		Capture, AuditCapture string
		Steps                 []struct {
			Call       int
			IAMEvent   int
			Reopen     bool
			WaitStatus iamtypes.DeletionTaskStatusType
		}
	}
	readJSON := func(t *testing.T, path string, value any) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, value); err != nil {
			t.Fatal(err)
		}
	}
	readJSON(t, "../testdata/ecs/service_roles.json", &workflows)
	for _, workflow := range workflows {
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(workflow.Capture+"/"+backend, func(t *testing.T) {
				var native struct {
					AccountID, Prefix string
					Calls             []struct {
						Label, Service, Operation, Region, Actor, Code string
						Input, Output                                  json.RawMessage
					}
				}
				readJSON(t, "../testdata/aws/ecs/"+workflow.Capture, &native)
				var audit struct{ Events []map[string]any }
				if workflow.AuditCapture != "" {
					readJSON(t, "../testdata/aws/ecs/"+workflow.AuditCapture, &audit)
				}
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: native.AccountID})
				// A different account's identically named role and live cluster must
				// neither satisfy provisioning nor block this account's deletion.
				foreign := ecs.New(ecs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("222222222222", "test", ""), RetryMaxAttempts: 1})
				if _, err := foreign.CreateCluster(t.Context(), &ecs.CreateClusterInput{ClusterName: aws.String("foreign-role-dependency")}); err != nil {
					t.Fatal(err)
				}
				var caller *ststypes.Credentials
				bindings := map[string]string{}
				for _, step := range workflow.Steps {
					if step.Reopen {
						clients = reopen()
						continue
					}
					row := native.Calls[step.Call-1]
					if !t.Run(row.Label, func(t *testing.T) {
						key, secret, token := "test", "test", ""
						if row.Actor == "probe-caller" {
							if caller == nil {
								session, err := clients.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: aws.String("arn:aws:iam::" + native.AccountID + ":role/" + native.Prefix), RoleSessionName: aws.String(native.Prefix)})
								if err != nil {
									t.Fatal(err)
								}
								caller = session.Credentials
							}
							key, secret, token = aws.ToString(caller.AccessKeyId), aws.ToString(caller.SecretAccessKey), aws.ToString(caller.SessionToken)
						}
						var client any
						switch row.Service {
						case "ecs":
							client = ecs.New(ecs.Options{Region: row.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), RetryMaxAttempts: 1})
						case "iam":
							client = clients.iam(key, secret, token)
						default:
							t.Fatalf("unsupported replay service %q", row.Service)
						}
						input := string(row.Input)
						for before, after := range bindings {
							input = strings.ReplaceAll(input, before, after)
						}
						out, err := awstest.CallSDK(t.Context(), client, row.Operation, json.RawMessage(input))
						if row.Code != "Success" {
							assertAPIError(t, err, row.Code)
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						if step.IAMEvent != 0 {
							assertECSLinkedRoleAudit(t, clients, audit.Events[step.IAMEvent-1], nativeAuditRequestID(t, out, nil))
						}
						var want struct {
							Role           struct{ Arn string }
							Cluster        struct{ ClusterArn, Status string }
							DeletionTaskId string
							Status         iamtypes.DeletionTaskStatusType
							Reason         *iamtypes.DeletionTaskFailureReasonType
						}
						if err := json.Unmarshal(row.Output, &want); err != nil {
							t.Fatal(err)
						}
						switch got := out.(type) {
						case *ecs.CreateClusterOutput:
							if got.Cluster == nil || aws.ToString(got.Cluster.ClusterArn) != want.Cluster.ClusterArn || aws.ToString(got.Cluster.Status) != want.Cluster.Status {
								t.Fatalf("cluster admission differs from native: %+v", got.Cluster)
							}
						case *iam.GetRoleOutput:
							if got.Role == nil || aws.ToString(got.Role.Arn) != want.Role.Arn {
								t.Fatalf("wrong retained role: %+v", got.Role)
							}
						case *iam.DeleteServiceLinkedRoleOutput:
							bindings[want.DeletionTaskId] = aws.ToString(got.DeletionTaskId)
							if step.WaitStatus != "" {
								terminal := waitOrganizationRoleDeletion(t, clients.iam("test", "test", ""), got.DeletionTaskId)
								if terminal.Status != step.WaitStatus {
									t.Fatalf("role deletion status=%s want %s: %+v", terminal.Status, step.WaitStatus, terminal.Reason)
								}
							}
						case *iam.GetServiceLinkedRoleDeletionStatusOutput:
							if got.Status != want.Status {
								t.Fatalf("role deletion status=%s want %s", got.Status, want.Status)
							}
							// Native usage checks may stop at the first populated region.
							// Require every captured blocker, without pinning report order.
							if want.Reason != nil {
								for _, dependency := range want.Reason.RoleUsageList {
									for _, arn := range dependency.Resources {
										if got.Reason == nil || !slices.ContainsFunc(got.Reason.RoleUsageList, func(usage iamtypes.RoleUsageType) bool {
											return aws.ToString(usage.Region) == aws.ToString(dependency.Region) && slices.Contains(usage.Resources, arn)
										}) {
											t.Fatalf("missing native role dependency %s in %s", arn, aws.ToString(dependency.Region))
										}
									}
								}
							}
						}
					}) {
						return
					}
				}
			})
		}
	}
}

func assertECSLinkedRoleAudit(t *testing.T, clients cloudClients, want map[string]any, parentRequest string) {
	t.Helper()
	trails := cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), RetryMaxAttempts: 1})
	got := auditLatestRecord(t, trails, "CreateServiceLinkedRole")
	if id, _ := got["requestID"].(string); id == "" || id == parentRequest {
		t.Fatalf("dependent IAM request has no distinct identity: %#v", got)
	}
	fields := func(actual, native map[string]any, names ...string) {
		t.Helper()
		for _, field := range names {
			value, present := actual[field]
			expected, nativePresent := native[field]
			if present != nativePresent || !reflect.DeepEqual(value, expected) {
				t.Fatalf("dependent IAM %s: got %#v (present %t), native %#v (present %t)", field, value, present, expected, nativePresent)
			}
		}
	}
	fields(got, want, "eventSource", "eventName", "awsRegion", "sourceIPAddress", "userAgent", "errorCode", "requestParameters", "readOnly", "eventCategory", "managementEvent", "eventType", "recipientAccountId")
	actor, nativeActor := got["userIdentity"].(map[string]any), want["userIdentity"].(map[string]any)
	fields(actor, nativeActor, "type", "arn", "accountId", "invokedBy")
	issuer := actor["sessionContext"].(map[string]any)["sessionIssuer"].(map[string]any)
	nativeIssuer := nativeActor["sessionContext"].(map[string]any)["sessionIssuer"].(map[string]any)
	fields(issuer, nativeIssuer, "type", "arn", "accountId", "userName")
}
