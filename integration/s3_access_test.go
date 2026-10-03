package stackd_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"stackd"
	"stackd/clock"
)

func TestS3NativeAccessControls(t *testing.T) {
	for _, name := range []string{"public_access", "ownership", "ownership_authority", "local_acl_authority"} {
		t.Run(name, func(t *testing.T) { runS3NativeControlReplay(t, "s3/"+name+"_replay.json") })
	}
}

func TestS3ControlNativeReads(t *testing.T) {
	t.Run("sdk", func(t *testing.T) {
		runS3NativeControlReplay(t, "s3control/native_read_replay.json")
	})
	t.Run("raw", func(t *testing.T) {
		runS3NativeRawReplay(t, "s3control/native_raw_replay.json")
	})
	t.Run("audit", func(t *testing.T) {
		runS3NativeAuditReplay(t, "s3control/native_audit_replay.json")
	})
}

func TestS3ControlNativePolicyAdmission(t *testing.T) {
	runS3NativeControlReplay(t, "s3control/s3_policy_admission_replay.json")
}

func TestS3ControlAccessPoints(t *testing.T) {
	runS3NativeControlReplay(t, "s3control/access_point_control_replay.json")
}

func TestS3AccessPointAuthority(t *testing.T) {
	runS3NativeControlReplay(t, "s3control/access_point_authority_replay.json")
}

func TestS3AccessPointMultipart(t *testing.T) {
	runS3NativeControlReplay(t, "s3control/access_point_multipart_replay.json")
}

func TestS3AccessPointRegion(t *testing.T) {
	runS3NativeRawReplay(t, "s3control/access_point_region_replay.json")
}

func TestS3AccessPointAudit(t *testing.T) {
	runS3NativeAuditReplay(t, "s3control/access_point_audit_replay.json")
}

func TestS3ControlDocumentedAccountBlock(t *testing.T) {
	t.Run("controls", func(t *testing.T) {
		runS3NativeControlReplay(t, "s3control/account_block_replay.json")
	})
	t.Run("service", func(t *testing.T) {
		s3LoggingDelivery(t, "s3control/service_delivery_replay.json")
	})
}

func TestS3ControlDocumentedOrganizationBlock(t *testing.T) {
	runS3NativeControlReplay(t, "s3control/organization_block_replay.json")
}

func TestS3NativeRequestPayment(t *testing.T) {
	t.Run("controls", func(t *testing.T) {
		runS3NativeControlReplay(t, "s3/requester_control_replay.json")
	})
	for _, name := range []string{"admission", "management_raw", "data", "presigned"} {
		t.Run(name, func(t *testing.T) {
			runS3NativeRawReplay(t, "s3/requester_"+name+"_replay.json")
		})
	}
	t.Run("audit", func(t *testing.T) {
		runS3NativeAuditReplay(t, "s3/requester_audit_replay.json")
	})
}

func TestS3NativeLoggingControls(t *testing.T) {
	t.Run("controls", func(t *testing.T) {
		runS3NativeControlReplay(t, "s3/logging_control_replay.json")
	})
	t.Run("raw", func(t *testing.T) {
		runS3NativeRawReplay(t, "s3/logging_raw_replay.json")
	})
	t.Run("audit", func(t *testing.T) {
		runS3NativeAuditReplay(t, "s3/logging_audit_replay.json")
	})
}

func runS3NativeControlReplay(t *testing.T, path string) {
	t.Helper()
	var fixture struct {
		Payloads  map[string][]s3MultipartPayload
		Scenarios []struct {
			Name       string
			ManualTime bool
			Setup      []s3KMSCall
			Calls      []struct {
				s3MultipartCall
				Advance string
			}
		}
	}
	awsReadFixture(t, path, &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Scenarios {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				source := clock.NewManual(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source})
				replay := newS3KMSReplay(clients)
				for _, row := range scenario.Setup {
					if !t.Run(row.Label, func(t *testing.T) { replay.call(t, row) }) {
						return
					}
					if !scenario.ManualTime {
						advanceClock(t, source, time.Second)
					}
				}
				for _, row := range scenario.Calls {
					if row.Reopen {
						replay.clients = reopen()
					}
					if row.Advance != "" {
						duration, err := time.ParseDuration(row.Advance)
						if err != nil {
							t.Fatal(err)
						}
						advanceClock(t, source, duration)
						trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
					}
					if !t.Run(row.Label, func(t *testing.T) {
						if row.Service != "" && row.Service != "s3" {
							replay.call(t, row.s3KMSCall)
						} else {
							s3MultipartReplayCall(t, replay, fixture.Payloads, row.s3MultipartCall)
						}
					}) {
						return
					}
					if !scenario.ManualTime {
						advanceClock(t, source, time.Second)
					}
				}
			})
		}
	}
}

func TestS3NativeAccessRaw(t *testing.T) {
	runS3NativeRawReplay(t, "s3/access_raw_replay.json")
}

func runS3NativeRawReplay(t *testing.T, path string) {
	t.Helper()
	var fixture struct {
		Scenarios []struct {
			Name  string
			TLS   bool
			Setup []s3KMSCall
			Calls []struct {
				s3MultipartEventCall
				Source, Actor string
				After         []s3KMSCall
			}
		}
	}
	awsReadFixture(t, path, &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Scenarios {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				source := clock.NewManual(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
				clients, reopen := retainedS3ReplayCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, scenario.TLS)
				replay := newS3KMSReplay(clients)
				for _, row := range scenario.Setup {
					if !t.Run(row.Label, func(t *testing.T) { replay.call(t, row) }) {
						return
					}
					advanceClock(t, source, time.Second)
				}
				for _, row := range scenario.Calls {
					if row.Reopen {
						replay.clients = reopen()
					}
					if !t.Run(fmt.Sprintf("%d-%s", row.Sequence, row.Label), func(t *testing.T) {
						t.Logf("native source: %s:%d", row.Source, row.Sequence)
						actor := row.Actor
						if actor == "" {
							actor = "caller"
						}
						credentials, ok := replay.sessions[actor]
						if !ok {
							t.Fatalf("missing actor %q", actor)
						}
						s3MultipartEventRequest(t, replay, credentials, row.s3MultipartEventCall, source.Now())
						for _, after := range row.After {
							if after.Reopen {
								replay.clients = reopen()
							}
							replay.call(t, after)
							advanceClock(t, source, time.Second)
						}
					}) {
						return
					}
					advanceClock(t, source, time.Second)
				}
			})
		}
	}
}

func TestS3NativePublicPolicyClassification(t *testing.T) {
	var fixture struct {
		Source, Bucket string
		Cases          []struct {
			Name                                                         string
			Sequence, Status, StatusSequence, BlockSequence, BlockStatus int
			Policy                                                       json.RawMessage
			Code, BlockCode                                              string
			Public                                                       *bool
		}
	}
	awsReadFixture(t, "s3/public_policy_replay.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012"})
			replay := newS3KMSReplay(clients)
			client := replay.s3Client("caller")
			if _, err := client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &fixture.Bucket}); err != nil {
				t.Fatal(err)
			}
			if _, err := clients.iam("test", "test", "").CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("Delegated")}); err != nil {
				t.Fatal(err)
			}
			for _, row := range fixture.Cases {
				if !t.Run(row.Name, func(t *testing.T) {
					if _, err := client.PutPublicAccessBlock(t.Context(), &s3.PutPublicAccessBlockInput{Bucket: &fixture.Bucket, PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{BlockPublicPolicy: aws.Bool(false)}}); err != nil {
						t.Fatal(err)
					}
					input, err := json.Marshal(map[string]any{"Bucket": fixture.Bucket, "Policy": string(row.Policy)})
					if err != nil {
						t.Fatal(err)
					}
					replay.call(t, s3KMSCall{Label: row.Name, Source: fixture.Source, Sequence: row.Sequence, Service: "s3", Operation: "PutBucketPolicy", Actor: "caller", Input: input, Code: row.Code, Status: row.Status})
					if row.Public == nil {
						return
					}
					status, err := client.GetBucketPolicyStatus(t.Context(), &s3.GetBucketPolicyStatusInput{Bucket: &fixture.Bucket})
					if err != nil {
						t.Fatal(err)
					}
					if status.PolicyStatus == nil || status.PolicyStatus.IsPublic == nil || *status.PolicyStatus.IsPublic != *row.Public {
						t.Fatalf("native classification %t, got %+v", *row.Public, status.PolicyStatus)
					}
					if _, err := client.PutPublicAccessBlock(t.Context(), &s3.PutPublicAccessBlockInput{Bucket: &fixture.Bucket, PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{BlockPublicPolicy: aws.Bool(true)}}); err != nil {
						t.Fatal(err)
					}
					replay.call(t, s3KMSCall{Label: row.Name + "-blocked-admission", Source: fixture.Source, Sequence: row.BlockSequence, Service: "s3", Operation: "PutBucketPolicy", Actor: "caller", Input: input, Code: row.BlockCode, Status: row.BlockStatus})
					retained, err := client.GetBucketPolicyStatus(t.Context(), &s3.GetBucketPolicyStatusInput{Bucket: &fixture.Bucket})
					if err != nil {
						t.Fatal(err)
					}
					if retained.PolicyStatus == nil || retained.PolicyStatus.IsPublic == nil || *retained.PolicyStatus.IsPublic != *row.Public {
						t.Fatalf("public-block admission changed retained classification: %+v", retained.PolicyStatus)
					}
				}) {
					return
				}
			}
		})
	}
}
