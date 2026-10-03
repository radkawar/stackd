package stackd_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	ebstypes "github.com/aws/aws-sdk-go-v2/service/ebs/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	ebsapi "stackd/internal/awsapi/ebs"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/integrations"
	ebsservice "stackd/internal/services/ebs"
	iamservice "stackd/internal/services/iam"
	kmsservice "stackd/internal/services/kms"
	"stackd/storage"
)

func TestEBSDependencyAuditSurvivesCommandRollback(t *testing.T) {
	var native struct {
		CloudTrail struct {
			Events []struct {
				Label string `json:"call_label"`
				Event map[string]any
			}
		}
	}
	awsReadFixture(t, "ebs/encryption_authorization.json", &native)
	var deniedNative map[string]any
	for _, row := range native.CloudTrail.Events {
		if row.Label == "start-denied-ebs-action" {
			deniedNative = row.Event
			break
		}
	}
	if deniedNative == nil {
		t.Fatal("missing native EBS management denial")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "ebs-audit.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC))
			_, clients, _ := startEventDeliveryCloud(t, backends, source)
			actor, access, secret := clients.user(t, eventDeliveryAccount, "snapshot-audit")
			client := ebs.New(ebs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), HTTPClient: clients.server.Client(), Credentials: credentials.NewStaticCredentialsProvider(access, secret, ""), RetryMaxAttempts: 1})
			root := ebs.New(ebs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), HTTPClient: clients.server.Client(), Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", ""), RetryMaxAttempts: 1})
			key, err := clients.kms(eventDeliveryAccount, "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			parent, err := root.StartSnapshot(t.Context(), &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1), Encrypted: aws.Bool(true), KmsKeyArn: key.KeyMetadata.Arn})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := root.CompleteSnapshot(t.Context(), &ebs.CompleteSnapshotInput{SnapshotId: parent.SnapshotId, ChangedBlocksCount: aws.Int32(0)}); err != nil {
				t.Fatal(err)
			}
			source.Advance(ebsservice.CompletionDelay + ebsservice.ReadinessDelay)
			for _, tc := range []struct {
				name, deny, failure                string
				parent, complete, invalid, managed bool
				outcomes                           map[string]string
			}{
				{name: "denied-generate", deny: "kms:GenerateDataKey", failure: "ValidationException", outcomes: map[string]string{"GenerateDataKey": "AccessDeniedException", "StartSnapshot": "ValidationException"}},
				{name: "managed-key-rollback", deny: "kms:GenerateDataKey", managed: true, failure: "ValidationException", outcomes: map[string]string{"CreateKey": "", "CreateAlias": "", "GenerateDataKey": "AccessDeniedException", "StartSnapshot": "ValidationException"}},
				{name: "reencrypt-then-denied-decrypt", deny: "kms:Decrypt", parent: true, failure: "ResourceNotFoundException", outcomes: map[string]string{"ReEncrypt": "", "Decrypt": "AccessDeniedException", "StartSnapshot": "ResourceNotFoundException"}},
				{name: "denied-start", deny: "ebs:StartSnapshot", failure: "AccessDeniedException", outcomes: map[string]string{"StartSnapshot": "AccessDenied"}},
				{name: "denied-tags", deny: "ec2:CreateTags", failure: "AccessDeniedException", outcomes: map[string]string{"StartSnapshot": "AccessDenied"}},
				{name: "denied-complete", deny: "ebs:CompleteSnapshot", complete: true, failure: "AccessDeniedException", outcomes: map[string]string{"CompleteSnapshot": "AccessDenied"}},
				{name: "validation", invalid: true, failure: "ValidationException", outcomes: map[string]string{"StartSnapshot": "ValidationException"}},
				{name: "success", outcomes: map[string]string{"GenerateDataKey": "", "StartSnapshot": ""}},
				{name: "child-success", parent: true, outcomes: map[string]string{"ReEncrypt": "", "Decrypt": "", "StartSnapshot": ""}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}`
					if tc.deny != "" {
						policy += fmt.Sprintf(`,{"Effect":"Deny","Action":%q,"Resource":"*"}`, tc.deny)
					}
					putUserPolicy(t, clients.iam(eventDeliveryAccount, "test", ""), "snapshot-audit", policy+`]}`)
					before, err := backends.Journal.Read(t.Context(), 0, 1000)
					if err != nil {
						t.Fatal(err)
					}
					sequence := before[len(before)-1].Sequence
					input := &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1), Description: aws.String("private-denied-description"), ClientToken: aws.String(tc.name), Tags: []ebstypes.Tag{{Key: aws.String("audit"), Value: aws.String("private-denied-tag")}}}
					if tc.parent {
						input.ParentSnapshotId = parent.SnapshotId
					} else {
						input.Encrypted, input.KmsKeyArn = aws.Bool(true), key.KeyMetadata.Arn
					}
					if tc.managed {
						input.KmsKeyArn = nil
					}
					if tc.invalid {
						// Native encrypted-parent-true-key preserves this invalid
						// combination's typed request document.
						input.ParentSnapshotId = parent.SnapshotId
					}
					if tc.complete {
						_, err = client.CompleteSnapshot(t.Context(), &ebs.CompleteSnapshotInput{SnapshotId: parent.SnapshotId, ChangedBlocksCount: aws.Int32(0)})
					} else {
						_, err = client.StartSnapshot(t.Context(), input)
					}
					if tc.failure != "" {
						assertAPIError(t, err, tc.failure)
					} else if err != nil {
						t.Fatal(err)
					}
					rows, err := backends.Journal.Read(t.Context(), sequence, 1000)
					if err != nil {
						t.Fatal(err)
					}
					got := map[string]string{}
					for _, row := range rows {
						call := row.APICallCompleted
						if call == nil || call.EventSource != "ebs.amazonaws.com" && call.EventSource != "kms.amazonaws.com" {
							continue
						}
						if _, duplicate := got[call.EventName]; duplicate {
							t.Fatalf("duplicate child outcome: %s", call.EventName)
						}
						got[call.EventName] = call.ErrorCode
						if row.ActorARN != actor || call.Identity.AccessKeyID != access {
							t.Fatalf("lost original caller: %+v", row)
						}
						trail := auditLookupRecord(t, trailNativeClient(clients), row.RequestID, call.EventName)
						if trail["eventID"] != call.EventID {
							t.Fatal("journal and CloudTrail outcome identities differ")
						}
						if call.EventSource == "kms.amazonaws.com" {
							identity := trail["userIdentity"].(map[string]any)
							if row.ActorService != "ebs.amazonaws.com" || identity["invokedBy"] != "ebs.amazonaws.com" || trail["userAgent"] != "ebs.amazonaws.com" {
								t.Fatalf("lost child service origin: %#v", trail)
							}
							request := trail["requestParameters"].(map[string]any)
							if request["plaintext"] != nil || request["ciphertextBlob"] != nil || call.ReadOnly && trail["responseElements"] != nil {
								t.Fatalf("retained cryptographic secret: %#v", trail)
							}
						} else if call.ErrorCode == "AccessDenied" {
							for _, field := range []string{"errorCode", "requestParameters", "responseElements"} {
								if !reflect.DeepEqual(trail[field], deniedNative[field]) {
									t.Fatalf("denied %s = %#v, native %#v", field, trail[field], deniedNative[field])
								}
							}
						} else {
							request, ok := trail["requestParameters"].(map[string]any)
							if !ok || request["description"] != "private-denied-description" {
								t.Fatalf("validation/dependency/success request document was suppressed: %#v", trail)
							}
						}
					}
					if !reflect.DeepEqual(got, tc.outcomes) {
						t.Fatalf("completed outcomes = %#v, want %#v", got, tc.outcomes)
					}
					if tc.failure != "" {
						err := backends.EBS.View(t.Context(), func(reader ebsservice.Reader) error {
							snapshots, err := reader.Snapshots(ebsservice.Scope{Partition: "aws", AccountID: eventDeliveryAccount, Region: "us-east-1"})
							if err == nil && len(snapshots) != 1 {
								t.Errorf("failed snapshot creation retained state: %+v", snapshots)
							}
							return err
						})
						if err != nil {
							t.Fatal(err)
						}
						keys, err := clients.kms(eventDeliveryAccount, "test", "").ListKeys(t.Context(), &kms.ListKeysInput{})
						if err != nil || len(keys.Keys) != 1 || aws.ToString(keys.Keys[0].KeyId) != aws.ToString(key.KeyMetadata.KeyId) {
							t.Fatalf("failed snapshot creation retained managed key state: %+v %v", keys, err)
						}
					}
				})
			}
		})
	}
}

func TestEBSExplicitOuterRollbackRemovesStateAndChildAudit(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "ebs-outer-rollback.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC))
			recorder := apievents.New(backends.Journal)
			identities := iamservice.NewWithConfig(iamservice.Config{Repository: backends.IAM, Clock: source})
			keys := kmsservice.NewWithConfig(kmsservice.Config{Storage: backends.KMS, APIEvents: recorder, Clock: source})
			snapshots := ebsservice.New(ebsservice.Config{Repository: backends.EBS, Recorder: recorder, Clock: source, Keys: integrations.EBSSnapshotKeys{KMS: keys, Activity: identities}})
			t.Cleanup(func() { _ = snapshots.Close(); _ = keys.Close(); _ = identities.Close() })
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: eventDeliveryAccount, Region: "us-east-1", AccessKeyID: eventDeliveryAccount, PrincipalARN: "arn:aws:iam::" + eventDeliveryAccount + ":root", PrincipalID: eventDeliveryAccount, RequestID: "outer-snapshot"})
			model, _ := awscatalog.LookupService("ebs")
			operation, _ := model.Operation("StartSnapshot")
			rollback := errors.New("explicit outer rollback")
			for _, missingKey := range []bool{false, true} {
				err := backends.EBS.Update(ctx, func(tx ebsservice.Transaction) error {
					input := &ebsapi.StartSnapshotRequest{VolumeSize: new(ebsapi.VolumeSize(1)), Encrypted: new(ebsapi.Boolean(true))}
					if missingKey {
						input.KmsKeyArn = new(ebsapi.KmsKeyArn("alias/missing"))
					}
					_, rejected := snapshots.ExecuteCommand(tx.Context(), awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
					if missingKey && (rejected == nil || rejected.Code != "ValidationException") || !missingKey && rejected != nil {
						t.Fatalf("unexpected command result: %v", rejected)
					}
					return rollback
				})
				if !errors.Is(err, rollback) {
					t.Fatal(err)
				}
				rows, err := backends.Journal.Read(t.Context(), 0, 100)
				if err != nil || len(rows) != 0 {
					t.Fatalf("explicit rollback retained child events: %+v %v", rows, err)
				}
				if err := backends.EBS.View(ctx, func(reader ebsservice.Reader) error {
					rows, err := reader.Snapshots(ebsservice.Scope{Partition: "aws", AccountID: eventDeliveryAccount, Region: "us-east-1"})
					if len(rows) != 0 {
						t.Fatal("explicit rollback retained snapshot state")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if err := backends.KMS.View(ctx, func(reader kmsservice.Reader) error {
					stored, err := reader.Scopes()
					if len(stored) != 0 {
						t.Fatal("explicit rollback retained managed key state")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
