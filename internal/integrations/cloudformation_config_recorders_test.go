package integrations

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	api "stackd/internal/awsapi/configservice"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	config "stackd/internal/services/configservice"
	"stackd/storage/sqlite"
	configsqlite "stackd/storage/sqlite/configservice"
)

func cfnConfigTestOwner(t *testing.T) (context.Context, config.Scope, config.Repository, StepFunctionsCommands) {
	t.Helper()
	scope := config.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: scope.AccountID})
	repo := config.NewMemoryRepository(nil)
	service := config.New(config.Config{Repository: repo})
	t.Cleanup(func() { _ = service.Close() })
	return ctx, scope, repo, NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"configservice": service})
}

func cfnConfigTestSeed(t *testing.T, ctx context.Context, repo config.Repository, fn func(config.Transaction) error) {
	t.Helper()
	if err := repo.Update(ctx, fn); err != nil {
		t.Fatal(err)
	}
}

func cfnConfigTestError(t *testing.T, err error, code string) {
	t.Helper()
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

func TestCloudFormationConfigChannelDeletePreservesForeignRecorder(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		name := "native"
		if foreign {
			name = "other-stack"
		}
		t.Run(name, func(t *testing.T) {
			ctx, scope, repo, commands := cfnConfigTestOwner(t)
			r := cloudformation.ResourceRequest{StackID: "stack", LogicalID: "Channel", Token: "channel-incarnation", PhysicalID: "delivery"}
			recorder := cloudformation.ResourceRequest{PhysicalID: "foreign", CloudControl: true}
			if foreign {
				recorder = cloudformation.ResourceRequest{StackID: "foreign-stack", LogicalID: "Recorder", Token: "recorder-incarnation", PhysicalID: "foreign"}
			}
			recorderARN := "arn:aws:config:us-east-1:111111111111:configuration-recorder/foreign/0123456789abcdef"
			channelARN := "arn:aws:config:us-east-1:111111111111:delivery-channel/delivery"
			start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			cfnConfigTestSeed(t, ctx, repo, func(tx config.Transaction) error {
				privateRecorder := config.CloudFormationOwnership{}
				if foreign {
					privateRecorder = config.CloudFormationOwnership{Owner: cfnMessagingOwner(recorder), Token: cfnMessagingHash(recorder.Token)}
				}
				if err := tx.PutRecorder(config.Recorder{CFNOwnership: privateRecorder, Scope: scope, Name: "foreign", ARN: recorderARN, RoleARN: "arn:aws:iam::111111111111:role/config", AllSupported: true, Recording: true, LastStart: start, LastStatusChange: start, LastStatus: "Success"}); err != nil {
					return err
				}
				if foreign {
					if err := tx.PutTags(scope, recorderARN, map[string]string{cfnMessagingOwnerTag: cfnMessagingOwner(recorder), cfnMessagingTokenTag: cfnMessagingHash(recorder.Token)}); err != nil {
						return err
					}
				}
				if err := tx.PutChannel(config.Channel{CFNOwnership: config.CloudFormationOwnership{Owner: cfnMessagingOwner(r), Token: cfnMessagingHash(r.Token)}, Scope: scope, Name: "delivery", Bucket: "real-bucket", Frequency: "TwentyFour_Hours"}); err != nil {
					return err
				}
				return tx.PutTags(scope, channelARN, map[string]string{cfnMessagingOwnerTag: cfnMessagingOwner(r), cfnMessagingTokenTag: cfnMessagingHash(r.Token)})
			})
			h := cfnConfigChannel{commands}
			cfnConfigTestError(t, h.Delete(ctx, r), "LastDeliveryChannelDeleteFailedException")
			// Check the real owner's observable execution status, not dispatched calls.
			status, err := cfnComputeCall[api.DescribeConfigurationRecorderStatusOutput](ctx, commands, "configservice", "DescribeConfigurationRecorderStatus", map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			if len(status.ConfigurationRecordersStatus) != 1 || status.ConfigurationRecordersStatus[0].Recording == nil || !bool(*status.ConfigurationRecordersStatus[0].Recording) || status.ConfigurationRecordersStatus[0].LastStopTime != nil {
				t.Fatalf("foreign recorder was stopped: %#v", status)
			}
			if _, err := h.Read(ctx, r); err != nil {
				t.Fatalf("rejected delete removed channel: %v", err)
			}
			denied := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::111111111111:user/restricted", PrincipalID: "AIDARESTRICTED"})
			if err := h.Delete(denied, r); err == nil {
				t.Fatal("channel deletion bypassed current IAM")
			}
			stale := r
			stale.Token = "different-incarnation"
			cfnConfigTestError(t, h.Delete(ctx, stale), "ResourceAlreadyExistsException")
			// Only the recorder's legitimate owner may stop it; after that channel
			// removal converges using native admission, including an idempotent retry.
			if err := (cfnConfigRecorder{commands}).Delete(ctx, recorder); err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(ctx, r); err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Read(ctx, r); !cfnSecurityMissing(err) {
				t.Fatalf("channel still present: %v", err)
			}
		})
	}
}

func TestCloudFormationConfigCreateReplayRetainsOnlyAdmittedIncarnation(t *testing.T) {
	ctx, scope, repo, commands := cfnConfigTestOwner(t)
	recorder := cloudformation.ResourceRequest{StackID: "stack", LogicalID: "Recorder", Token: "recorder-incarnation", Properties: cloudformation.Properties{"Name": "retained", "RoleARN": ""}}
	channel := cloudformation.ResourceRequest{StackID: "stack", LogicalID: "Channel", Token: "channel-incarnation", Properties: cloudformation.Properties{"Name": "delivery", "S3BucketName": ""}}
	recorderARN := "arn:aws:config:us-east-1:111111111111:configuration-recorder/retained/0123456789abcdef"
	cfnConfigTestSeed(t, ctx, repo, func(tx config.Transaction) error {
		if err := tx.PutRecorder(config.Recorder{CFNOwnership: config.CloudFormationOwnership{Owner: cfnMessagingOwner(recorder), Token: cfnMessagingHash(recorder.Token)}, Scope: scope, Name: "retained", ARN: recorderARN, RoleARN: "arn:aws:iam::111111111111:role/config", AllSupported: true}); err != nil {
			return err
		}
		if err := tx.PutTags(scope, recorderARN, map[string]string{cfnMessagingOwnerTag: cfnMessagingOwner(recorder), cfnMessagingTokenTag: cfnMessagingHash(recorder.Token)}); err != nil {
			return err
		}
		if err := tx.PutChannel(config.Channel{CFNOwnership: config.CloudFormationOwnership{Owner: cfnMessagingOwner(channel), Token: cfnMessagingHash(channel.Token)}, Scope: scope, Name: "delivery", Bucket: "real-bucket", Frequency: "TwentyFour_Hours"}); err != nil {
			return err
		}
		return tx.PutTags(scope, "arn:aws:config:us-east-1:111111111111:delivery-channel/delivery", map[string]string{cfnMessagingOwnerTag: cfnMessagingOwner(channel), cfnMessagingTokenTag: cfnMessagingHash(channel.Token)})
	})
	// The native Put rejects these replays before admission. Their authentic
	// persisted incarnation must still be returned for controller rollback.
	for _, tc := range []struct {
		name, id string
		h        cloudformation.ResourceHandler
		r        cloudformation.ResourceRequest
		code     string
	}{
		{"recorder", "retained", cfnConfigRecorder{commands}, recorder, "InvalidRoleException"},
		{"channel", "delivery", cfnConfigChannel{commands}, channel, "NoSuchBucketException"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.h.Create(ctx, tc.r)
			cfnConfigTestError(t, err, tc.code)
			if result.PhysicalID != tc.id {
				t.Fatalf("admitted incarnation lost: %#v", result)
			}
			foreign := tc.r
			foreign.Token = "other-incarnation"
			result, err = tc.h.Create(ctx, foreign)
			cfnConfigTestError(t, err, tc.code)
			if result.PhysicalID != "" {
				t.Fatalf("adopted foreign incarnation: %#v", result)
			}
			tc.r.PhysicalID = tc.id
			if err := tc.h.Delete(ctx, tc.r); err != nil {
				t.Fatal(err)
			}
			result, err = tc.h.Create(ctx, foreign)
			cfnConfigTestError(t, err, tc.code)
			if result.PhysicalID != "" {
				t.Fatalf("fabricated admission for absent resource: %#v", result)
			}
		})
	}
}

func TestConfigRecorderCreationSettingIsNotMutableStatusOrTags(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, started := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/started=%t", backend, started), func(t *testing.T) {
				ctx, scope, repo, _ := cfnConfigTestOwner(t)
				path := filepath.Join(t.TempDir(), "recorder.sqlite")
				var closeDatabase func()
				open := func() {
					db, err := sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					repo = configsqlite.New(db)
					closeDatabase = func() {
						if err := db.Close(); err != nil {
							t.Fatal(err)
						}
					}
				}
				if backend == "sqlite" {
					open()
					defer func() { closeDatabase() }()
				}
				request := cloudformation.ResourceRequest{StackID: "stack", LogicalID: "Recorder", Token: "created-recorder", PhysicalID: "retained"}
				recorderARN := "arn:aws:config:us-east-1:111111111111:configuration-recorder/retained/0123456789abcdef"
				cfnConfigTestSeed(t, ctx, repo, func(tx config.Transaction) error {
					return tx.PutRecorder(config.Recorder{
						Scope: scope, Name: request.PhysicalID, ARN: recorderARN, AllSupported: true, Recording: true,
						CFNOwnership:    config.CloudFormationOwnership{Owner: cfnMessagingOwner(request), Token: cfnMessagingHash(request.Token)},
						StartedOnCreate: started, StartedOnCreateKnown: true,
					})
				})
				service := config.New(config.Config{Repository: repo})
				defer func() { _ = service.Close() }()
				commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"configservice": service})
				// Public metadata deliberately contradicts the admitted setting.
				if err := cfnComputeRun(ctx, commands, "configservice", "TagResource", map[string]any{
					"ResourceArn": recorderARN, "Tags": []any{map[string]any{"Key": "stackd:cloudformation:config-start", "Value": fmt.Sprint(!started)}},
				}); err != nil {
					t.Fatal(err)
				}
				// The real native transition clears recording/pending start, not creation configuration.
				if err := cfnComputeRun(ctx, commands, "configservice", "StopConfigurationRecorder", map[string]any{"ConfigurationRecorderName": request.PhysicalID}); err != nil {
					t.Fatal(err)
				}
				_ = service.Close()
				if backend == "sqlite" {
					closeDatabase()
					open()
				}
				service = config.New(config.Config{Repository: repo})
				commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"configservice": service})
				handler := cfnConfigRecorder{commands}
				properties, err := handler.Read(ctx, request)
				if err != nil {
					t.Fatal(err)
				}
				if actual, present := properties["StartedOnCreate"]; !present || actual != started {
					t.Fatalf("mutable status/tag overwrote retained creation setting: %+v", properties)
				}
				foreign := request
				foreign.Token = "foreign-incarnation"
				if _, err := handler.Read(ctx, foreign); !cfnSecurityClaimMismatch(err) {
					t.Fatalf("foreign recorder metadata read: %v", err)
				}
				denied := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::111111111111:user/restricted", PrincipalID: "AIDARESTRICTED"})
				if _, err := handler.Read(denied, request); err == nil || cfnSecurityClaimMismatch(err) {
					t.Fatalf("creation metadata bypassed current IAM: %v", err)
				}
				// Legacy/ordinary native rows do not acquire a setting from public markers.
				cfnConfigTestSeed(t, ctx, repo, func(tx config.Transaction) error {
					if err := tx.DeleteRecorder(scope); err != nil {
						return err
					}
					return tx.PutRecorder(config.Recorder{Scope: scope, Name: request.PhysicalID, ARN: recorderARN, AllSupported: true})
				})
				request.CloudControl = true
				properties, err = handler.Read(ctx, request)
				if err != nil {
					t.Fatal(err)
				}
				if _, present := properties["StartedOnCreate"]; present {
					t.Fatalf("invented unobserved native creation setting: %+v", properties)
				}
			})
		}
	}
}
