package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"

	"stackd"
	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
)

func TestAccessKeyEventsSDKLifecycleAndRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.sqlite")
			backends := storage.NewMemory()
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC))
			start := func() (*stackd.Stack, cloudClients, func()) {
				closeDatabase := func() {}
				if backend == "sqlite" {
					backends, closeDatabase = openSQLiteBackends(t, path)
				}
				cloud, err := stackd.New(stackd.Config{Storage: backends, Clock: source})
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewServer(cloud)
				close := func() { server.Close(); _ = cloud.Close(); closeDatabase() }
				t.Cleanup(close)
				return cloud, cloudClients{server}, close
			}
			cloud, c, closeFirst := start()
			root := c.iam("test", "test", "")
			user, err := root.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("key-owner"), Path: aws.String("/original/")})
			if err != nil {
				t.Fatal(err)
			}
			created, err := root.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: user.User.UserName})
			if err != nil {
				t.Fatal(err)
			}
			key, secret := aws.ToString(created.AccessKey.AccessKeyId), aws.ToString(created.AccessKey.SecretAccessKey)
			var expected []journal.Event
			record := func(meta middleware.Metadata, accountID string, payload journal.AccessKeyChanged) {
				requestID, _ := awsmiddleware.GetRequestIDMetadata(meta)
				if requestID == "" {
					t.Fatal("missing SDK request ID")
				}
				expected = append(expected, journal.Event{Envelope: journal.Envelope{At: source.Now(), Partition: "aws", AccountID: accountID, Region: "us-east-1", RequestID: requestID, ActorARN: "arn:aws:iam::" + accountID + ":root"}, AccessKeyChanged: payload})
			}
			record(created.ResultMetadata, "000000000000", journal.AccessKeyChanged{Action: journal.AccessKeyCreated, AccessKeyID: key, PrincipalARN: aws.ToString(user.User.Arn), Status: "Active"})
			advanceClock(t, source, time.Minute)
			session, err := c.sts("test", "test", "").GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
			if err != nil {
				t.Fatal(err)
			}
			requestID, _ := awsmiddleware.GetRequestIDMetadata(session.ResultMetadata)
			expected = append(expected, journal.Event{Envelope: journal.Envelope{At: source.Now(), Partition: "aws", AccountID: "000000000000", Region: "us-east-1", RequestID: requestID, ActorARN: "arn:aws:iam::000000000000:root"}, SessionIssued: journal.SessionIssued{PrincipalARN: "arn:aws:iam::000000000000:root", SessionType: "GetSessionToken", Expiration: source.Now().Add(15 * time.Minute)}})
			for _, status := range []iamtypes.StatusType{iamtypes.StatusTypeInactive, iamtypes.StatusTypeInactive, iamtypes.StatusTypeActive} {
				advanceClock(t, source, time.Minute)
				updated, err := root.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{UserName: user.User.UserName, AccessKeyId: aws.String(key), Status: status})
				if err != nil {
					t.Fatal(err)
				}
				record(updated.ResultMetadata, "000000000000", journal.AccessKeyChanged{Action: journal.AccessKeyStatusUpdated, AccessKeyID: key, PrincipalARN: aws.ToString(user.User.Arn), Status: string(status)})
				identity, err := c.sts(key, secret, "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
				if status == iamtypes.StatusTypeInactive {
					assertAPIError(t, err, "InvalidClientTokenId")
				} else if err != nil || aws.ToString(identity.Arn) != aws.ToString(user.User.Arn) {
					t.Fatal("reactivated key did not authenticate its owner", err)
				}
			}
			_, err = c.iam(key, secret, "").CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{})
			assertAPIError(t, err, "AccessDenied")
			_, err = root.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{UserName: user.User.UserName, AccessKeyId: aws.String(key), Status: "invalid"})
			assertAPIError(t, err, "ValidationError")
			other := c.iam("222222222222", "test", "")
			otherUser, err := other.CreateUser(t.Context(), &iam.CreateUserInput{UserName: user.User.UserName})
			if err != nil {
				t.Fatal(err)
			}
			_, err = other.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{UserName: otherUser.User.UserName, AccessKeyId: aws.String(key)})
			assertAPIError(t, err, "NoSuchEntity")
			if _, err := root.UpdateUser(t.Context(), &iam.UpdateUserInput{UserName: user.User.UserName, NewUserName: aws.String("renamed"), NewPath: aws.String("/current/")}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, time.Minute)
			deleted, err := root.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{UserName: aws.String("renamed"), AccessKeyId: aws.String(key)})
			if err != nil {
				t.Fatal(err)
			}
			record(deleted.ResultMetadata, "000000000000", journal.AccessKeyChanged{Action: journal.AccessKeyDeleted, AccessKeyID: key, PrincipalARN: "arn:aws:iam::000000000000:user/current/renamed"})
			_, err = root.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{UserName: aws.String("renamed"), AccessKeyId: aws.String(key)})
			assertAPIError(t, err, "NoSuchEntity")
			otherKey, err := other.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: otherUser.User.UserName})
			if err != nil {
				t.Fatal(err)
			}
			record(otherKey.ResultMetadata, "222222222222", journal.AccessKeyChanged{Action: journal.AccessKeyCreated, AccessKeyID: aws.ToString(otherKey.AccessKey.AccessKeyId), PrincipalARN: aws.ToString(otherUser.User.Arn), Status: "Active"})
			rows, err := cloud.Events(t.Context(), 0, 100)
			credentials := credentialEvents(rows)
			if err != nil || len(credentials) != len(expected) {
				t.Fatalf("credential history = %+v, want %+v: %v", rows, expected, err)
			}
			var previous int64
			for _, row := range rows {
				if row.Sequence <= previous {
					t.Fatal("mixed journal is not in commit order", rows)
				}
				previous = row.Sequence
			}
			for i := range expected {
				expected[i].Sequence = credentials[i].Sequence
			}
			if !reflect.DeepEqual(credentials, expected) {
				t.Fatalf("credential history = %+v, want %+v", credentials, expected)
			}
			var collected []journal.Event
			var cursor int64
			for {
				response, err := c.server.Client().Get(fmt.Sprintf("%s/_stackd/events?after=%d&limit=2", c.server.URL, cursor))
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != 200 {
					t.Fatal("event page", response.Status, err)
				}
				var page struct {
					Events    []journal.Event `json:"events"`
					NextAfter int64           `json:"next_after"`
				}
				if err := json.Unmarshal(body, &page); err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{secret, aws.ToString(otherKey.AccessKey.SecretAccessKey), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken)} {
					if strings.Contains(string(body), secret) {
						t.Fatal("journal exposed a signing secret or session token")
					}
				}
				var wire struct {
					Events []map[string]json.RawMessage `json:"events"`
				}
				if err := json.Unmarshal(body, &wire); err != nil {
					t.Fatal(err)
				}
				for _, event := range wire.Events {
					payloads := 0
					for name := range event {
						if strings.HasSuffix(name, "_v1") {
							payloads++
						}
					}
					if payloads != 1 {
						t.Fatal("JSON event does not carry exactly one payload", event)
					}
				}
				if len(page.Events) == 0 {
					if page.NextAfter != cursor {
						t.Fatal("empty page changed the cursor")
					}
					break
				}
				if page.NextAfter <= cursor || page.NextAfter != page.Events[len(page.Events)-1].Sequence {
					t.Fatal("page did not advance to its last event", page)
				}
				collected = append(collected, page.Events...)
				cursor = page.NextAfter
			}
			if journalJSON(t, collected) != journalJSON(t, rows) {
				t.Fatal("mixed event pagination changed the history", collected)
			}
			snapshot := append([]journal.Event(nil), rows...)
			for i := range rows {
				if rows[i].AccessKeyChanged.Action != "" {
					rows[i].AccessKeyChanged.PrincipalARN = "changed"
					break
				}
			}
			closeFirst()
			cloud, c, _ = start()
			recovered, err := cloud.Events(t.Context(), 0, 100)
			if err != nil || !reflect.DeepEqual(recovered, snapshot) {
				t.Fatal("recovery or detached-read mutation changed the history", recovered, err)
			}
			_, err = c.sts(key, secret, "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
			assertAPIError(t, err, "InvalidClientTokenId")
			if _, err := c.sts(aws.ToString(otherKey.AccessKey.AccessKeyId), aws.ToString(otherKey.AccessKey.SecretAccessKey), "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{}); err != nil {
				t.Fatal("committed key did not recover with its event", err)
			}
			if _, err := c.iam("222222222222", "test", "").DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{UserName: otherUser.User.UserName, AccessKeyId: otherKey.AccessKey.AccessKeyId}); err != nil {
				t.Fatal(err)
			}
			rows, err = cloud.Events(t.Context(), cursor, 100)
			rows = credentialEvents(rows)
			if err != nil || len(rows) != 1 || rows[0].Sequence <= cursor || rows[0].AccessKeyChanged.Action != journal.AccessKeyDeleted {
				t.Fatal("recovered journal did not continue", rows, err)
			}
		})
	}
}

func (j *rejectingJournal) AppendAccessKeyChanged(ctx context.Context, e journal.Envelope, change journal.AccessKeyChanged) error {
	if err := j.Storage.AppendAccessKeyChanged(ctx, e, change); err != nil {
		return err
	}
	if j.fail.CompareAndSwap(true, false) {
		return errors.New("injected event append failure")
	}
	return nil
}

func TestAccessKeyEventsSDKRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, action := range []string{"CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey"} {
			for _, failure := range []string{"append", "commit", "cancellation"} {
				t.Run(backend+"/"+action+"/"+failure, func(t *testing.T) {
					backends := storage.NewMemory()
					if backend == "sqlite" {
						backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
					}
					events := &rejectingJournal{Storage: backends.Journal}
					backends.Journal = events
					repository := &signedAuthorityRepository{Repository: backends.IAM}
					backends.IAM = repository
					c := clockCloud(t, stackd.Config{Storage: backends})
					arn, key, secret := c.user(t, "test", "owner")
					root := c.iam("test", "test", "")
					putUserPolicy(t, root, "owner", allow(`"iam:*"`, arn))
					caller := c.iam(key, secret, "")
					mutate := func() error {
						switch action {
						case "CreateAccessKey":
							out, err := caller.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{})
							if err != nil && out != nil {
								t.Error("failed creation returned key material")
							}
							return err
						case "UpdateAccessKey":
							_, err := caller.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{AccessKeyId: aws.String(key), Status: iamtypes.StatusTypeInactive})
							return err
						default:
							_, err := caller.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{AccessKeyId: aws.String(key)})
							return err
						}
					}
					baseline, err := events.Read(t.Context(), 0, 100)
					if err != nil || len(credentialEvents(baseline)) != 1 {
						t.Fatal("fixture history", baseline, err)
					}
					plan := &signedAuthorityPlan{key: key, failCommit: failure == "commit", cancelCommit: failure == "cancellation"}
					if failure == "append" {
						events.fail.Store(true)
					} else {
						repository.arm(plan)
					}
					assertAPIError(t, mutate(), "ServiceFailure")
					if failure != "append" {
						ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
						defer cancel()
						plan.wait(t, ctx)
					}
					rows, err := events.Read(t.Context(), 0, 100)
					if err != nil || len(rows) < len(baseline) || !reflect.DeepEqual(rows[:len(baseline)], baseline) || !reflect.DeepEqual(credentialEvents(rows), credentialEvents(baseline)) {
						t.Fatal("failed mutation persisted an event", rows, err)
					}
					keys, err := root.ListAccessKeys(t.Context(), &iam.ListAccessKeysInput{UserName: aws.String("owner")})
					if err != nil || len(keys.AccessKeyMetadata) != 1 || aws.ToString(keys.AccessKeyMetadata[0].AccessKeyId) != key || keys.AccessKeyMetadata[0].Status != iamtypes.StatusTypeActive {
						t.Fatal("failed mutation changed the owner's keys", keys, err)
					}
					if _, err := c.sts(key, secret, "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{}); err != nil {
						t.Fatal("rolled-back key mutation changed signed authentication", err)
					}
					if err := mutate(); err != nil {
						t.Fatal("mutation could not be retried", err)
					}
					rows, err = events.Read(t.Context(), baseline[len(baseline)-1].Sequence, 100)
					rows = credentialEvents(rows)
					if err != nil || len(rows) != 1 || rows[0].ActorARN != arn || rows[0].AccessKeyChanged.PrincipalARN != arn {
						t.Fatal("successful retry did not record the caller and owner", rows, err)
					}
				})
			}
		}
	}
}
