package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
)

func credentialEvents(events []journal.Event) []journal.Event {
	var credentials []journal.Event
	for _, event := range events {
		if event.AccessKeyChanged.Action != "" || event.SessionIssued.SessionType != "" {
			credentials = append(credentials, event)
		}
	}
	return credentials
}

// lifecycleEvents selects typed domain facts from the shared journal. API
// outcomes have their own assertions; they do not change a lifecycle's contract.
func lifecycleEvents(t *testing.T, history journal.Storage) []journal.Event {
	t.Helper()
	var events []journal.Event
	var after int64
	for {
		rows, err := history.Read(t.Context(), after, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			return events
		}
		for _, row := range rows {
			if row.APICallCompleted == nil {
				events = append(events, row)
			}
		}
		after = rows[len(rows)-1].Sequence
	}
}

func journalJSON(t *testing.T, events []journal.Event) string {
	t.Helper()
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestSessionEventsSDKPaginationAndRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.sqlite")
			backends := storage.NewMemory()
			epoch := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
			source := clock.NewManual(epoch)
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
			root := c.sts("test", "test", "")
			session, err := root.GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
			if err != nil {
				t.Fatal(err)
			}
			requestID, _ := awsmiddleware.GetRequestIDMetadata(session.ResultMetadata)
			role, err := c.iam("222222222222", "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("event-target"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			assumed, err := root.AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("event-session"), DurationSeconds: aws.Int32(900)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: aws.String("arn:aws:iam::222222222222:role/missing"), RoleSessionName: aws.String("denied")})
			assertAPIError(t, err, "AccessDenied")
			_, err = c.sts(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken)).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
			if err != nil {
				t.Fatal(err)
			}
			history, err := cloud.Events(t.Context(), 0, 100)
			events := credentialEvents(history)
			if err != nil || len(events) != 2 {
				t.Fatal("issuance history", history, err)
			}
			if events[0].RequestID != requestID || requestID == "" || events[0].ActorARN != "arn:aws:iam::000000000000:root" || events[0].AccountID != "000000000000" || events[0].SessionIssued.SessionType != "GetSessionToken" {
				t.Fatal("incorrect source identity or request linkage", events[0])
			}
			if events[1].AccountID != "222222222222" || events[1].ActorARN != events[0].ActorARN || events[1].SessionIssued.PrincipalARN != aws.ToString(assumed.AssumedRoleUser.Arn) || events[1].SessionIssued.IssuerARN != aws.ToString(role.Role.Arn) {
				t.Fatal("cross-account event lost scope", events[1])
			}
			var previous int64
			for _, event := range history {
				if event.Sequence <= previous {
					t.Fatal("mixed journal is not in commit order", history)
				}
				previous = event.Sequence
			}
			for _, event := range events {
				if !event.At.Equal(epoch) || event.Partition != "aws" || event.Region != "us-east-1" || !event.SessionIssued.Expiration.Equal(epoch.Add(15*time.Minute)) {
					t.Fatal("event ordering or service time", event)
				}
			}
			response, err := c.server.Client().Get(c.server.URL + "/_stackd/events?limit=1")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK {
				t.Fatal("event endpoint", response.Status, err)
			}
			var page struct {
				Events    []journal.Event `json:"events"`
				NextAfter int64           `json:"next_after"`
			}
			if err := json.Unmarshal(body, &page); err != nil || len(page.Events) != 1 || page.NextAfter != page.Events[0].Sequence || journalJSON(t, page.Events) != journalJSON(t, history[:1]) {
				t.Fatal("event page", page, err)
			}
			for _, secret := range []*string{session.Credentials.SecretAccessKey, session.Credentials.SessionToken, assumed.Credentials.SecretAccessKey, assumed.Credentials.SessionToken} {
				encoded, _ := json.Marshal(history)
				if strings.Contains(string(encoded), aws.ToString(secret)) || strings.Contains(string(body), aws.ToString(secret)) {
					t.Fatal("event history contains credential material")
				}
			}
			// CloudTrail may retain a public caller key ID, but credential
			// publication payloads must continue to omit the issued keys.
			encoded, _ := json.Marshal(events)
			for _, key := range []*string{session.Credentials.AccessKeyId, assumed.Credentials.AccessKeyId} {
				if strings.Contains(string(encoded), aws.ToString(key)) {
					t.Fatal("session event contains an issued access-key ID")
				}
			}
			collected, cursor := page.Events, page.NextAfter
			for {
				tail, err := cloud.Events(t.Context(), cursor, 1)
				if err != nil {
					t.Fatal(err)
				}
				if len(tail) == 0 {
					break
				}
				if len(tail) != 1 || tail[0].Sequence <= cursor {
					t.Fatal("cursor skipped or repeated a journal entry", tail)
				}
				collected = append(collected, tail...)
				cursor = tail[0].Sequence
			}
			if journalJSON(t, collected) != journalJSON(t, history) {
				t.Fatal("mixed journal pagination changed the history", collected)
			}
			snapshot := append([]journal.Event(nil), history...)
			for i := range history {
				if history[i].SessionIssued.SessionType != "" {
					history[i].SessionIssued.PrincipalARN = "changed"
					break
				}
			}
			closeFirst()
			cloud, c, _ = start()
			recovered, err := cloud.Events(t.Context(), 0, 100)
			if err != nil || !reflect.DeepEqual(recovered, snapshot) {
				t.Fatal("event history changed across recovery", recovered, err)
			}
			if _, err := c.sts("test", "test", "").GetFederationToken(t.Context(), &sts.GetFederationTokenInput{Name: aws.String("after-recovery"), DurationSeconds: aws.Int32(900)}); err != nil {
				t.Fatal(err)
			}
			tail, err := cloud.Events(t.Context(), cursor, 100)
			tail = credentialEvents(tail)
			if err != nil || len(tail) != 1 || tail[0].Sequence <= cursor || tail[0].SessionIssued.SessionType != "GetFederationToken" {
				t.Fatal("restart did not continue the journal", tail, err)
			}
			for _, query := range []string{"after=-1", "limit=0", "limit=1001", "after=invalid"} {
				response, err := c.server.Client().Get(c.server.URL + "/_stackd/events?" + query)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusBadRequest {
					t.Fatal("invalid query accepted", query, response.Status)
				}
			}
		})
	}
}

type rejectingJournal struct {
	journal.Storage
	fail atomic.Bool
}

func (j *rejectingJournal) AppendSessionIssued(ctx context.Context, e journal.Envelope, session journal.SessionIssued) error {
	if err := j.Storage.AppendSessionIssued(ctx, e, session); err != nil {
		return err
	}
	if j.fail.CompareAndSwap(true, false) {
		return errors.New("injected event append failure")
	}
	return nil
}

func TestSessionEventFailureRollsBackCredentialSDK(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
			}
			events := &rejectingJournal{Storage: backends.Journal}
			backends.Journal = events
			f := newSignedAuthorityFixture(t, backends)
			baseline, err := events.Read(t.Context(), 0, 100)
			credentials := credentialEvents(baseline)
			if err != nil || len(credentials) != 1 || credentials[0].AccessKeyChanged.Action != journal.AccessKeyCreated {
				t.Fatal("fixture access key was not recorded", baseline, err)
			}
			cursor := baseline[len(baseline)-1].Sequence
			events.fail.Store(true)
			out, err := f.issue(t.Context(), "GetSessionToken")
			assertAPIError(t, err, "InternalFailure")
			if out != nil || f.sessionCount(t) != 0 {
				t.Fatal("failed event append published a credential")
			}
			rows, err := events.Read(t.Context(), cursor, 100)
			if err != nil || len(credentialEvents(rows)) != 0 {
				t.Fatal("failed append retained an event", rows, err)
			}
			if _, err := f.issue(t.Context(), "GetSessionToken"); err != nil {
				t.Fatal("retry failed", err)
			}
			rows, err = events.Read(t.Context(), cursor, 100)
			rows = credentialEvents(rows)
			if err != nil || len(rows) != 1 || rows[0].Sequence <= cursor || rows[0].SessionIssued.SessionType != "GetSessionToken" {
				t.Fatal("retry committed incorrect history", rows, err)
			}
		})
	}
}
