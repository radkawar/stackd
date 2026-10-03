package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
	accountstore "stackd/storage/account"
	iamstore "stackd/storage/iam"
	orgstore "stackd/storage/organizations"
)

func creationEventCloud(t *testing.T, backends *storage.Backends, source *clock.Manual) (*stackd.Stack, cloudClients, func()) {
	t.Helper()
	cloud, err := stackd.New(stackd.Config{Storage: backends, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(cloud)
	close := func() { server.Close(); _ = cloud.Close() }
	t.Cleanup(close)
	return cloud, cloudClients{server}, close
}

func TestOrganizationCreationEventsRecoverySDK(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.sqlite")
			backends := storage.NewMemory()
			closeDB := func() {}
			open := func() {
				if backend == "sqlite" {
					backends, closeDB = openSQLiteBackends(t, path)
				}
			}
			open()
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC))
			_, c, close := creationEventCloud(t, backends, source)
			f := organizationFixture(t, c, source)
			org, err := f.org.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
			if err != nil {
				t.Fatal(err)
			}
			input := &organizations.CreateAccountInput{AccountName: aws.String("private-member-name"), Email: aws.String("private-member@example.test")}
			accepted, err := f.org.CreateAccount(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			requestID, _ := awsmiddleware.GetRequestIDMetadata(accepted.ResultMetadata)
			if requestID == "" {
				t.Fatal("missing SDK request ID")
			}
			rows := lifecycleEvents(t, backends.Journal)
			if len(rows) != 1 || rows[0].Sequence <= 0 {
				t.Fatal("accepted intent was not recorded exactly once", rows)
			}
			want := journal.Event{Envelope: journal.Envelope{Sequence: rows[0].Sequence, At: source.Now(), Partition: "aws", AccountID: "000000000000", Region: "us-east-1", RequestID: requestID, ActorARN: "arn:aws:iam::000000000000:root"}, AccountCreationChanged: journal.AccountCreationChanged{OrganizationID: aws.ToString(org.Organization.Id), CreationRequestID: aws.ToString(accepted.CreateAccountStatus.Id), State: "IN_PROGRESS"}}
			if !reflect.DeepEqual(rows, []journal.Event{want}) {
				t.Fatal("accepted intent and event disagree", rows, want)
			}
			close()
			closeDB()
			advanceClock(t, source, time.Second)
			open()
			cloud, c, close := creationEventCloud(t, backends, source)
			if _, err := cloud.RunDueJobs(t.Context(), 10); err != nil {
				t.Fatal(err)
			}
			client := c.organizations("test", "test")
			status, err := client.DescribeCreateAccountStatus(t.Context(), &organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: accepted.CreateAccountStatus.Id})
			if err != nil || status.CreateAccountStatus.State != orgtypes.CreateAccountStateSucceeded {
				t.Fatal("recovered intent did not finish", status, err)
			}
			rows = lifecycleEvents(t, backends.Journal)
			if len(rows) != 2 || rows[1].Sequence <= want.Sequence {
				t.Fatal("recovery did not commit exactly one later completion", rows)
			}
			completed := want
			completed.Sequence, completed.At = rows[1].Sequence, source.Now()
			completed.AccountCreationChanged.State, completed.AccountCreationChanged.AccountID = "SUCCEEDED", aws.ToString(status.CreateAccountStatus.AccountId)
			expected := []journal.Event{want, completed}
			if !reflect.DeepEqual(rows, expected) {
				t.Fatal("recovered completion lost its origin or time", rows, expected)
			}
			// The published member has a real access role usable by the origin account.
			role, err := c.iam(completed.AccountCreationChanged.AccountID, "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("OrganizationAccountAccessRole")})
			if err != nil || !role.Role.CreateDate.Equal(completed.At) {
				t.Fatal("event was published without its access role", role, err)
			}
			session, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("created-member")})
			if err != nil {
				t.Fatal(err)
			}
			identity, err := c.sessionSTS(session.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
			if err != nil || aws.ToString(identity.Account) != completed.AccountCreationChanged.AccountID {
				t.Fatal("published account access did not authenticate", identity, err)
			}
			// An existing email is an accepted intent followed by a failed result.
			failed, err := client.CreateAccount(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, time.Second)
			if _, err := cloud.RunDueJobs(t.Context(), 10); err != nil {
				t.Fatal(err)
			}
			failure, err := client.DescribeCreateAccountStatus(t.Context(), &organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: failed.CreateAccountStatus.Id})
			if err != nil || failure.CreateAccountStatus.FailureReason != orgtypes.CreateAccountFailureReasonEmailAlreadyExists {
				t.Fatal("expected terminal duplicate-email failure", failure, err)
			}
			rows = lifecycleEvents(t, backends.Journal)
			failedRequestID, _ := awsmiddleware.GetRequestIDMetadata(failed.ResultMetadata)
			if len(rows) != 5 || !reflect.DeepEqual(rows[:2], expected) || rows[2].SessionIssued.PrincipalARN != aws.ToString(session.AssumedRoleUser.Arn) || rows[2].SessionIssued.IssuerARN != aws.ToString(role.Role.Arn) || rows[3].AccountCreationChanged.State != "IN_PROGRESS" || rows[3].AccountCreationChanged.CreationRequestID != aws.ToString(failed.CreateAccountStatus.Id) || rows[4].AccountCreationChanged.CreationRequestID != rows[3].AccountCreationChanged.CreationRequestID || rows[4].AccountCreationChanged.State != "FAILED" || rows[4].AccountCreationChanged.FailureReason != "EMAIL_ALREADY_EXISTS" || rows[4].AccountCreationChanged.AccountID != "" || failedRequestID == "" || rows[3].RequestID != failedRequestID || rows[4].RequestID != failedRequestID {
				t.Fatal("mixed success/failure history", rows)
			}
			for i := 1; i < len(rows); i++ {
				if rows[i].Sequence <= rows[i-1].Sequence {
					t.Fatal("mixed lifecycle history lost commit order", rows)
				}
			}
			_, err = client.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("bad"), Email: aws.String("invalid")})
			assertAPIError(t, err, "InvalidInputException")
			_, err = c.organizations("333333333333", "test").CreateAccount(t.Context(), input)
			assertAPIError(t, err, "AWSOrganizationsNotInUseException")
			pageRows, err := backends.Journal.Read(t.Context(), completed.Sequence, 3)
			if err != nil || len(pageRows) != 3 {
				t.Fatal("reading operator history page", pageRows, err)
			}
			response, err := c.server.Client().Get(c.server.URL + "/_stackd/events?limit=3&after=" + strconv.FormatInt(completed.Sequence, 10))
			if err != nil {
				t.Fatal(err)
			}
			var page struct {
				Events    []journal.Event
				NextAfter int64 `json:"next_after"`
			}
			err = json.NewDecoder(response.Body).Decode(&page)
			response.Body.Close()
			if err != nil || page.NextAfter != pageRows[len(pageRows)-1].Sequence || journalJSON(t, page.Events) != journalJSON(t, pageRows) {
				t.Fatal("operator history pagination", page, pageRows, err)
			}
			raw, err := json.Marshal(rows)
			if err != nil || strings.Contains(string(raw), *input.Email) || strings.Contains(string(raw), *input.AccountName) || strings.Contains(string(raw), *session.Credentials.SecretAccessKey) {
				t.Fatal("event payload leaked resource data", err)
			}
			close()
			closeDB()
			open()
			cloud, _, _ = creationEventCloud(t, backends, source)
			if _, err := cloud.RunDueJobs(t.Context(), 10); err != nil {
				t.Fatal(err)
			}
			if recovered := lifecycleEvents(t, backends.Journal); !reflect.DeepEqual(recovered, rows) {
				t.Fatal("completed jobs emitted again or rejected requests emitted", recovered)
			}
		})
	}
}

type creationCommitFailure struct {
	orgstore.Storage
	mode atomic.Int32
}

func (s *creationCommitFailure) CompareAndSwap(ctx context.Context, partition string, revision uint64, record orgstore.PartitionRecord, commit func(context.Context) error) (bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	return s.Storage.CompareAndSwap(ctx, partition, revision, record, func(ctx context.Context) error {
		if commit != nil {
			if err := commit(ctx); err != nil {
				return err
			}
		}
		switch s.mode.Load() {
		case 1:
			return errors.New("injected failure after staged Organizations state and event")
		case 2:
			cancel()
		}
		return nil
	})
}

type creationAppendFailure struct {
	journal.Storage
	fail atomic.Bool
}

func (s *creationAppendFailure) AppendAccountCreationChanged(ctx context.Context, envelope journal.Envelope, change journal.AccountCreationChanged) error {
	if err := s.Storage.AppendAccountCreationChanged(ctx, envelope, change); err != nil {
		return err
	}
	if s.fail.Load() {
		return errors.New("injected account event append failure")
	}
	return nil
}

func TestOrganizationCreationEventsRollbackSDK(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, phase := range []string{"accepted", "succeeded", "failed"} {
			for _, mode := range []string{"append", "commit", "cancel", "iam commit", "iam cancel"} {
				if strings.HasPrefix(mode, "iam") && phase != "succeeded" {
					continue
				}
				t.Run(backend+"/"+phase+"/"+mode, func(t *testing.T) {
					backends := storage.NewMemory()
					if backend == "sqlite" {
						backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
					}
					roles := &accountRoleRepository{Repository: backends.IAM}
					backends.IAM = roles
					state := &creationCommitFailure{Storage: backends.Organizations}
					history := &creationAppendFailure{Storage: backends.Journal}
					backends.Organizations, backends.Journal = state, history
					source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
					cloud, c, _ := creationEventCloud(t, backends, source)
					f := organizationFixture(t, c, source)
					if err := backends.Account.Update(t.Context(), func(tx accountstore.Writer) error {
						return tx.PutContact(accountstore.Scope{Partition: "aws", AccountID: "000000000000"}, accountstore.ContactInformation{FullName: "Owner", AddressLine1: "1 Test Street"})
					}); err != nil {
						t.Fatal(err)
					}
					email := "rollback@example.test"
					if phase == "failed" {
						email = "000000000000@localhost.local"
					}
					input := &organizations.CreateAccountInput{AccountName: aws.String("rollback"), Email: &email}
					var accepted *organizations.CreateAccountOutput
					var err error
					if phase != "accepted" {
						accepted, err = f.org.CreateAccount(t.Context(), input)
						if err != nil {
							t.Fatal(err)
						}
					}
					before, revision, err := backends.Organizations.Load(t.Context(), "aws")
					if err != nil {
						t.Fatal(err)
					}
					baseline := lifecycleEvents(t, history)
					switch mode {
					case "append":
						history.fail.Store(true)
					case "commit":
						state.mode.Store(1)
					case "cancel":
						state.mode.Store(2)
					case "iam commit":
						roles.mode.Store(1)
					case "iam cancel":
						roles.mode.Store(2)
					}
					if phase == "accepted" {
						_, err := f.org.CreateAccount(t.Context(), input)
						assertAPIError(t, err, "ServiceException")
					} else {
						advanceClock(t, source, time.Second)
						if _, err := cloud.RunDueJobs(t.Context(), 10); err == nil {
							t.Fatal("failed job drain succeeded")
						}
					}
					after, nextRevision, err := backends.Organizations.Load(t.Context(), "aws")
					if err != nil || nextRevision != revision || !reflect.DeepEqual(after, before) {
						t.Fatal("failed publication changed Organizations", err)
					}
					if rows := lifecycleEvents(t, history); !reflect.DeepEqual(rows, baseline) {
						t.Fatal("failed publication retained an event", rows)
					}
					if err := backends.IAM.View(t.Context(), func(tx iamstore.ReadTx) error {
						roles, err := tx.Roles(iamstore.Scope{Partition: "aws", AccountID: "100000000001"})
						if len(roles) != 0 {
							t.Error("failed publication retained account roles", roles)
						}
						return err
					}); err != nil {
						t.Fatal(err)
					}
					if err := backends.Account.View(t.Context(), func(tx accountstore.Reader) error {
						_, found, err := tx.Contact(accountstore.Scope{Partition: "aws", AccountID: "100000000001"})
						if found {
							t.Error("failed publication retained copied contact")
						}
						return err
					}); err != nil {
						t.Fatal(err)
					}
					state.mode.Store(0)
					roles.mode.Store(0)
					history.fail.Store(false)
					if phase == "accepted" {
						accepted, err = f.org.CreateAccount(t.Context(), input)
						if err != nil {
							t.Fatal(err)
						}
						advanceClock(t, source, time.Second)
					}
					if _, err := cloud.RunDueJobs(t.Context(), 10); err != nil {
						t.Fatal(err)
					}
					status, err := f.org.DescribeCreateAccountStatus(t.Context(), &organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: accepted.CreateAccountStatus.Id})
					if err != nil || status.CreateAccountStatus.State == orgtypes.CreateAccountStateInProgress {
						t.Fatal("retry did not complete", status, err)
					}
					rows := lifecycleEvents(t, history)
					if len(rows) != 2 || rows[0].AccountCreationChanged.State != "IN_PROGRESS" || rows[1].AccountCreationChanged.State != string(status.CreateAccountStatus.State) {
						t.Fatal("retry did not record exactly one terminal result", rows)
					}
				})
			}
		}
	}
}

func TestOrganizationCreationEventRevisionConflictSDK(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
			}
			state := &delegationCommitStorage{Storage: backends.Organizations, identities: backends.IAM, entered: make(chan struct{}), resume: make(chan struct{})}
			backends.Organizations = state
			f := newOrganizationReportFixture(t, backends)
			actor, key, secret := f.cloud.user(t, "test", "creator")
			putUserPolicy(t, f.iam, "creator", allow(`"organizations:CreateAccount"`, "*"))
			baseline := lifecycleEvents(t, backends.Journal)
			credentials := credentialEvents(baseline)
			if len(credentials) != 1 || credentials[0].AccessKeyChanged.Action != journal.AccessKeyCreated || credentials[0].AccessKeyChanged.AccessKeyID != key || credentials[0].AccessKeyChanged.PrincipalARN != actor {
				t.Fatal("creator credential publication is missing", credentials)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			state.pauseNext.Store(true)
			type result struct {
				output *organizations.CreateAccountOutput
				err    error
			}
			done := make(chan result, 1)
			go func() {
				out, err := f.cloud.organizations(key, secret).CreateAccount(ctx, &organizations.CreateAccountInput{AccountName: aws.String("conflict"), Email: aws.String("conflict@example.test")})
				done <- result{out, err}
			}()
			select {
			case <-state.entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			func() {
				defer close(state.resume)
				if _, err := f.org.CreateOrganizationalUnit(ctx, &organizations.CreateOrganizationalUnitInput{ParentId: &f.rootID, Name: aws.String("concurrent")}); err != nil {
					t.Fatal(err)
				}
			}()
			select {
			case result := <-done:
				if result.err != nil {
					t.Fatal(result.err)
				}
				requestID, _ := awsmiddleware.GetRequestIDMetadata(result.output.ResultMetadata)
				rows := lifecycleEvents(t, backends.Journal)
				if len(rows) < len(baseline) || !reflect.DeepEqual(rows[:len(baseline)], baseline) {
					t.Fatal("revision retry changed previously committed journal entries", rows)
				}
				var accepted []journal.Event
				for _, row := range rows {
					if row.AccountCreationChanged.CreationRequestID != "" {
						accepted = append(accepted, row)
					}
				}
				if len(accepted) != 1 || accepted[0].AccountCreationChanged.CreationRequestID != aws.ToString(result.output.CreateAccountStatus.Id) || accepted[0].AccountCreationChanged.State != "IN_PROGRESS" || requestID == "" || accepted[0].RequestID != requestID || accepted[0].ActorARN != actor || accepted[0].Sequence <= baseline[len(baseline)-1].Sequence {
					t.Fatal("rejected revision emitted an event or lost its caller", accepted)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
