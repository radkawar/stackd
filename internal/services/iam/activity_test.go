package iam_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/clock"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/gateway"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

type activityFixture struct {
	repository iam.Repository
	clock      *clock.Manual
	store      *identity.Store
	service    *iam.Service
	server     *httptest.Server
	root       *sdkiam.Client
}

func newActivityFixture(t *testing.T, repository iam.Repository, start time.Time) *activityFixture {
	t.Helper()
	if repository == nil {
		repository = iam.NewMemoryRepository(nil)
	}
	f := &activityFixture{repository: repository, clock: clock.NewManual(start)}
	f.store = identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: iam.NewCredentialRepository(repository, nil), Clock: f.clock})
	f.service = iam.NewWithConfig(iam.Config{Credentials: f.store, Repository: repository, Clock: f.clock})
	t.Cleanup(func() { _ = f.service.Close() })
	model, _ := awscatalog.LookupService("iam")
	registry := &gateway.Registry{}
	if err := registry.Register(gateway.Service{Name: "iam", SigningName: "iam", Protocol: gateway.Query, QueryVersion: "2010-05-08", Namespace: "https://iam.amazonaws.com/doc/2010-05-08/", Provider: f.service, Model: &model, Decode: iamapi.DecodeRequest}); err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(registry, gateway.Config{AccountID: "123456789012", Credentials: f.store, Activity: f.service})
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewServer(g)
	t.Cleanup(f.server.Close)
	f.root = f.client("us-east-1", identity.Credential{AccessKeyID: "test", SecretAccessKey: "test"})
	return f
}

func (f *activityFixture) client(region string, key identity.Credential) *sdkiam.Client {
	return sdkiam.New(sdkiam.Options{Region: region, BaseEndpoint: aws.String(f.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key.AccessKeyID, key.SecretAccessKey, key.SessionToken), HTTPClient: f.server.Client(), RetryMaxAttempts: 1})
}

func (f *activityFixture) user(t *testing.T, name string) identity.Credential {
	t.Helper()
	if _, err := f.root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: &name, Path: aws.String("/activity/")}); err != nil {
		t.Fatal(err)
	}
	key, err := f.root.CreateAccessKey(t.Context(), &sdkiam.CreateAccessKeyInput{UserName: &name})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := f.store.Resolve(t.Context(), aws.ToString(key.AccessKey.AccessKeyId))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func activityRows(t *testing.T, repository iam.Repository, scope iam.Scope, principalID string) []iam.PrincipalActivity {
	t.Helper()
	var rows []iam.PrincipalActivity
	if err := repository.View(t.Context(), func(tx iam.ReadTx) error {
		var err error
		rows, err = tx.PrincipalActivities(scope)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return slices.DeleteFunc(rows, func(row iam.PrincipalActivity) bool { return row.PrincipalID != principalID })
}

func TestPrincipalActivityDeniedAttemptsAndCredentialCoalescing(t *testing.T) {
	for _, start := range []time.Time{{}, time.Unix(0, 0).UTC()} {
		t.Run(start.Format(time.RFC3339), func(t *testing.T) {
			f := newActivityFixture(t, nil, start)
			key := f.user(t, "activity")
			client := f.client("us-east-1", key)
			_, err := client.ListUsers(t.Context(), &sdkiam.ListUsersInput{})
			requireCode(t, err, "AccessDenied")
			// Distinct operations at the same instant must remain distinct even
			// though access-key usage keeps its first observation in 15 minutes.
			_, err = client.GetAccountSummary(t.Context(), &sdkiam.GetAccountSummaryInput{})
			requireCode(t, err, "AccessDenied")
			if err := f.clock.Advance(time.Minute); err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			failures := make(chan error, 6)
			for range 6 {
				workers.Go(func() {
					_, err := client.ListUsers(t.Context(), &sdkiam.ListUsersInput{})
					failures <- err
				})
			}
			workers.Wait()
			close(failures)
			for err := range failures {
				requireCode(t, err, "AccessDenied")
			}
			_, err = f.client("eu-west-1", key).ListUsers(t.Context(), &sdkiam.ListUsersInput{})
			requireCode(t, err, "AccessDenied")
			scope := iam.Scope{Partition: "aws", AccountID: key.AccountID}
			rows := activityRows(t, f.repository, scope, key.PrincipalID)
			if len(rows) != 3 {
				t.Fatalf("activity=%+v; want two actions and two distinct regions", rows)
			}
			for _, row := range rows {
				want := start.Add(time.Minute)
				if row.ActionName == "GetAccountSummary" {
					want = start
				}
				if row.ServiceNamespace != "iam" || row.PrincipalARN != key.PrincipalARN || !row.LastAuthenticated.Equal(want) || row.Region == "N/A" {
					t.Fatalf("activity=%+v; want last attempt %v and real request region", row, want)
				}
			}
			_, used, err := f.store.AccessKeyLastUsed(key.AccountID, key.AccessKeyID)
			if err != nil || !used.Date.Equal(start) || used.Service != "iam" || used.Region != "N/A" {
				t.Fatalf("credential usage=%+v, %v; want first attempt with credential-specific region", used, err)
			}
			// Reopening the repository with earlier service time cannot erase
			// newer activity, even while the old timestamp is a valid zero time.
			older := iam.NewWithConfig(iam.Config{Credentials: f.store, Repository: f.repository, Clock: clock.NewManual(start)})
			t.Cleanup(func() { _ = older.Close() })
			ctx := activityContext(t.Context(), key, "aws", "us-east-1")
			if err := older.RecordActivity(ctx, "iam", "ListUsers"); err != nil {
				t.Fatal(err)
			}
			if got := activityRows(t, f.repository, scope, key.PrincipalID); !slices.Equal(got, rows) {
				t.Fatalf("earlier instance changed activity: %+v => %+v", rows, got)
			}
		})
	}
}

func activityContext(ctx context.Context, key identity.Credential, partition, region string) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{AccountID: key.AccountID, Partition: partition, Region: region, AccessKeyID: key.AccessKeyID, PrincipalID: key.PrincipalID, PrincipalARN: key.PrincipalARN, SessionType: string(key.SessionType), IssuerID: key.IssuerID, IssuerARN: key.IssuerARN})
}

type activityFailureRepository struct {
	iam.Repository
	fail   atomic.Bool
	cancel atomic.Bool
}

func (r *activityFailureRepository) Update(ctx context.Context, fn func(iam.WriteTx) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	return r.Repository.Update(ctx, func(tx iam.WriteTx) error {
		return fn(activityFailureTx{WriteTx: tx, fail: r.fail.Load(), cancel: r.cancel.Load(), cancelContext: cancel})
	})
}

type activityFailureTx struct {
	iam.WriteTx
	fail, cancel  bool
	cancelContext context.CancelFunc
}

func (tx activityFailureTx) PutPrincipalActivity(scope iam.Scope, row iam.PrincipalActivity) error {
	if err := tx.WriteTx.PutPrincipalActivity(scope, row); err != nil {
		return err
	}
	if tx.fail {
		return errors.New("activity storage failure")
	}
	if tx.cancel {
		tx.cancelContext()
	}
	return nil
}

func TestPrincipalActivityFailureRollsBackUsageAndPreventsServiceEffects(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "storage failure"
		if canceled {
			name = "precommit cancellation"
		}
		t.Run(name, func(t *testing.T) {
			repository := &activityFailureRepository{Repository: iam.NewMemoryRepository(nil)}
			f := newActivityFixture(t, repository, time.Unix(0, 0).UTC())
			key := f.user(t, "activity")
			_, err := f.root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: aws.String("activity"), PolicyName: aws.String("Create"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			repository.fail.Store(!canceled)
			repository.cancel.Store(canceled)
			_, err = f.client("us-east-1", key).CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("must-not-exist")})
			requireCode(t, err, "ServiceFailure")
			repository.fail.Store(false)
			repository.cancel.Store(false)
			scope := iam.Scope{Partition: "aws", AccountID: key.AccountID}
			if rows := activityRows(t, repository, scope, key.PrincipalID); len(rows) != 0 {
				t.Fatalf("rolled-back activity exists: %+v", rows)
			}
			_, used, err := f.store.AccessKeyLastUsed(key.AccountID, key.AccessKeyID)
			if err != nil || used.Recorded() {
				t.Fatalf("rolled-back credential usage=%+v %v", used, err)
			}
			_, err = f.root.GetUser(t.Context(), &sdkiam.GetUserInput{UserName: aws.String("must-not-exist")})
			requireCode(t, err, "NoSuchEntity")
			if _, err := f.client("us-east-1", key).CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("must-not-exist")}); err != nil {
				t.Fatal(err)
			}
			if rows := activityRows(t, repository, scope, key.PrincipalID); len(rows) != 1 {
				t.Fatalf("successful retry activity=%+v", rows)
			}
		})
	}
}

func TestPrincipalActivitySessionsUseCurrentIssuerAndSurviveCredentialRemoval(t *testing.T) {
	f := newActivityFixture(t, nil, time.Unix(0, 0).UTC())
	parent := f.user(t, "session-user")
	role, err := f.root.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("activity-role"), Path: aws.String("/activity/"), AssumeRolePolicyDocument: aws.String(trustEC2)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.root.PutRolePolicy(t.Context(), &sdkiam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("List"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	// Session issuance is setup here; the behavior under test is subsequent
	// signed HTTP authentication and activity attribution for each token type.
	temporary, err := f.store.IssueSession(t.Context(), parent, identity.SessionSpec{Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	federated, err := f.store.IssueFederation(t.Context(), parent, identity.FederationSpec{Name: "activity-session", Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	assumed, err := f.store.IssueRoleSession(t.Context(), parent, identity.RoleSessionSpec{Role: identity.Principal{AccountID: parent.AccountID, ARN: aws.ToString(role.Role.Arn), ID: aws.ToString(role.Role.RoleId)}, SessionName: "activity-session", Duration: time.Hour, MaxSessionDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.client("us-east-1", temporary).ListUsers(t.Context(), &sdkiam.ListUsersInput{})
	requireCode(t, err, "AccessDenied") // IAM requires MFA for GetSessionToken.
	_, err = f.client("us-east-1", federated).GetAccountSummary(t.Context(), &sdkiam.GetAccountSummaryInput{})
	requireCode(t, err, "AccessDenied") // IAM rejects GetFederationToken sessions.
	if _, err := f.client("us-east-1", assumed).ListUsers(t.Context(), &sdkiam.ListUsersInput{}); err != nil {
		t.Fatal(err)
	}
	scope := iam.Scope{Partition: "aws", AccountID: parent.AccountID}
	userRows := activityRows(t, f.repository, scope, parent.PrincipalID)
	roleRows := activityRows(t, f.repository, scope, assumed.IssuerID)
	if len(userRows) != 2 || len(roleRows) != 1 || roleRows[0].PrincipalARN != assumed.IssuerARN || roleRows[0].ActionName != "ListUsers" {
		t.Fatalf("wrong session attribution: user=%+v role=%+v", userRows, roleRows)
	}
	if rows := activityRows(t, f.repository, scope, assumed.PrincipalID); len(rows) != 0 {
		t.Fatalf("session ARN became a separate IAM principal: %+v", rows)
	}
	if _, err := f.root.DeleteAccessKey(t.Context(), &sdkiam.DeleteAccessKeyInput{UserName: aws.String("session-user"), AccessKeyId: &parent.AccessKeyID}); err != nil {
		t.Fatal(err)
	}
	if err := f.clock.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	// The role session is independent of its issuer's original access key.
	_, err = f.client("us-east-1", assumed).GetAccountSummary(t.Context(), &sdkiam.GetAccountSummaryInput{})
	requireCode(t, err, "AccessDenied")
	roleRows = activityRows(t, f.repository, scope, assumed.IssuerID)
	if len(roleRows) != 2 {
		t.Fatalf("role attempt after source-key revocation missing: %+v", roleRows)
	}
	if err := iam.NewCredentialRepository(f.repository, nil).Update(t.Context(), func(tx identity.Transaction) error { return tx.Delete(assumed.AccessKeyID) }); err != nil {
		t.Fatal(err)
	}
	_, err = f.client("us-east-1", assumed).ListUsers(t.Context(), &sdkiam.ListUsersInput{})
	requireCode(t, err, "InvalidClientTokenId")
	if got := activityRows(t, f.repository, scope, assumed.IssuerID); !slices.Equal(got, roleRows) {
		t.Fatalf("credential removal changed persisted role history: %+v", got)
	}
	if err := f.clock.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	_, err = f.client("us-east-1", temporary).ListUsers(t.Context(), &sdkiam.ListUsersInput{})
	requireCode(t, err, "ExpiredToken")
	if got := activityRows(t, f.repository, scope, parent.PrincipalID); !slices.Equal(got, userRows) {
		t.Fatalf("expired session changed persisted user history: %+v", got)
	}
}

func TestPrincipalActivityRenameAndRecreateKeepImmutableIdentity(t *testing.T) {
	f := newActivityFixture(t, nil, time.Unix(0, 0).UTC())
	key := f.user(t, "before")
	_, err := f.client("us-east-1", key).ListUsers(t.Context(), &sdkiam.ListUsersInput{})
	requireCode(t, err, "AccessDenied")
	_, err = f.root.UpdateUser(t.Context(), &sdkiam.UpdateUserInput{UserName: aws.String("before"), NewUserName: aws.String("after"), NewPath: aws.String("/renamed/")})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.clock.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	_, err = f.client("us-east-1", key).ListUsers(t.Context(), &sdkiam.ListUsersInput{})
	requireCode(t, err, "AccessDenied")
	scope := iam.Scope{Partition: "aws", AccountID: key.AccountID}
	rows := activityRows(t, f.repository, scope, key.PrincipalID)
	if len(rows) != 1 || rows[0].PrincipalARN != "arn:aws:iam::123456789012:user/renamed/after" {
		t.Fatalf("rename lost stable identity: %+v", rows)
	}
	if _, err := f.root.DeleteAccessKey(t.Context(), &sdkiam.DeleteAccessKeyInput{UserName: aws.String("after"), AccessKeyId: &key.AccessKeyID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.root.DeleteUser(t.Context(), &sdkiam.DeleteUserInput{UserName: aws.String("after")}); err != nil {
		t.Fatal(err)
	}
	recreated := f.user(t, "after")
	if recreated.PrincipalID == key.PrincipalID {
		t.Fatal("recreated user reused immutable ID")
	}
	if got := activityRows(t, f.repository, scope, recreated.PrincipalID); len(got) != 0 {
		t.Fatalf("new user inherited old activity: %+v", got)
	}
	_, err = f.client("us-east-1", recreated).ListUsers(t.Context(), &sdkiam.ListUsersInput{})
	requireCode(t, err, "AccessDenied")
	if got := activityRows(t, f.repository, scope, key.PrincipalID); !slices.Equal(got, rows) {
		t.Fatalf("recreated user changed old activity: %+v", got)
	}
}

func TestPrincipalActivityAccountPartitionIsolation(t *testing.T) {
	f := newActivityFixture(t, nil, time.Unix(0, 0).UTC())
	for _, scope := range []struct{ account, partition, region string }{
		{"123456789012", "aws", "us-east-1"},
		{"999999999999", "aws", "us-east-1"},
		{"123456789012", "aws-cn", "cn-north-1"},
		{"123456789012", "aws-us-gov", "us-gov-west-1"},
	} {
		t.Run(scope.account+"/"+scope.partition, func(t *testing.T) {
			root := f.client(scope.region, identity.Credential{AccessKeyID: scope.account, SecretAccessKey: "test"})
			user, err := root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("isolated")})
			if err != nil {
				t.Fatal(err)
			}
			created, err := root.CreateAccessKey(t.Context(), &sdkiam.CreateAccessKeyInput{UserName: user.User.UserName})
			if err != nil {
				t.Fatal(err)
			}
			key, err := f.store.Resolve(t.Context(), aws.ToString(created.AccessKey.AccessKeyId))
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.client(scope.region, key).ListUsers(t.Context(), &sdkiam.ListUsersInput{})
			requireCode(t, err, "AccessDenied")
			ownScope := iam.Scope{AccountID: scope.account, Partition: scope.partition}
			rows := activityRows(t, f.repository, ownScope, key.PrincipalID)
			if len(rows) != 1 || rows[0].PrincipalARN != aws.ToString(user.User.Arn) || rows[0].Region != scope.region {
				t.Fatalf("scoped activity=%+v", rows)
			}
			roots := activityRows(t, f.repository, ownScope, scope.account)
			if len(roots) == 0 || roots[0].PrincipalARN != "arn:"+scope.partition+":iam::"+scope.account+":root" {
				t.Fatalf("bootstrap root not contextualized: %+v", roots)
			}
			foreignPartition, foreignRegion := "aws-cn", "cn-north-1"
			if scope.partition == "aws-cn" {
				foreignPartition, foreignRegion = "aws", "us-east-1"
			}
			_, err = f.client(foreignRegion, key).ListUsers(t.Context(), &sdkiam.ListUsersInput{})
			requireCode(t, err, "InvalidClientTokenId")
			if got := activityRows(t, f.repository, iam.Scope{AccountID: scope.account, Partition: foreignPartition}, key.PrincipalID); len(got) != 0 {
				t.Fatalf("foreign partition received activity: %+v", got)
			}
			if got := activityRows(t, f.repository, ownScope, key.PrincipalID); !slices.Equal(got, rows) {
				t.Fatalf("rejected requests changed activity: %+v", got)
			}
		})
	}
}

func TestPrincipalActivityAcceptedWorkOutlivesSessionCredential(t *testing.T) {
	f := newActivityFixture(t, nil, time.Unix(0, 0).UTC())
	parent := f.user(t, "accepted-work")
	session, err := f.store.IssueSession(t.Context(), parent, identity.SessionSpec{Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	accepted := activityContext(t.Context(), session, "aws", "us-east-1")
	if err := f.clock.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	_, err = f.client("us-east-1", session).ListUsers(t.Context(), &sdkiam.ListUsersInput{})
	requireCode(t, err, "ExpiredToken")
	// A persisted job keeps its accepted caller snapshot. Recording a real
	// downstream attempt must not turn expiry into a second authentication gate.
	if err := f.service.RecordActivity(accepted, "kms", "Decrypt"); err != nil {
		t.Fatal(err)
	}
	if err := iam.NewCredentialRepository(f.repository, nil).Update(t.Context(), func(tx identity.Transaction) error { return tx.Delete(session.AccessKeyID) }); err != nil {
		t.Fatal(err)
	}
	if err := f.service.RecordActivity(accepted, "kms", "GenerateDataKey"); err != nil {
		t.Fatal(err)
	}
	rows := activityRows(t, f.repository, iam.Scope{AccountID: parent.AccountID, Partition: "aws"}, parent.PrincipalID)
	if len(rows) != 2 {
		t.Fatalf("accepted job lost activity after credential expiry/removal: %+v", rows)
	}
	for _, row := range rows {
		if row.PrincipalARN != parent.PrincipalARN || row.ServiceNamespace != "kms" || !row.LastAuthenticated.Equal(f.clock.Now()) {
			t.Fatalf("accepted activity changed principal: %+v", row)
		}
	}
	if _, err := f.store.Resolve(t.Context(), session.AccessKeyID); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("recording resurrected a credential: %v", err)
	}
}
