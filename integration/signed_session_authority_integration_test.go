package stackd_test

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd"
	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
	iamstore "stackd/storage/iam"
	identitystore "stackd/storage/identity"
)

const signedAuthorityTimeout = 5 * time.Second

// This backend observes a successfully committed gateway usage transaction for
// the signed caller, then runs a one-shot hook before the next write transaction
// begins. Reading the caller's credential identifies that transaction even when
// the reporting window coalesces usage and no credential row is rewritten.
// Hooks use public SDKs outside the storage lock; no service internals or
// authorization replacements participate in these tests.
type signedAuthorityRepository struct {
	iamstore.Repository
	mu   sync.Mutex
	plan *signedAuthorityPlan
}

type signedAuthorityPlan struct {
	key            string
	usageCommitted bool
	before         func(context.Context) error
	duringRoleRead func()
	failCommit     bool
	failMFA        bool
	cancelCommit   bool
	entered        bool
	hookErr        error
	issued         []identitystore.Credential
	done           chan struct{}
}

func (tx *signedAuthorityWriteTx) PutMFADevice(scope iamstore.Scope, device iamstore.MFADevice) error {
	if tx.plan != nil && tx.plan.failMFA {
		return errors.New("MFA counter write failed")
	}
	return tx.WriteTx.PutMFADevice(scope, device)
}

func TestSignedMFACodeStorageFailure(t *testing.T) {
	f := newSignedAuthorityFixture(t, storage.NewMemory())
	signedMFADevice(t, f)
	plan := &signedAuthorityPlan{key: f.key, failMFA: true}
	f.repository.arm(plan)
	ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
	defer cancel()
	out, err := f.issue(ctx, "GetSessionToken")
	plan.wait(t, ctx)
	assertAPIError(t, err, "InternalFailure")
	if out != nil || len(plan.issued) != 0 {
		t.Fatal("MFA storage failure published a credential")
	}
	if _, err := f.issue(ctx, "GetSessionToken"); err != nil {
		t.Fatal("failed MFA write consumed the code", err)
	}
}

func (r *signedAuthorityRepository) arm(plan *signedAuthorityPlan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	plan.done = make(chan struct{})
	r.plan = plan
}

func (r *signedAuthorityRepository) Update(ctx context.Context, fn func(iamstore.WriteTx) error) error {
	return r.write(ctx, fn, r.Repository.Update)
}

func (r *signedAuthorityRepository) Attempt(ctx context.Context, fn func(iamstore.WriteTx) error) error {
	return r.write(ctx, fn, r.Repository.Attempt)
}

func (r *signedAuthorityRepository) write(ctx context.Context, fn func(iamstore.WriteTx) error, transaction func(context.Context, func(iamstore.WriteTx) error) error) error {
	r.mu.Lock()
	plan := r.plan
	selected := plan != nil && plan.usageCommitted
	if selected {
		r.plan = nil
		plan.entered = true
	}
	r.mu.Unlock()
	if selected {
		defer close(plan.done)
	}
	if selected && plan.before != nil {
		plan.hookErr = plan.before(ctx)
		if plan.hookErr != nil {
			return plan.hookErr
		}
	}
	transactionContext, cancel := context.WithCancel(ctx)
	defer cancel()
	usage := false
	err := transaction(transactionContext, func(tx iamstore.WriteTx) error {
		wrapped := &signedAuthorityWriteTx{WriteTx: tx, usage: &usage}
		if plan != nil {
			wrapped.key = plan.key
		}
		if selected {
			wrapped.plan = plan
			wrapped.cancel = cancel
		}
		if err := fn(wrapped); err != nil {
			return err
		}
		if selected && plan.failCommit {
			return errors.New("injected signed session commit failure")
		}
		if selected && plan.cancelCommit {
			cancel()
		}
		return nil
	})
	if err == nil && usage && plan != nil && !selected {
		r.mu.Lock()
		if r.plan == plan {
			plan.usageCommitted = true
		}
		r.mu.Unlock()
	}
	return err
}

func (p *signedAuthorityPlan) wait(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-p.done:
	case <-ctx.Done():
		t.Fatal("signed STS request did not finish the authority write boundary:", ctx.Err())
	}
}

type signedAuthorityWriteTx struct {
	iamstore.WriteTx
	key    string
	usage  *bool
	plan   *signedAuthorityPlan
	cancel context.CancelFunc
}

func (tx *signedAuthorityWriteTx) Credential(key string) (identitystore.Record, error) {
	record, err := tx.WriteTx.Credential(key)
	if err == nil && key == tx.key {
		*tx.usage = true
	}
	return record, err
}

func (tx *signedAuthorityWriteTx) PutCredential(record identitystore.Record) error {
	_, existingErr := tx.WriteTx.Credential(record.Credential.AccessKeyID)
	if err := tx.WriteTx.PutCredential(record); err != nil {
		return err
	}
	if tx.plan != nil && errors.Is(existingErr, identitystore.ErrNotFound) && record.Credential.SessionToken != "" {
		tx.plan.issued = append(tx.plan.issued, record.Credential)
		if tx.plan.cancelCommit {
			tx.cancel()
		}
	}
	return nil
}

func (tx *signedAuthorityWriteTx) Roles(scope iamstore.Scope) ([]iamstore.Role, error) {
	roles, err := tx.WriteTx.Roles(scope)
	if err == nil && tx.plan != nil && tx.plan.duringRoleRead != nil {
		hook := tx.plan.duringRoleRead
		tx.plan.duringRoleRead = nil
		hook()
	}
	return roles, err
}

type signedAuthorityFixture struct {
	cloudClients
	repository *signedAuthorityRepository
	clock      *clock.Manual
	root       *iam.Client
	caller     *sts.Client
	userARN    string
	userID     string
	key        string
	role       *iamtypes.Role
	assume     *sts.AssumeRoleInput
	session    *sts.GetSessionTokenInput
	federation *sts.GetFederationTokenInput
}

func newSignedAuthorityFixture(t *testing.T, backends *storage.Backends) *signedAuthorityFixture {
	t.Helper()
	repository := &signedAuthorityRepository{Repository: backends.IAM}
	backends.IAM = repository
	manual := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
	c := clockCloud(t, stackd.Config{Storage: backends, Clock: manual})
	root := c.iam("test", "test", "")
	userARN, key, secret := c.user(t, "test", "signed-caller")
	user, err := root.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("signed-caller")})
	if err != nil {
		t.Fatal(err)
	}
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":["sts:AssumeRole","sts:TagSession","sts:SetSourceIdentity"]}}`, userARN)
	created, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("signed-role"), AssumeRolePolicyDocument: aws.String(trust), MaxSessionDuration: aws.Int32(7200)})
	if err != nil {
		t.Fatal(err)
	}
	putUserPolicy(t, root, "signed-caller", allow(`["sts:AssumeRole","sts:GetFederationToken","sts:TagSession","sts:SetSourceIdentity"]`, "*"))
	return &signedAuthorityFixture{
		cloudClients: c, repository: repository, clock: manual, root: root, caller: c.sts(key, secret, ""), userARN: userARN, userID: aws.ToString(user.User.UserId), key: key, role: created.Role,
		assume:     &sts.AssumeRoleInput{RoleArn: created.Role.Arn, RoleSessionName: aws.String("signed-session"), DurationSeconds: aws.Int32(900)},
		session:    &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)},
		federation: &sts.GetFederationTokenInput{Name: aws.String("signed-federation"), DurationSeconds: aws.Int32(900)},
	}
}

func (f *signedAuthorityFixture) issue(ctx context.Context, action string) (*ststypes.Credentials, error) {
	switch action {
	case "AssumeRole":
		out, err := f.caller.AssumeRole(ctx, f.assume)
		if out != nil {
			return out.Credentials, err
		}
		return nil, err
	case "GetSessionToken":
		out, err := f.caller.GetSessionToken(ctx, f.session)
		if out != nil {
			return out.Credentials, err
		}
		return nil, err
	case "GetFederationToken":
		out, err := f.caller.GetFederationToken(ctx, f.federation)
		if out != nil {
			return out.Credentials, err
		}
		return nil, err
	default:
		return nil, fmt.Errorf("unknown test action %q", action)
	}
}

func (f *signedAuthorityFixture) sessionCount(t *testing.T) int {
	t.Helper()
	count := 0
	err := f.repository.Repository.View(t.Context(), func(tx iamstore.ReadTx) error {
		for _, principal := range []string{f.userID, aws.ToString(f.role.RoleId)} {
			records, err := tx.PrincipalCredentials("000000000000", principal)
			if err != nil {
				return err
			}
			for _, record := range records {
				if record.Credential.SessionToken != "" {
					count++
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func TestSignedSessionAuthoritySDKUsesCurrentState(t *testing.T) {
	cases := []struct {
		name, action, code string
		prepare            func(*testing.T, *signedAuthorityFixture)
		mutate             func(context.Context, *signedAuthorityFixture) error
	}{
		{"trust", "AssumeRole", "AccessDenied", nil, func(ctx context.Context, f *signedAuthorityFixture) error {
			_, err := f.root.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{RoleName: f.role.RoleName, PolicyDocument: aws.String(`{"Statement":{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}}`)})
			return err
		}},
		{"role_deleted", "AssumeRole", "AccessDenied", nil, func(ctx context.Context, f *signedAuthorityFixture) error {
			_, err := f.root.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: f.role.RoleName})
			return err
		}},
		{"role_duration", "AssumeRole", "ValidationError", func(_ *testing.T, f *signedAuthorityFixture) { f.assume.DurationSeconds = aws.Int32(7200) }, func(ctx context.Context, f *signedAuthorityFixture) error {
			_, err := f.root.UpdateRole(ctx, &iam.UpdateRoleInput{RoleName: f.role.RoleName, MaxSessionDuration: aws.Int32(3600)})
			return err
		}},
		{"identity_policy", "AssumeRole", "AccessDenied", nil, signedDenyCaller},
		{"federation_identity_policy", "GetFederationToken", "AccessDenied", nil, signedDenyCaller},
		{"boundary", "AssumeRole", "AccessDenied", nil, func(ctx context.Context, f *signedAuthorityFixture) error {
			policy, err := f.root.CreatePolicy(ctx, &iam.CreatePolicyInput{PolicyName: aws.String("deny-assumption"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"*"}}`)})
			if err != nil {
				return err
			}
			_, err = f.root.PutUserPermissionsBoundary(ctx, &iam.PutUserPermissionsBoundaryInput{UserName: aws.String("signed-caller"), PermissionsBoundary: policy.Policy.Arn})
			return err
		}},
		{"managed_session_policy", "AssumeRole", "MalformedPolicyDocument", signedManagedSessionPolicy, signedDeleteSessionPolicy},
		{"federation_managed_policy", "GetFederationToken", "MalformedPolicyDocument", signedManagedSessionPolicy, signedDeleteSessionPolicy},
		{"mfa_disabled", "GetSessionToken", "AccessDenied", signedMFADevice, signedDeactivateMFA},
		{"assume_mfa_disabled", "AssumeRole", "AccessDenied", signedMFADevice, signedDeactivateMFA},
		{"session_parent_disabled", "GetSessionToken", "InvalidClientTokenId", nil, signedDisableCaller},
		{"federation_parent_disabled", "GetFederationToken", "InvalidClientTokenId", nil, signedDisableCaller},
		{"assume_parent_disabled", "AssumeRole", "InvalidClientTokenId", nil, signedDisableCaller},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSignedAuthorityFixture(t, storage.NewMemory())
			if tc.prepare != nil {
				tc.prepare(t, f)
			}
			plan := &signedAuthorityPlan{key: f.key, before: func(ctx context.Context) error { return tc.mutate(ctx, f) }}
			f.repository.arm(plan)
			ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
			defer cancel()
			out, err := f.issue(ctx, tc.action)
			plan.wait(t, ctx)
			assertAPIError(t, err, tc.code)
			if !plan.entered || plan.hookErr != nil {
				t.Fatalf("authority mutation did not complete: entered=%v, error=%v", plan.entered, plan.hookErr)
			}
			if out != nil || f.sessionCount(t) != 0 {
				t.Fatal("a request denied by current authority state issued credentials")
			}
		})
	}
}

func signedDeactivateMFA(ctx context.Context, f *signedAuthorityFixture) error {
	_, err := f.root.DeactivateMFADevice(ctx, &iam.DeactivateMFADeviceInput{UserName: aws.String("signed-caller"), SerialNumber: f.session.SerialNumber})
	if err != nil {
		return err
	}
	return f.clock.Advance(10 * time.Second)
}

func signedDenyCaller(ctx context.Context, f *signedAuthorityFixture) error {
	_, err := f.root.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: aws.String("signed-caller"), PolicyName: aws.String("access"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Deny","Action":"sts:*","Resource":"*"}}`)})
	return err
}

func signedDisableCaller(ctx context.Context, f *signedAuthorityFixture) error {
	_, err := f.root.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{UserName: aws.String("signed-caller"), AccessKeyId: aws.String(f.key), Status: iamtypes.StatusTypeInactive})
	return err
}

func signedManagedSessionPolicy(t *testing.T, f *signedAuthorityFixture) {
	t.Helper()
	policy, err := f.root.CreatePolicy(t.Context(), &iam.CreatePolicyInput{PolicyName: aws.String("session-limit"), PolicyDocument: aws.String(allow(`"sqs:SendMessage"`, "*"))})
	if err != nil {
		t.Fatal(err)
	}
	f.assume.PolicyArns = []ststypes.PolicyDescriptorType{{Arn: policy.Policy.Arn}}
	f.federation.PolicyArns = []ststypes.PolicyDescriptorType{{Arn: policy.Policy.Arn}}
}

func signedDeleteSessionPolicy(ctx context.Context, f *signedAuthorityFixture) error {
	_, err := f.root.DeletePolicy(ctx, &iam.DeletePolicyInput{PolicyArn: f.assume.PolicyArns[0].Arn})
	return err
}

func signedMFADevice(t *testing.T, f *signedAuthorityFixture) {
	t.Helper()
	device, err := f.root.CreateVirtualMFADevice(t.Context(), &iam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("signed-device")})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(device.VirtualMFADevice.Base32StringSeed))
	if err != nil {
		t.Fatal(err)
	}
	step := f.clock.Now().Unix() / 30
	_, err = f.root.EnableMFADevice(t.Context(), &iam.EnableMFADeviceInput{UserName: aws.String("signed-caller"), SerialNumber: device.VirtualMFADevice.SerialNumber, AuthenticationCode1: aws.String(otpForTest(seed, step-1)), AuthenticationCode2: aws.String(otpForTest(seed, step))})
	if err != nil {
		t.Fatal(err)
	}
	f.session.SerialNumber, f.session.TokenCode = device.VirtualMFADevice.SerialNumber, aws.String(otpForTest(seed, step+1))
	f.assume.SerialNumber, f.assume.TokenCode = f.session.SerialNumber, f.session.TokenCode
	advanceClock(t, f.clock, 10*time.Second)
}

func TestSignedSessionAuthoritySDKRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, action := range []string{"AssumeRole", "GetSessionToken", "GetFederationToken"} {
			for _, failure := range []string{"commit_failure", "cancellation"} {
				t.Run(backend+"/"+action+"/"+failure, func(t *testing.T) {
					backends := storage.NewMemory()
					if backend == "sqlite" {
						backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
					}
					testSignedSessionRollback(t, backends, action, failure)
				})
			}
		}
	}
}

func testSignedSessionRollback(t *testing.T, backends *storage.Backends, action, failure string) {
	f := newSignedAuthorityFixture(t, backends)
	if action != "GetFederationToken" {
		signedMFADevice(t, f)
	}
	baseline, err := backends.Journal.Read(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	credentials := credentialEvents(baseline)
	if len(credentials) != 1 || credentials[0].AccessKeyChanged.Action != journal.AccessKeyCreated || credentials[0].AccessKeyChanged.AccessKeyID != f.key || credentials[0].AccessKeyChanged.PrincipalARN != f.userARN {
		t.Fatal("caller credential publication is missing", credentials)
	}
	plan := &signedAuthorityPlan{key: f.key, failCommit: failure == "commit_failure", cancelCommit: failure == "cancellation"}
	f.repository.arm(plan)
	ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
	defer cancel()
	out, err := f.issue(ctx, action)
	plan.wait(t, ctx)
	if err == nil || out != nil {
		t.Fatal("failed transaction returned session credentials")
	}
	if !plan.entered || len(plan.issued) != 1 {
		t.Fatalf("failure did not follow one session insertion: entered=%v, insertions=%d", plan.entered, len(plan.issued))
	}
	if f.sessionCount(t) != 0 {
		t.Fatal("failed transaction persisted a session")
	}
	events, err := backends.Journal.Read(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < len(baseline) || !reflect.DeepEqual(events[:len(baseline)], baseline) {
		t.Fatal("failed transaction changed previously committed journal entries", events)
	}
	if !reflect.DeepEqual(credentialEvents(events), credentials) {
		t.Fatal("failed transaction changed credential event history", events)
	}
	attempted := plan.issued[0]
	_, err = f.sts(attempted.AccessKeyID, attempted.SecretAccessKey, attempted.SessionToken).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	assertAPIError(t, err, "InvalidClientTokenId")
	if action != "GetFederationToken" {
		if _, err := f.issue(ctx, action); err != nil {
			t.Fatal("failed publication consumed the MFA code", err)
		}
		_, err := f.issue(ctx, action)
		assertAPIError(t, err, "AccessDenied")
	}
}

func TestSignedSessionAuthoritySDKExpiredParent(t *testing.T) {
	f := newSignedAuthorityFixture(t, storage.NewMemory())
	parent, err := f.caller.GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
	if err != nil {
		t.Fatal(err)
	}
	f.caller = f.sessionSTS(parent.Credentials)
	plan := &signedAuthorityPlan{key: aws.ToString(parent.Credentials.AccessKeyId), before: func(context.Context) error { return f.clock.Advance(15 * time.Minute) }}
	f.repository.arm(plan)
	ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
	defer cancel()
	out, err := f.issue(ctx, "AssumeRole")
	plan.wait(t, ctx)
	assertAPIError(t, err, "ExpiredToken")
	if !plan.entered || plan.hookErr != nil || out != nil || f.sessionCount(t) != 1 {
		t.Fatal("expiry at authority entry did not preserve only the existing parent session")
	}
}

func TestSignedSessionAuthoritySDKCrossAccountSessionPolicies(t *testing.T) {
	f := newSignedAuthorityFixture(t, storage.NewMemory())
	ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
	defer cancel()
	const destination = "123456789012"
	owner := f.iam(destination, "test", "")
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalAccount":"000000000000","aws:PrincipalArn":%q}}}}`, f.userARN)
	role, err := owner.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("destination-role"), AssumeRolePolicyDocument: aws.String(trust)})
	if err != nil {
		t.Fatal(err)
	}
	queues := f.sqs(destination, "test", "")
	queue, err := queues.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("destination-work")})
	if err != nil {
		t.Fatal(err)
	}
	const queueARN = "arn:aws:sqs:us-east-1:123456789012:destination-work"
	putRolePolicy(t, owner, "destination-role", allow(`["sqs:SendMessage","sqs:ReceiveMessage"]`, queueARN))
	policy, err := owner.CreatePolicy(ctx, &iam.CreatePolicyInput{PolicyName: aws.String("same-name"), PolicyDocument: aws.String(allow(`"sqs:SendMessage"`, queueARN))})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.root.CreatePolicy(ctx, &iam.CreatePolicyInput{PolicyName: aws.String("same-name"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Deny","Action":"sqs:*","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	callerPolicy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":%q,"Condition":{"StringEquals":{"aws:PrincipalAccount":"000000000000","aws:ResourceAccount":"123456789012"}}}}`, aws.ToString(role.Role.Arn))
	putUserPolicy(t, f.root, "signed-caller", callerPolicy)
	f.assume.RoleArn = role.Role.Arn
	f.assume.PolicyArns = []ststypes.PolicyDescriptorType{{Arn: policy.Policy.Arn}}
	plan := &signedAuthorityPlan{key: f.key}
	f.repository.arm(plan)
	issued, err := f.issue(ctx, "AssumeRole")
	plan.wait(t, ctx)
	if err != nil {
		t.Fatal("caller identity or destination policy scope changed:", err)
	}
	who, err := f.sessionSTS(issued).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(who.Account) != destination {
		t.Fatalf("destination session identity: %v, %v", who, err)
	}
	session := f.sessionSQS(issued)
	if _, err := session.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("authorized across accounts")}); err != nil {
		t.Fatal("destination managed session policy was not used:", err)
	}
	_, err = session.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
	assertAPIError(t, err, "AccessDenied")
	before := federationIntegrationCredentialCount(t, f.repository.Repository, destination, aws.ToString(role.Role.RoleId))
	// The clock remains unchanged, so the gateway coalesces this caller's
	// repeated usage. The authority hook must still run before issuance.
	plan = &signedAuthorityPlan{key: f.key, before: func(ctx context.Context) error { return signedDenyCaller(ctx, f) }}
	f.repository.arm(plan)
	issued, err = f.issue(ctx, "AssumeRole")
	plan.wait(t, ctx)
	assertAPIError(t, err, "AccessDenied")
	if plan.hookErr != nil || issued != nil || federationIntegrationCredentialCount(t, f.repository.Repository, destination, aws.ToString(role.Role.RoleId)) != before {
		t.Fatal("cross-account issuance ignored the caller's current deny")
	}
}

func TestSignedSessionAuthoritySDKConcurrentWriterCannotMixPolicies(t *testing.T) {
	f := newSignedAuthorityFixture(t, storage.NewMemory())
	ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
	defer cancel()
	if err := signedDenyCaller(ctx, f); err != nil {
		t.Fatal(err)
	}
	started, finished := make(chan struct{}), make(chan error, 1)
	plan := &signedAuthorityPlan{key: f.key}
	plan.duringRoleRead = func() {
		go func() {
			close(started)
			finished <- f.repository.Repository.Update(ctx, func(tx iamstore.WriteTx) error {
				scope := iamstore.Scope{Partition: "aws", AccountID: "000000000000"}
				user, err := tx.User(scope, "signed-caller")
				if err != nil {
					return err
				}
				user.Inline["access"] = allow(`"sts:AssumeRole"`, "*")
				if err := tx.PutUser(scope, user); err != nil {
					return err
				}
				role, err := tx.Role(scope, "signed-role")
				if err != nil {
					return err
				}
				role.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}}`
				return tx.PutRole(scope, role)
			})
		}()
		<-started
	}
	f.repository.arm(plan)
	issued, err := f.issue(ctx, "AssumeRole")
	plan.wait(t, ctx)
	assertAPIError(t, err, "AccessDenied")
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal("concurrent writer failed:", err)
		}
	case <-ctx.Done():
		t.Fatal("authority blocked the concurrent writer after returning:", ctx.Err())
	}
	if issued != nil || f.sessionCount(t) != 0 {
		t.Fatal("mixed the first state's trust allow with the second state's identity allow")
	}
	_, err = f.issue(ctx, "AssumeRole")
	assertAPIError(t, err, "AccessDenied")
}

func TestSignedSessionAuthoritySDKCapturesTimeAfterWaiting(t *testing.T) {
	f := newSignedAuthorityFixture(t, storage.NewMemory())
	start := f.clock.Now()
	deadline := start.Add(90 * time.Second)
	document := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"sts:*","Resource":"*"},{"Effect":"Deny","Action":"sts:*","Resource":"*","Condition":{"DateGreaterThanEquals":{"aws:CurrentTime":%q}}}]}`, deadline.Format(time.RFC3339))
	putUserPolicy(t, f.root, "signed-caller", document)
	f.assume.Tags = []ststypes.Tag{{Key: aws.String("team"), Value: aws.String("clock")}}
	f.assume.SourceIdentity = aws.String("clock-source")
	plan := &signedAuthorityPlan{key: f.key, before: func(context.Context) error { return f.clock.Advance(time.Minute) }}
	plan.duringRoleRead = func() { plan.hookErr = f.clock.Advance(time.Minute) }
	f.repository.arm(plan)
	ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
	defer cancel()
	issued, err := f.issue(ctx, "AssumeRole")
	plan.wait(t, ctx)
	if err != nil || plan.hookErr != nil {
		t.Fatalf("time changed within one authority decision: %v, %v", err, plan.hookErr)
	}
	if len(plan.issued) != 1 || !plan.issued[0].CreateDate.Equal(start.Add(time.Minute)) || !aws.ToTime(issued.Expiration).Equal(start.Add(16*time.Minute)) {
		t.Fatal("issuance did not use the instant captured after waiting for the authority transaction")
	}
	if !f.clock.Now().Equal(start.Add(2 * time.Minute)) {
		t.Fatal("test did not advance the clock through the authorization cutoff")
	}
	_, err = f.issue(ctx, "AssumeRole")
	assertAPIError(t, err, "AccessDenied")
}

func TestSignedSessionAuthoritySDKRefreshesRenamedCaller(t *testing.T) {
	for _, action := range []string{"AssumeRole", "GetSessionToken", "GetFederationToken"} {
		t.Run(action, func(t *testing.T) {
			f := newSignedAuthorityFixture(t, storage.NewMemory())
			// The gateway authenticates the original name. Only the identity
			// refreshed inside the authority transaction satisfies this policy.
			putUserPolicy(t, f.root, "signed-caller", `{"Statement":[{"Effect":"Allow","Action":"sts:*","Resource":"*"},{"Effect":"Deny","Action":"sts:*","Resource":"*","Condition":{"StringNotEquals":{"aws:username":"renamed-caller"}}}]}`)
			plan := &signedAuthorityPlan{key: f.key, before: func(ctx context.Context) error {
				_, err := f.root.UpdateUser(ctx, &iam.UpdateUserInput{UserName: aws.String("signed-caller"), NewUserName: aws.String("renamed-caller")})
				return err
			}}
			f.repository.arm(plan)
			ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
			defer cancel()
			issued, err := f.issue(ctx, action)
			plan.wait(t, ctx)
			if err != nil || plan.hookErr != nil || len(plan.issued) != 1 {
				t.Fatalf("renamed caller was not refreshed at authority entry: %v, %v; insertions=%d", err, plan.hookErr, len(plan.issued))
			}
			const currentARN = "arn:aws:iam::000000000000:user/renamed-caller"
			if action == "GetSessionToken" {
				who, err := f.sessionSTS(issued).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
				if err != nil || aws.ToString(who.Arn) != currentARN || aws.ToString(who.UserId) != f.userID {
					t.Fatalf("session retained the stale caller identity: %v, %v", who, err)
				}
			}
			if action == "GetFederationToken" && (plan.issued[0].IssuerARN != currentARN || plan.issued[0].IssuerID != f.userID) {
				t.Fatal("federation session retained a stale issuing identity")
			}
		})
	}
}
