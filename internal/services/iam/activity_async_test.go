package iam_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

var errAsyncActivityWrite = errors.New("reporting writer unavailable")

type activityWriteGate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *activityWriteGate) unblock() { g.once.Do(func() { close(g.release) }) }

type asyncActivityRepository struct {
	iam.Repository
	gate           atomic.Pointer[activityWriteGate]
	fail           atomic.Bool
	updates        atomic.Int64
	activityWrites atomic.Int64
	usageWrites    atomic.Int64
}

func (r *asyncActivityRepository) Update(ctx context.Context, fn func(iam.WriteTx) error) error {
	if gate := r.gate.Load(); gate != nil {
		select {
		case gate.entered <- struct{}{}:
		default:
		}
		select {
		case <-gate.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if r.fail.Load() {
		return errAsyncActivityWrite
	}
	r.updates.Add(1)
	return r.Repository.Update(ctx, func(tx iam.WriteTx) error { return fn(asyncActivityTx{WriteTx: tx, repository: r}) })
}

type asyncActivityTx struct {
	iam.WriteTx
	repository *asyncActivityRepository
}

func (asyncActivityTx) User(iam.Scope, string) (iam.User, error) {
	return iam.User{}, errors.New("activity hydrated a user by mutable name")
}

func (asyncActivityTx) Users(iam.Scope) ([]iam.User, error) {
	return nil, errors.New("activity enumerated an account's users")
}

func (asyncActivityTx) PrincipalCredentials(string, string) ([]identity.Record, error) {
	return nil, errors.New("activity principal fencing depended on remaining credentials")
}

func (tx asyncActivityTx) PutPrincipalActivity(scope iam.Scope, row iam.PrincipalActivity) error {
	tx.repository.activityWrites.Add(1)
	return tx.WriteTx.PutPrincipalActivity(scope, row)
}

func (tx asyncActivityTx) PutCredentialUsage(key string, use identity.LastUsed) error {
	tx.repository.usageWrites.Add(1)
	return tx.WriteTx.PutCredentialUsage(key, use)
}

func bufferedActivityFixture(t *testing.T, start time.Time) (*iam.Service, *asyncActivityRepository, *clock.Manual, identity.Credential) {
	t.Helper()
	return bufferedActivityFixtureOn(t, iam.NewMemoryRepository(nil), start)
}

func bufferedActivityFixtureOn(t *testing.T, backing iam.Repository, start time.Time) (*iam.Service, *asyncActivityRepository, *clock.Manual, identity.Credential) {
	t.Helper()
	repository := &asyncActivityRepository{Repository: backing}
	key := identity.Credential{AccessKeyID: "AKIABUFFERED", AccountID: "123456789012", PrincipalID: "AIDABUFFERED", PrincipalARN: "arn:aws:iam::123456789012:user/path/buffered", UserName: "buffered"}
	if err := repository.Repository.Update(t.Context(), func(tx iam.WriteTx) error {
		if err := tx.PutUser(iam.Scope{Partition: "aws", AccountID: key.AccountID}, iam.User{UserId: key.PrincipalID, UserName: key.UserName, Arn: key.PrincipalARN}); err != nil {
			return err
		}
		return tx.PutCredential(identity.Record{Credential: key, Status: identity.Active, LastUsed: identity.LastUsed{Service: "N/A", Region: "N/A"}})
	}); err != nil {
		t.Fatal(err)
	}
	source := clock.NewManual(start)
	service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: source})
	t.Cleanup(func() {
		repository.gate.Store(nil)
		repository.fail.Store(false)
		_ = service.Close()
	})
	return service, repository, source, key
}

func bufferedCredential(t *testing.T, repository iam.Repository, key string) identity.Record {
	t.Helper()
	var record identity.Record
	if err := repository.View(t.Context(), func(tx iam.ReadTx) error {
		var err error
		record, err = tx.Credential(key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return record
}

func awaitActivitySignal[T any](t *testing.T, signal <-chan T) T {
	t.Helper()
	select {
	case value := <-signal:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("activity work did not complete")
		var zero T
		return zero
	}
}

func TestAsyncActivityEnqueueWhileWriterBlockedAndFailureMerge(t *testing.T) {
	start := time.Date(2035, 1, 2, 3, 4, 5, 123456789, time.UTC)
	service, repository, source, key := bufferedActivityFixture(t, start)
	ctx := activityContext(t.Context(), key, "aws", "us-east-1")
	gate := &activityWriteGate{entered: make(chan struct{}, 1), release: make(chan struct{})}
	repository.gate.Store(gate)
	repository.fail.Store(true)
	defer gate.unblock()
	if err := service.RecordActivity(ctx, "s3", "GetObject"); err != nil {
		t.Fatal(err)
	}
	flushed := make(chan error, 1)
	go func() { flushed <- service.FlushActivity(t.Context()) }()
	awaitActivitySignal(t, gate.entered)
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(activityContext(t.Context(), key, "aws", "eu-west-1"))
	cancel()
	enqueued := make(chan error, 1)
	go func() {
		if err := service.RecordActivity(canceled, "kms", "Decrypt"); err != nil {
			enqueued <- err
			return
		}
		enqueued <- service.RecordActivity(ctx, "s3", "GetObject")
	}()
	if err := awaitActivitySignal(t, enqueued); err != nil {
		t.Fatalf("enqueue inherited a canceled request or waited for the writer: %v", err)
	}
	// Read the underlying authority while the reporting writer is held before
	// its transaction: no unflushed reporting update is durable.
	scope := iam.Scope{Partition: "aws", AccountID: key.AccountID}
	if rows := activityRows(t, repository.Repository, scope, key.PrincipalID); len(rows) != 0 {
		t.Fatalf("unflushed activity is durable: %+v", rows)
	}
	if used := bufferedCredential(t, repository.Repository, key.AccessKeyID).LastUsed; used.Recorded() {
		t.Fatalf("unflushed credential usage is durable: %+v", used)
	}
	repository.gate.Store(nil)
	gate.unblock()
	if err := awaitActivitySignal(t, flushed); !errors.Is(err, errAsyncActivityWrite) {
		t.Fatalf("explicit failed drain=%v", err)
	}
	if err := service.FlushActivity(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled drain=%v", err)
	}
	repository.fail.Store(false)
	if err := source.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := service.FlushActivity(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows := activityRows(t, repository.Repository, scope, key.PrincipalID)
	if len(rows) != 2 {
		t.Fatalf("failed snapshot lost concurrent arrivals: %+v", rows)
	}
	for _, row := range rows {
		if !row.LastAuthenticated.Equal(start.Add(time.Second)) {
			t.Fatalf("flush time replaced observation time: %+v", row)
		}
		if row.ServiceNamespace == "kms" && row.Region != "eu-west-1" {
			t.Fatalf("canceled caller metadata changed: %+v", row)
		}
	}
	used := bufferedCredential(t, repository.Repository, key.AccessKeyID).LastUsed
	if !used.Date.Equal(start) || used.Service != "s3" || used.Region != "us-east-1" {
		t.Fatalf("failure merge replaced the first coherent credential observation: %+v", used)
	}
	if repository.updates.Load() != 1 || repository.activityWrites.Load() != 2 || repository.usageWrites.Load() != 1 {
		t.Fatalf("batch writes: transactions=%d activities=%d credentials=%d", repository.updates.Load(), repository.activityWrites.Load(), repository.usageWrites.Load())
	}
}

func TestAsyncActivityCoalescesRowsWithoutLosingCredentialWindowCandidates(t *testing.T) {
	start := time.Time{}
	service, repository, source, key := bufferedActivityFixture(t, start)
	if err := repository.Repository.Update(t.Context(), func(tx iam.WriteTx) error {
		return tx.PutCredentialUsage(key.AccessKeyID, identity.LastUsed{Date: start, Service: "sts", Region: "us-east-1"})
	}); err != nil {
		t.Fatal(err)
	}
	gate := &activityWriteGate{entered: make(chan struct{}, 1), release: make(chan struct{})}
	defer gate.unblock()
	repository.gate.Store(gate)
	repository.fail.Store(true)
	blocked := make(chan error, 1)
	started := false
	for _, observation := range []struct {
		advance time.Duration
		service string
		region  string
	}{
		{14 * time.Minute, "s3", "us-east-1"},
		{2 * time.Minute, "iam", "eu-west-1"},
		{14 * time.Minute, "sqs", "ap-south-1"},
		{time.Minute, "kms", "eu-central-1"},
	} {
		if err := source.Advance(observation.advance); err != nil {
			t.Fatal(err)
		}
		ctx := activityContext(t.Context(), key, "aws", observation.region)
		for range 100 {
			if err := service.RecordActivity(ctx, observation.service, "Attempt"); err != nil {
				t.Fatal(err)
			}
			if !started {
				started = true
				go func() { blocked <- service.FlushActivity(t.Context()) }()
				awaitActivitySignal(t, gate.entered)
			}
		}
	}
	repository.gate.Store(nil)
	gate.unblock()
	if err := awaitActivitySignal(t, blocked); !errors.Is(err, errAsyncActivityWrite) {
		t.Fatalf("held batch drain=%v", err)
	}
	repository.fail.Store(false)
	if err := service.FlushActivity(t.Context()); err != nil {
		t.Fatal(err)
	}
	used := bufferedCredential(t, repository.Repository, key.AccessKeyID).LastUsed
	if !used.Date.Equal(start.Add(31*time.Minute)) || used.Service != "kms" || used.Region != "eu-central-1" {
		t.Fatalf("intermediate first-use boundary candidate was discarded: %+v", used)
	}
	rows := activityRows(t, repository.Repository, iam.Scope{Partition: "aws", AccountID: key.AccountID}, key.PrincipalID)
	if len(rows) != 4 || repository.updates.Load() != 1 || repository.activityWrites.Load() != 4 || repository.usageWrites.Load() != 1 {
		t.Fatalf("coalesced batch=%+v; transactions=%d activities=%d credentials=%d", rows, repository.updates.Load(), repository.activityWrites.Load(), repository.usageWrites.Load())
	}
	for _, row := range rows {
		if row.ServiceNamespace == "iam" && (row.Region != "eu-west-1" || !row.LastAuthenticated.Equal(start.Add(16*time.Minute))) {
			t.Fatalf("credential normalization leaked into activity history: %+v", row)
		}
	}
}

func TestAsyncActivityWorkerUsesWallTimeAndShutdownIsJoined(t *testing.T) {
	start := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	service, repository, _, key := bufferedActivityFixture(t, start)
	gate := &activityWriteGate{entered: make(chan struct{}, 1), release: make(chan struct{})}
	defer gate.unblock()
	repository.gate.Store(gate)
	if err := service.RecordActivity(activityContext(t.Context(), key, "aws", "us-east-1"), "s3", "GetObject"); err != nil {
		t.Fatal(err)
	}
	// No StartWorkers or service-clock advance: the first observation owns a
	// managed one-second wall-clock worker, even for a standalone service.
	awaitActivitySignal(t, gate.entered)
	closed := make(chan error, 1)
	go func() { closed <- service.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("shutdown did not join the in-flight reporting transaction: %v", err)
	default:
	}
	repository.gate.Store(nil)
	gate.unblock()
	if err := awaitActivitySignal(t, closed); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	used := bufferedCredential(t, repository.Repository, key.AccessKeyID).LastUsed
	if !used.Date.Equal(start) || used.Service != "s3" {
		t.Fatalf("shutdown did not flush the captured observation: %+v", used)
	}
	if err := service.RecordActivity(activityContext(t.Context(), key, "aws", "us-east-1"), "s3", "GetObject"); err == nil {
		t.Fatal("closed service accepted reporting work without an owner")
	}
}

func TestAsyncActivityShutdownReportsFailureAndKeepsPendingForExplicitDrain(t *testing.T) {
	service, repository, _, key := bufferedActivityFixture(t, time.Time{})
	if err := service.RecordActivity(activityContext(t.Context(), key, "aws", "us-east-1"), "iam", "ListUsers"); err != nil {
		t.Fatal(err)
	}
	repository.fail.Store(true)
	if err := service.Close(); !errors.Is(err, errAsyncActivityWrite) {
		t.Fatalf("shutdown failure=%v", err)
	}
	if err := service.Close(); !errors.Is(err, errAsyncActivityWrite) {
		t.Fatalf("repeated shutdown failure=%v", err)
	}
	repository.fail.Store(false)
	if err := service.FlushActivity(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows := activityRows(t, repository.Repository, iam.Scope{Partition: "aws", AccountID: key.AccountID}, key.PrincipalID)
	if len(rows) != 1 || !rows[0].LastAuthenticated.IsZero() {
		t.Fatalf("shutdown failure discarded pending zero-time activity: %+v", rows)
	}
}

func TestAsyncActivityCapturesOnlyTrustedScalarMetadata(t *testing.T) {
	service, repository, _, key := bufferedActivityFixture(t, time.Time{})
	metadata := awsctx.Metadata{AccountID: key.AccountID, Partition: "aws", Region: "eu-west-1", AccessKeyID: key.AccessKeyID, PrincipalID: key.PrincipalID, PrincipalARN: key.PrincipalARN, SessionTags: map[string]string{"secret": "not-reporting-data"}, SessionContext: map[string][]string{"source": {"original"}}}
	ctx, cancel := context.WithCancel(awsctx.WithMetadata(t.Context(), metadata))
	if err := service.RecordActivity(ctx, "s3", "GetObject"); err != nil {
		t.Fatal(err)
	}
	cancel()
	metadata.Region = "ap-south-1"
	metadata.PrincipalID = "replacement"
	metadata.SessionTags["secret"] = "changed"
	metadata.SessionContext["source"][0] = "changed"
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	rows := activityRows(t, repository.Repository, iam.Scope{Partition: "aws", AccountID: key.AccountID}, key.PrincipalID)
	if len(rows) != 1 || rows[0].Region != "eu-west-1" || rows[0].PrincipalARN != key.PrincipalARN {
		t.Fatalf("caller mutation/cancellation changed accepted reporting data: %+v", rows)
	}
}

func TestAsyncActivityIdentityFencesDoNotPoisonOtherObservations(t *testing.T) {
	service, repository, _, key := bufferedActivityFixture(t, time.Time{})
	scope := iam.Scope{Partition: "aws", AccountID: key.AccountID}
	ctx := activityContext(t.Context(), key, "aws", "us-east-1")
	if err := service.RecordActivity(ctx, "s3", "GetObject"); err != nil {
		t.Fatal(err)
	}
	replacement := key
	replacement.PrincipalID = "AIDAREPLACEMENT"
	valid := replacement
	valid.AccessKeyID = "AKIACURRENT"
	if err := repository.Repository.Update(t.Context(), func(tx iam.WriteTx) error {
		if err := tx.DeleteUser(scope, key.UserName); err != nil {
			return err
		}
		if err := tx.PutUser(scope, iam.User{UserName: key.UserName, UserId: replacement.PrincipalID, Arn: key.PrincipalARN}); err != nil {
			return err
		}
		if err := tx.PutCredential(identity.Record{Credential: replacement, Status: identity.Active}); err != nil {
			return err
		}
		return tx.PutCredential(identity.Record{Credential: valid, Status: identity.Active})
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.RecordActivity(activityContext(t.Context(), valid, "aws", "eu-west-1"), "kms", "Decrypt"); err != nil {
		t.Fatal(err)
	}
	if err := service.FlushActivity(t.Context()); err != nil {
		t.Fatal(err)
	}
	if used := bufferedCredential(t, repository.Repository, key.AccessKeyID).LastUsed; used.Recorded() {
		t.Fatalf("replacement credential inherited stale usage: %+v", used)
	}
	if rows := activityRows(t, repository.Repository, scope, key.PrincipalID); len(rows) != 0 {
		t.Fatalf("deleted principal reporting was resurrected: %+v", rows)
	}
	rows := activityRows(t, repository.Repository, scope, valid.PrincipalID)
	if len(rows) != 1 || rows[0].ServiceNamespace != "kms" || rows[0].Region != "eu-west-1" {
		t.Fatalf("stale principal poisoned unrelated activity: %+v", rows)
	}
	if used := bufferedCredential(t, repository.Repository, valid.AccessKeyID).LastUsed; !used.Recorded() || used.Service != "kms" {
		t.Fatalf("valid credential lost its observation: %+v", used)
	}
}

func TestAsyncActivityAcceptedRoleUseSurvivesMissingSessionAndFencesRecreatedIssuer(t *testing.T) {
	start := time.Time{}
	service, repository, source, parent := bufferedActivityFixture(t, start)
	scope := iam.Scope{Partition: "aws", AccountID: parent.AccountID}
	live := iam.Role{RoleName: "live", RoleId: "AROALIVE", Arn: "arn:aws:iam::123456789012:role/path/live"}
	stale := iam.Role{RoleName: "stale", RoleId: "AROASTALE", Arn: "arn:aws:iam::123456789012:role/path/stale"}
	session := func(key string, role iam.Role) identity.Credential {
		return identity.Credential{AccessKeyID: key, AccountID: parent.AccountID, PrincipalID: role.RoleId + ":accepted", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/" + role.RoleName + "/accepted", SessionType: identity.SessionTypeAssumeRole, SessionToken: "token", IssuerID: role.RoleId, IssuerARN: role.Arn, Expiration: start.Add(time.Hour)}
	}
	missing := session("ASIAMISSING", live)
	expired := session("ASIAEXPIRED", live)
	recreated := session("ASIASTALE", stale)
	if err := repository.Repository.Update(t.Context(), func(tx iam.WriteTx) error {
		if err := tx.PutRole(scope, live); err != nil {
			return err
		}
		if err := tx.PutRole(scope, stale); err != nil {
			return err
		}
		for _, key := range []identity.Credential{missing, expired, recreated} {
			if err := tx.PutCredential(identity.Record{Credential: key, Status: identity.Active}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Capture accepted work now, then remove/expire its sessions and replace
	// an issuer before the durable reporting boundary.
	for _, key := range []identity.Credential{missing, expired, recreated} {
		if err := service.RecordActivity(activityContext(t.Context(), key, "aws", "us-east-1"), "sqs", "SendMessage"); err != nil {
			t.Fatal(err)
		}
	}
	if err := source.Advance(2 * time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := repository.Repository.Update(t.Context(), func(tx iam.WriteTx) error {
		if err := tx.DeleteCredential(missing.AccessKeyID); err != nil {
			return err
		}
		current, err := tx.Credential(expired.AccessKeyID)
		if err != nil {
			return err
		}
		current.Status = identity.Inactive
		if err := tx.PutCredential(current); err != nil {
			return err
		}
		if err := tx.DeleteRole(scope, stale.RoleName); err != nil {
			return err
		}
		replacement := stale
		replacement.RoleId = "AROANEW"
		return tx.PutRole(scope, replacement)
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.RecordActivity(activityContext(t.Context(), missing, "aws", "eu-west-1"), "kms", "Decrypt"); err != nil {
		t.Fatal(err)
	}
	if err := service.FlushActivity(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := repository.Repository.View(t.Context(), func(tx iam.ReadTx) error {
		role, err := tx.Role(scope, live.RoleName)
		if err != nil {
			return err
		}
		if !role.LastUsed.Date.Equal(source.Now()) || role.LastUsed.Region != "eu-west-1" {
			t.Fatalf("missing accepted session lost issuer use: %+v", role.LastUsed)
		}
		role, err = tx.Role(scope, stale.RoleName)
		if err != nil {
			return err
		}
		if !role.LastUsed.Date.IsZero() || role.LastUsed.Region != "" {
			t.Fatalf("recreated issuer inherited stale use: %+v", role.LastUsed)
		}
		_, err = tx.Credential(missing.AccessKeyID)
		if !errors.Is(err, identity.ErrNotFound) {
			t.Fatalf("reporting resurrected a deleted session: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if used := bufferedCredential(t, repository.Repository, expired.AccessKeyID).LastUsed; !used.Recorded() || !used.Date.IsZero() || used.Service != "sqs" || used.Region != "us-east-1" {
		t.Fatalf("flush reauthenticated accepted expired/inactive usage or lost zero time: %+v", used)
	}
	if rows := activityRows(t, repository.Repository, scope, stale.RoleId); len(rows) != 0 {
		t.Fatalf("stale issuer activity was resurrected: %+v", rows)
	}
	rows := activityRows(t, repository.Repository, scope, live.RoleId)
	if len(rows) != 2 {
		t.Fatalf("one stale observation poisoned the batch: %+v", rows)
	}
}

func TestAsyncActivityTemporaryCredentialSameInstantKeepsFirstCoherentUse(t *testing.T) {
	service, repository, _, key := bufferedActivityFixture(t, time.Time{})
	key.SessionType = identity.SessionTypeGetSessionToken
	key.SessionToken = "session"
	key.IssuerID, key.IssuerARN = key.PrincipalID, key.PrincipalARN
	if err := repository.Repository.Update(t.Context(), func(tx iam.WriteTx) error {
		return tx.PutCredential(identity.Record{Credential: key, Status: identity.Active})
	}); err != nil {
		t.Fatal(err)
	}
	for _, observation := range []struct{ service, region string }{{"sqs", "us-east-1"}, {"kms", "eu-west-1"}} {
		if err := service.RecordActivity(activityContext(t.Context(), key, "aws", observation.region), observation.service, "Attempt"); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.FlushActivity(t.Context()); err != nil {
		t.Fatal(err)
	}
	used := bufferedCredential(t, repository.Repository, key.AccessKeyID).LastUsed
	if !used.Recorded() || !used.Date.IsZero() || used.Service != "sqs" || used.Region != "us-east-1" {
		t.Fatalf("nested equal-time attempt replaced first temporary-credential use: %+v", used)
	}
	if rows := activityRows(t, repository.Repository, iam.Scope{Partition: "aws", AccountID: key.AccountID}, key.PrincipalID); len(rows) != 2 {
		t.Fatalf("credential coalescing lost per-service attempts: %+v", rows)
	}
}

func TestAsyncActivityConcurrentDrainCancellationAndOrdering(t *testing.T) {
	start := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	service, repository, source, key := bufferedActivityFixture(t, start)
	ctx := activityContext(t.Context(), key, "aws", "us-east-1")
	gate := &activityWriteGate{entered: make(chan struct{}, 1), release: make(chan struct{})}
	defer gate.unblock()
	repository.gate.Store(gate)
	if err := service.RecordActivity(ctx, "s3", "GetObject"); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { first <- service.FlushActivity(t.Context()) }()
	awaitActivitySignal(t, gate.entered)
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := service.RecordActivity(ctx, "s3", "GetObject"); err != nil {
		t.Fatal(err)
	}
	waitingContext, cancel := context.WithCancel(t.Context())
	defer cancel()
	second := make(chan error, 1)
	go func() { second <- service.FlushActivity(waitingContext) }()
	cancel()
	if err := awaitActivitySignal(t, second); !errors.Is(err, context.Canceled) {
		t.Fatalf("concurrent drain ignored cancellation while waiting for storage: %v", err)
	}
	repository.gate.Store(nil)
	gate.unblock()
	if err := awaitActivitySignal(t, first); err != nil {
		t.Fatal(err)
	}
	if err := service.FlushActivity(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows := activityRows(t, repository.Repository, iam.Scope{Partition: "aws", AccountID: key.AccountID}, key.PrincipalID)
	if len(rows) != 1 || !rows[0].LastAuthenticated.Equal(start.Add(time.Second)) {
		t.Fatalf("older in-flight snapshot overwrote newer enqueue: %+v", rows)
	}
	used := bufferedCredential(t, repository.Repository, key.AccessKeyID).LastUsed
	if !used.Date.Equal(start) || used.Service != "s3" || used.Region != "us-east-1" {
		t.Fatalf("concurrent drain replaced first credential observation: %+v", used)
	}
}

func TestAsyncActivityRenameBeforeFlushPreservesImmutableUserHistory(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, removeCredential := range []bool{false, true} {
				name := "credential retained"
				if removeCredential {
					name = "credential removed"
				}
				t.Run(name, func(t *testing.T) {
					start := time.Time{}
					service, repository, source, key := bufferedActivityFixtureOn(t, identitySnapshotRepository(t, backend), start)
					scope := iam.Scope{Partition: "aws", AccountID: key.AccountID}
					accepted := activityContext(t.Context(), key, "aws", "us-east-1")
					if err := service.RecordActivity(accepted, "s3", "GetObject"); err != nil {
						t.Fatal(err)
					}
					renamed := key
					renamed.UserName = "renamed"
					renamed.PrincipalARN = "arn:aws:iam::123456789012:user/new-path/renamed"
					if err := repository.Repository.Update(t.Context(), func(tx iam.WriteTx) error {
						if err := tx.DeleteUser(scope, key.UserName); err != nil {
							return err
						}
						if err := tx.PutUser(scope, iam.User{UserId: key.PrincipalID, UserName: renamed.UserName, Arn: renamed.PrincipalARN}); err != nil {
							return err
						}
						record, err := tx.Credential(key.AccessKeyID)
						if err != nil {
							return err
						}
						record.Credential = renamed
						return tx.PutCredential(record)
					}); err != nil {
						t.Fatal(err)
					}
					if err := source.Advance(16 * time.Minute); err != nil {
						t.Fatal(err)
					}
					if err := service.RecordActivity(activityContext(t.Context(), renamed, "aws", "eu-west-1"), "iam", "GetUser"); err != nil {
						t.Fatal(err)
					}
					if err := source.Advance(14 * time.Minute); err != nil {
						t.Fatal(err)
					}
					// A previously accepted job can still carry the historical
					// ARN. It belongs in the same ordered credential timeline.
					if err := service.RecordActivity(accepted, "kms", "Decrypt"); err != nil {
						t.Fatal(err)
					}
					if removeCredential {
						if err := repository.Repository.Update(t.Context(), func(tx iam.WriteTx) error { return tx.DeleteCredential(key.AccessKeyID) }); err != nil {
							t.Fatal(err)
						}
					}
					if err := service.FlushActivity(t.Context()); err != nil {
						t.Fatal(err)
					}
					rows := activityRows(t, repository.Repository, scope, key.PrincipalID)
					if len(rows) != 3 {
						t.Fatalf("rename or credential deletion lost buffered user history: %+v", rows)
					}
					for _, row := range rows {
						wantARN, wantTime := key.PrincipalARN, start
						switch row.ServiceNamespace {
						case "iam":
							wantARN, wantTime = renamed.PrincipalARN, start.Add(16*time.Minute)
						case "kms":
							wantTime = start.Add(30 * time.Minute)
						}
						if row.PrincipalARN != wantARN || !row.LastAuthenticated.Equal(wantTime) {
							t.Fatalf("rename rewrote captured identity/time: %+v", row)
						}
					}
					if !removeCredential {
						used := bufferedCredential(t, repository.Repository, key.AccessKeyID).LastUsed
						if !used.Date.Equal(start.Add(16*time.Minute)) || used.Service != "iam" || used.Region != "N/A" {
							t.Fatalf("rename split the credential's first-use window: %+v", used)
						}
					}
				})
			}
		})
	}
}
