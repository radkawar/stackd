package iam_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/clock"
	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
)

// The API exposes independent permissions for generation and download:
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html.
func TestCredentialReportAbsentAndIndependentPermissions(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	root := clientFor(t, service, "123456789012", "us-east-1")
	missing, err := root.GetCredentialReport(t.Context(), &sdkiam.GetCredentialReportInput{})
	requireCode(t, err, "ReportNotPresent")
	var notPresent *types.CredentialReportNotPresentException
	if !errors.As(err, &notPresent) || missing != nil {
		t.Fatalf("missing report result=%+v error=%v", missing, err)
	}
	requireCredentialReportHTTPStatus(t, err, http.StatusGone)
	created, err := root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("report-auditor"), Path: aws.String("/security/")})
	if err != nil {
		t.Fatal(err)
	}
	caller := clientForIAMPrincipal(t, service, created.User)
	put := func(document string) {
		t.Helper()
		_, err := root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: created.User.UserName, PolicyName: aws.String("Reports"), PolicyDocument: aws.String(document)})
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = caller.GetCredentialReport(t.Context(), &sdkiam.GetCredentialReportInput{})
	requireCode(t, err, "AccessDenied")
	_, err = caller.GenerateCredentialReport(t.Context(), &sdkiam.GenerateCredentialReportInput{})
	requireCode(t, err, "AccessDenied")
	put(`{"Statement":{"Effect":"Allow","Action":"iam:GetCredentialReport","Resource":"*"}}`)
	_, err = caller.GetCredentialReport(t.Context(), &sdkiam.GetCredentialReportInput{})
	requireCode(t, err, "ReportNotPresent")
	_, err = caller.GenerateCredentialReport(t.Context(), &sdkiam.GenerateCredentialReportInput{})
	requireCode(t, err, "AccessDenied")
	put(`{"Statement":{"Effect":"Allow","Action":["iam:GetCredentialReport","iam:GenerateCredentialReport"],"Resource":"` + aws.ToString(created.User.Arn) + `"}}`)
	_, err = caller.GetCredentialReport(t.Context(), &sdkiam.GetCredentialReportInput{})
	requireCode(t, err, "AccessDenied")
	_, err = caller.GenerateCredentialReport(t.Context(), &sdkiam.GenerateCredentialReportInput{})
	requireCode(t, err, "AccessDenied")
	// A generation grant does not allow downloading the resulting report.
	put(`{"Statement":{"Effect":"Allow","Action":"iam:GenerateCredentialReport","Resource":"*"}}`)
	generated, err := caller.GenerateCredentialReport(t.Context(), &sdkiam.GenerateCredentialReportInput{})
	if err != nil || generated.State != types.ReportStateTypeStarted {
		t.Fatalf("initial generation=%+v error=%v", generated, err)
	}
	_, err = caller.GetCredentialReport(t.Context(), &sdkiam.GetCredentialReportInput{})
	requireCode(t, err, "AccessDenied")
	put(`{"Statement":[{"Effect":"Allow","Action":["iam:GetCredentialReport","iam:GenerateCredentialReport"],"Resource":"*"},{"Effect":"Deny","Action":"iam:GetCredentialReport","Resource":"*"}]}`)
	_, err = caller.GetCredentialReport(t.Context(), &sdkiam.GetCredentialReportInput{})
	requireCode(t, err, "AccessDenied")
	boundary, err := root.CreatePolicy(t.Context(), &sdkiam.CreatePolicyInput{PolicyName: aws.String("NoReportsBoundary"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.PutUserPermissionsBoundary(t.Context(), &sdkiam.PutUserPermissionsBoundaryInput{UserName: created.User.UserName, PermissionsBoundary: boundary.Policy.Arn}); err != nil {
		t.Fatal(err)
	}
	_, err = caller.GenerateCredentialReport(t.Context(), &sdkiam.GenerateCredentialReportInput{})
	requireCode(t, err, "AccessDenied")
	if _, err := root.DeleteUserPermissionsBoundary(t.Context(), &sdkiam.DeleteUserPermissionsBoundaryInput{UserName: created.User.UserName}); err != nil {
		t.Fatal(err)
	}
	service.SetAuthorizer(authorization.New(service, credentialReportDenyControls{}))
	for _, principal := range []*sdkiam.Client{caller, root} {
		output, err := principal.GetCredentialReport(t.Context(), &sdkiam.GetCredentialReportInput{})
		requireCode(t, err, "AccessDenied")
		if output != nil {
			t.Fatal("SCP-denied report exposed output")
		}
		_, err = principal.GenerateCredentialReport(t.Context(), &sdkiam.GenerateCredentialReportInput{})
		requireCode(t, err, "AccessDenied")
	}
}

func requireCredentialReportHTTPStatus(t *testing.T, err error, expected int) {
	t.Helper()
	var response interface{ HTTPStatusCode() int }
	if !errors.As(err, &response) || response.HTTPStatusCode() != expected {
		t.Fatalf("HTTP error=%v; want status %d", err, expected)
	}
}

type credentialReportDenyControls struct{}

func (credentialReportDenyControls) ServiceControlPolicies(context.Context) ([]iampolicy.PolicyLevel, error) {
	return []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":["iam:GetCredentialReport","iam:GenerateCredentialReport"],"Resource":"*"}]}`}}}}, nil
}

type credentialReportCommit struct {
	scope  iam.Scope
	record iam.CredentialReportRecord
}

// The decorator observes actual committed report records. Blocking background
// updates before storage acquisition keeps SDK reads available while a real job
// waits; it does not substitute fake output or a modeled generation delay.
type credentialReportTestRepository struct {
	iam.Repository
	blockBackground   atomic.Bool
	backgroundEntered chan struct{}
	backgroundRelease chan struct{}
	releaseOnce       sync.Once
	committed         chan credentialReportCommit
	attempts          chan credentialReportCommit
	rolledBack        chan credentialReportCommit
	failPending       atomic.Bool
	failTerminal      atomic.Bool
	blockTerminal     atomic.Bool
	terminalEntered   chan struct{}
	terminalRelease   chan struct{}
	cancelMu          sync.Mutex
	cancelPending     context.CancelFunc
}

func newCredentialReportTestRepository(base iam.Repository, blocked bool) *credentialReportTestRepository {
	if base == nil {
		base = iam.NewMemoryRepository(nil)
	}
	r := &credentialReportTestRepository{Repository: base, backgroundEntered: make(chan struct{}, 1), backgroundRelease: make(chan struct{}), committed: make(chan credentialReportCommit, 128), attempts: make(chan credentialReportCommit, 128), rolledBack: make(chan credentialReportCommit, 128), terminalEntered: make(chan struct{}, 1), terminalRelease: make(chan struct{})}
	r.blockBackground.Store(blocked)
	return r
}

func (r *credentialReportTestRepository) release() {
	r.releaseOnce.Do(func() { close(r.backgroundRelease) })
}

func (r *credentialReportTestRepository) Update(ctx context.Context, fn func(iam.WriteTx) error) error {
	if r.blockBackground.Load() && awsctx.FromContext(ctx).RequestID != "iam-sdk-test" {
		select {
		case r.backgroundEntered <- struct{}{}:
		default:
		}
		select {
		case <-r.backgroundRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	var writes []credentialReportCommit
	err := r.Repository.Update(ctx, func(tx iam.WriteTx) error {
		if err := fn(credentialReportTestTx{WriteTx: tx, owner: r, writes: &writes}); err != nil {
			return err
		}
		for _, write := range writes {
			if write.record.State == iam.CredentialReportPending {
				if r.failPending.CompareAndSwap(true, false) {
					return errors.New("injected report intent commit failure")
				}
				r.cancelMu.Lock()
				cancel := r.cancelPending
				r.cancelPending = nil
				r.cancelMu.Unlock()
				if cancel != nil {
					cancel()
					// The HTTP transport propagates client cancellation to the
					// server asynchronously. Hold the transaction until its own
					// request context observes that cancellation.
					<-ctx.Done()
					return ctx.Err()
				}
			}
			if write.record.State == iam.CredentialReportComplete {
				if r.blockTerminal.Load() {
					select {
					case r.terminalEntered <- struct{}{}:
					default:
					}
					select {
					case <-r.terminalRelease:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				if r.failTerminal.Load() {
					return errors.New("injected report completion commit failure")
				}
			}
		}
		return nil
	})
	if err == nil {
		for _, write := range writes {
			r.committed <- write
		}
	} else {
		for _, write := range writes {
			r.rolledBack <- write
		}
	}
	return err
}

type credentialReportTestTx struct {
	iam.WriteTx
	owner  *credentialReportTestRepository
	writes *[]credentialReportCommit
}

func (tx credentialReportTestTx) PutCredentialReport(scope iam.Scope, record iam.CredentialReportRecord) error {
	if err := tx.WriteTx.PutCredentialReport(scope, record); err != nil {
		return err
	}
	record.Content = slices.Clone(record.Content)
	write := credentialReportCommit{scope, record}
	*tx.writes = append(*tx.writes, write)
	tx.owner.attempts <- write
	return nil
}

func waitCredentialReportCommit(t *testing.T, ctx context.Context, repository *credentialReportTestRepository, scope iam.Scope, generation uint64) iam.CredentialReportRecord {
	t.Helper()
	for {
		select {
		case event := <-repository.committed:
			if event.scope == scope && event.record.Generation == generation && event.record.State == iam.CredentialReportComplete {
				return event.record
			}
		case <-ctx.Done():
			t.Fatalf("report generation %d did not commit: %v", generation, ctx.Err())
			return iam.CredentialReportRecord{}
		}
	}
}

func storedCredentialReport(t *testing.T, repository iam.Repository, scope iam.Scope) iam.CredentialReportRecord {
	t.Helper()
	var record iam.CredentialReportRecord
	if err := repository.View(t.Context(), func(tx iam.ReadTx) error { var err error; record, err = tx.CredentialReport(scope); return err }); err != nil {
		t.Fatal(err)
	}
	return record
}

func credentialReportRows(t *testing.T, content []byte) map[string]map[string]string {
	t.Helper()
	rows, err := csv.NewReader(bytes.NewReader(content)).ReadAll()
	if err != nil || len(rows) < 2 {
		t.Fatalf("invalid credential CSV: rows=%d error=%v", len(rows), err)
	}
	result := make(map[string]map[string]string)
	for _, fields := range rows[1:] {
		row := make(map[string]string)
		for index, name := range rows[0] {
			row[name] = fields[index]
		}
		if _, duplicate := result[row["arn"]]; duplicate {
			t.Fatalf("duplicate report ARN %q", row["arn"])
		}
		result[row["arn"]] = row
	}
	return result
}

func TestCredentialReportCommittedSnapshotCacheAndReconstruction(t *testing.T) {
	for _, epoch := range []time.Time{{}, time.Date(2035, 2, 3, 4, 5, 6, 0, time.UTC)} {
		t.Run(epoch.Format(time.RFC3339), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			source := clock.NewManual(epoch)
			repository := newCredentialReportTestRepository(nil, true)
			service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: source})
			t.Cleanup(func() { repository.release(); _ = service.Close() })
			client := clientFor(t, service, scope.AccountID, "us-east-1")
			user, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("before")})
			if err != nil {
				t.Fatal(err)
			}
			key, err := client.CreateAccessKey(ctx, &sdkiam.CreateAccessKeyInput{UserName: user.User.UserName})
			if err != nil {
				t.Fatal(err)
			}
			if err := source.Advance(time.Minute); err != nil {
				t.Fatal(err)
			}
			requestedAt := source.Now()
			started, err := client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{})
			if err != nil || started.State != types.ReportStateTypeStarted {
				t.Fatalf("generation=%+v error=%v", started, err)
			}
			pending := storedCredentialReport(t, repository, scope)
			if pending.State != iam.CredentialReportPending || pending.Generation != 1 || !pending.RequestedAt.Equal(requestedAt) || len(pending.Content) != 0 {
				t.Fatalf("stored generation intent=%+v", pending)
			}
			_, err = client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
			requireCode(t, err, "ReportInProgress")
			var notReady *types.CredentialReportNotReadyException
			if !errors.As(err, &notReady) {
				t.Fatalf("missing typed report-not-ready error: %v", err)
			}
			requireCredentialReportHTTPStatus(t, err, http.StatusNotFound)
			inProgress, err := client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{})
			if err != nil || inProgress.State != types.ReportStateTypeInprogress {
				t.Fatalf("pending generation=%+v error=%v", inProgress, err)
			}
			if _, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("before-worker-snapshot")}); err != nil {
				t.Fatal(err)
			}
			if err := source.Advance(time.Minute); err != nil {
				t.Fatal(err)
			}
			generatedAt := source.Now()
			repository.release()
			completed := waitCredentialReportCommit(t, ctx, repository, scope, pending.Generation)
			if !completed.GeneratedAt.Equal(generatedAt) {
				t.Fatalf("worker generation time=%v; want %v", completed.GeneratedAt, generatedAt)
			}
			original, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
			if err != nil {
				t.Fatal(err)
			}
			if original.ReportFormat != types.ReportFormatTypeTextCsv || original.GeneratedTime == nil || !original.GeneratedTime.Equal(generatedAt) || !bytes.Equal(original.Content, completed.Content) {
				t.Fatalf("generated response metadata/content=%+v", original)
			}
			rows := credentialReportRows(t, original.Content)
			rootARN := "arn:aws:iam::" + scope.AccountID + ":root"
			rootCreated, err := time.Parse(time.RFC3339, rows[rootARN]["user_creation_time"])
			if err != nil || !rootCreated.Equal(epoch) {
				t.Fatalf("root creation changed to report time: %q %v", rows[rootARN]["user_creation_time"], err)
			}
			if rows["arn:aws:iam::123456789012:user/before-worker-snapshot"] == nil || !strings.EqualFold(rows[aws.ToString(user.User.Arn)]["access_key_1_active"], "true") {
				t.Fatal("worker did not capture current IAM credentials in its own snapshot")
			}
			if _, err := client.UpdateAccessKey(ctx, &sdkiam.UpdateAccessKeyInput{UserName: user.User.UserName, AccessKeyId: key.AccessKey.AccessKeyId, Status: types.StatusTypeInactive}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.UpdateUser(ctx, &sdkiam.UpdateUserInput{UserName: user.User.UserName, NewUserName: aws.String("after")}); err != nil {
				t.Fatal(err)
			}
			if err := source.Advance(4*time.Hour - time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			cached, err := client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{})
			if err != nil || cached.State != types.ReportStateTypeComplete {
				t.Fatalf("fresh cached generation=%+v error=%v", cached, err)
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			reconstructed := iam.NewWithConfig(iam.Config{Repository: repository, Clock: source})
			t.Cleanup(func() { _ = reconstructed.Close() })
			client = clientFor(t, reconstructed, scope.AccountID, "eu-west-2")
			read, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
			if err != nil || !bytes.Equal(read.Content, original.Content) || !read.GeneratedTime.Equal(*original.GeneratedTime) {
				t.Fatalf("cached report changed across mutation/reconstruction: %+v %v", read, err)
			}
			if storedCredentialReport(t, repository, scope).Generation != pending.Generation {
				t.Fatal("cached generation replaced the persisted report")
			}
			if err := source.Advance(time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			// The four-hour expiry edge is inferred from the linked API/guide
			// contract; the live fixture covers only cache reuse within it.
			atBoundary, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
			if err != nil || !bytes.Equal(atBoundary.Content, original.Content) {
				t.Fatalf("report expired at the inclusive cache boundary: %+v %v", atBoundary, err)
			}
			cached, err = client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{})
			if err != nil || cached.State != types.ReportStateTypeComplete {
				t.Fatalf("four-hour cache generation=%+v error=%v", cached, err)
			}
			if err := source.Advance(time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			expired, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
			requireCode(t, err, "ReportExpired")
			var expiredReport *types.CredentialReportExpiredException
			if !errors.As(err, &expiredReport) || expired != nil {
				t.Fatalf("expired report exposed output or lost typed error: %+v %v", expired, err)
			}
			requireCredentialReportHTTPStatus(t, err, http.StatusGone)
			next, err := client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{})
			if err != nil || next.State != types.ReportStateTypeStarted {
				t.Fatalf("old report did not start regeneration: %+v %v", next, err)
			}
			waitCredentialReportCommit(t, ctx, repository, scope, pending.Generation+1)
			fresh, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(fresh.Content, original.Content) || !fresh.GeneratedTime.After(*original.GeneratedTime) {
				t.Fatal("regenerated report retained the old snapshot")
			}
			freshRows := credentialReportRows(t, fresh.Content)
			if freshRows[aws.ToString(user.User.Arn)] != nil || !strings.EqualFold(freshRows["arn:aws:iam::123456789012:user/after"]["access_key_1_active"], "false") || freshRows[rootARN]["user_creation_time"] != rows[rootARN]["user_creation_time"] {
				t.Fatal("regenerated report lost rename/inactive-key/root-creation state")
			}
		})
	}
}

func TestCredentialReportConcurrentGenerateSharesOneJob(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	repository := newCredentialReportTestRepository(nil, true)
	service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: clock.NewManual(time.Time{})})
	t.Cleanup(func() { repository.release(); _ = service.Close() })
	client := clientFor(t, service, scope.AccountID, "us-east-1")
	type result struct {
		state types.ReportStateType
		err   error
	}
	results := make(chan result, 16)
	var requests sync.WaitGroup
	for range cap(results) {
		requests.Go(func() {
			out, err := client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{})
			if err != nil {
				results <- result{err: err}
				return
			}
			results <- result{state: out.State}
		})
	}
	requests.Wait()
	close(results)
	states := make(map[types.ReportStateType]int)
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		states[result.state]++
	}
	if states[types.ReportStateTypeStarted] != 1 || states[types.ReportStateTypeInprogress] != 15 || len(states) != 2 {
		t.Fatalf("concurrent generation states=%v", states)
	}
	pending := storedCredentialReport(t, repository, scope)
	if pending.Generation != 1 || pending.State != iam.CredentialReportPending || !pending.RequestedAt.IsZero() || len(pending.Content) != 0 {
		t.Fatalf("concurrent intent=%+v", pending)
	}
	repository.release()
	completed := waitCredentialReportCommit(t, ctx, repository, scope, pending.Generation)
	if !completed.GeneratedAt.IsZero() || len(completed.Content) == 0 {
		t.Fatalf("zero-epoch generation was lost: %+v", completed)
	}
	get, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
	if err != nil || get.GeneratedTime == nil || !get.GeneratedTime.IsZero() || !bytes.Equal(get.Content, completed.Content) {
		t.Fatalf("zero-epoch report=%+v error=%v", get, err)
	}
	if storedCredentialReport(t, repository, scope).Generation != pending.Generation {
		t.Fatal("concurrent requests issued multiple report generations")
	}
}

func TestCredentialReportGenerationIntentRollbackAndCancellation(t *testing.T) {
	for _, scenario := range []string{"failed commit", "canceled request"} {
		t.Run(scenario, func(t *testing.T) {
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			repository := newCredentialReportTestRepository(nil, true)
			service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: clock.NewManual(time.Time{})})
			t.Cleanup(func() { repository.release(); _ = service.Close() })
			client := clientFor(t, service, scope.AccountID, "us-east-1")
			requestContext, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario == "failed commit" {
				repository.failPending.Store(true)
			} else {
				repository.cancelMu.Lock()
				repository.cancelPending = cancel
				repository.cancelMu.Unlock()
			}
			out, err := client.GenerateCredentialReport(requestContext, &sdkiam.GenerateCredentialReportInput{})
			if scenario == "failed commit" {
				requireCode(t, err, "ServiceFailure")
			} else if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled request error=%v", err)
			}
			if out != nil {
				t.Fatalf("failed generation returned success: %+v", out)
			}
			if err := repository.View(t.Context(), func(tx iam.ReadTx) error {
				_, err := tx.CredentialReport(scope)
				if !errors.Is(err, iam.ErrRecordNotFound) {
					t.Fatalf("failed intent remained stored: %v", err)
				}
				_, err = tx.AccountMetadata(scope)
				if !errors.Is(err, iam.ErrRecordNotFound) {
					t.Fatalf("failed request provisioned account metadata: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if repository.failPending.Load() {
				t.Fatal("failure injection did not reach the report transaction")
			}
			_, err = client.GetCredentialReport(t.Context(), &sdkiam.GetCredentialReportInput{})
			requireCode(t, err, "ReportNotPresent")
			retried, err := client.GenerateCredentialReport(t.Context(), &sdkiam.GenerateCredentialReportInput{})
			if err != nil || retried.State != types.ReportStateTypeStarted {
				t.Fatalf("retry=%+v error=%v", retried, err)
			}
			if record := storedCredentialReport(t, repository, scope); record.Generation != 1 {
				t.Fatalf("rolled-back intent consumed generation: %+v", record)
			}
			repository.release()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			waitCredentialReportCommit(t, ctx, repository, scope, 1)
		})
	}
}

func TestCredentialReportPendingAndTerminalRollbackRecoverAfterClose(t *testing.T) {
	for _, scenario := range []string{"pending at shutdown", "canceled terminal commit", "failed terminal commit"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			source := clock.NewManual(time.Time{})
			repository := newCredentialReportTestRepository(nil, scenario == "pending at shutdown")
			repository.blockTerminal.Store(scenario == "canceled terminal commit")
			repository.failTerminal.Store(scenario == "failed terminal commit")
			service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: source})
			t.Cleanup(func() { repository.release(); _ = service.Close() })
			client := clientFor(t, service, scope.AccountID, "us-east-1")
			started, err := client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{})
			if err != nil || started.State != types.ReportStateTypeStarted {
				t.Fatalf("generation=%+v error=%v", started, err)
			}
			switch scenario {
			case "pending at shutdown":
				select {
				case <-repository.backgroundEntered:
				case <-ctx.Done():
					t.Fatal("worker never attempted the persisted job")
				}
			case "canceled terminal commit":
				select {
				case <-repository.terminalEntered:
				case <-ctx.Done():
					t.Fatal("worker never reached the terminal transaction")
				}
			case "failed terminal commit":
				select {
				case rollback := <-repository.rolledBack:
					if rollback.record.State != iam.CredentialReportComplete || len(rollback.record.Content) == 0 {
						t.Fatalf("failure did not exercise a completed CSV transaction: %+v", rollback)
					}
				case <-ctx.Done():
					t.Fatal("worker never attempted the terminal commit")
				}
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			retained := storedCredentialReport(t, repository, scope)
			if retained.State != iam.CredentialReportPending || retained.Generation != 1 || len(retained.Content) != 0 || !retained.GeneratedAt.IsZero() {
				t.Fatalf("interrupted job published a terminal snapshot: %+v", retained)
			}
			recoveredRepository := newCredentialReportTestRepository(repository.Repository, false)
			recovered := iam.NewWithConfig(iam.Config{Repository: recoveredRepository, Clock: source})
			t.Cleanup(func() { _ = recovered.Close() })
			client = clientFor(t, recovered, scope.AccountID, "eu-west-2")
			partial, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
			requireCode(t, err, "ReportInProgress")
			if partial != nil {
				t.Fatal("interrupted report exposed partial CSV")
			}
			if err := source.Advance(time.Minute); err != nil {
				t.Fatal(err)
			}
			recovered.StartWorkers()
			completed := waitCredentialReportCommit(t, ctx, recoveredRepository, scope, retained.Generation)
			if !completed.GeneratedAt.Equal(source.Now()) || !completed.RequestedAt.Equal(retained.RequestedAt) {
				t.Fatalf("recovery replaced the intent or used its old snapshot time: %+v", completed)
			}
			output, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
			if err != nil || !bytes.Equal(output.Content, completed.Content) {
				t.Fatalf("recovered report=%+v error=%v", output, err)
			}
		})
	}
}

func TestCredentialReportRecoveryRespectsFutureDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	source := clock.NewManual(time.Time{})
	repository := newCredentialReportTestRepository(nil, false)
	due := source.Now().Add(time.Hour)
	if err := repository.Repository.Update(ctx, func(tx iam.WriteTx) error {
		if err := tx.PutAccountMetadata(scope, iam.AccountMetadata{CreatedAt: source.Now()}); err != nil {
			return err
		}
		return tx.PutCredentialReport(scope, iam.CredentialReportRecord{Generation: 9, State: iam.CredentialReportPending, RequestedAt: due})
	}); err != nil {
		t.Fatal(err)
	}
	service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: source})
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, scope.AccountID, "us-east-1")
	for _, advance := range []time.Duration{0, time.Hour - time.Nanosecond} {
		if err := source.Advance(advance); err != nil {
			t.Fatal(err)
		}
		drained, err := service.RunDueJobs(ctx, 1)
		if err != nil || drained.Processed != 0 || drained.More || drained.Next == nil || !drained.Next.Equal(due) {
			t.Fatalf("future work was drained early: %+v error=%v", drained, err)
		}
		_, err = client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
		requireCode(t, err, "ReportInProgress")
	}
	if err := source.Advance(time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	drained, err := service.RunDueJobs(ctx, 1)
	if err != nil || drained.Processed != 1 || drained.More || drained.Next != nil {
		t.Fatalf("due report was not drained: %+v error=%v", drained, err)
	}
	completed := waitCredentialReportCommit(t, ctx, repository, scope, 9)
	if !completed.GeneratedAt.Equal(due) {
		t.Fatalf("future recovered report generated at %v; want %v", completed.GeneratedAt, due)
	}
	result, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
	if err != nil || !result.GeneratedTime.Equal(due) {
		t.Fatalf("future recovered SDK result=%+v error=%v", result, err)
	}
}

func TestCredentialReportSelectedJobCannotPublishOverReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	source := clock.NewManual(time.Time{})
	repository := newCredentialReportTestRepository(nil, true)
	service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: source})
	t.Cleanup(func() { repository.release(); _ = service.Close() })
	client := clientFor(t, service, scope.AccountID, "us-east-1")
	if _, err := client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-repository.backgroundEntered:
	case <-ctx.Done():
		t.Fatal("worker did not select generation one")
	}
	// Replace a selected persisted intent before its worker acquires the
	// transaction, as can happen when recovering/importing durable job state.
	due := source.Now().Add(time.Hour)
	if err := repository.Repository.Update(ctx, func(tx iam.WriteTx) error {
		return tx.PutCredentialReport(scope, iam.CredentialReportRecord{Generation: 2, State: iam.CredentialReportPending, RequestedAt: due})
	}); err != nil {
		t.Fatal(err)
	}
	repository.release()
	drained, err := service.RunDueJobs(ctx, 1)
	if err != nil || drained.Next == nil || !drained.Next.Equal(due) {
		t.Fatalf("replacement deadline was lost after stale selection: %+v %v", drained, err)
	}
	retained := storedCredentialReport(t, repository, scope)
	if retained.Generation != 2 || retained.State != iam.CredentialReportPending || len(retained.Content) != 0 || !retained.RequestedAt.Equal(due) {
		t.Fatalf("stale worker replaced current intent: %+v", retained)
	}
	if err := source.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RunDueJobs(ctx, 1); err != nil {
		t.Fatal(err)
	}
	completed := waitCredentialReportCommit(t, ctx, repository, scope, 2)
	if !completed.GeneratedAt.Equal(due) {
		t.Fatalf("replacement generation used stale snapshot time: %+v", completed)
	}
}

func TestCredentialReportFutureGeneratedTimeAndFailedState(t *testing.T) {
	for _, state := range []iam.CredentialReportState{iam.CredentialReportComplete, iam.CredentialReportFailed} {
		t.Run(string(state), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			source := clock.NewManual(time.Time{})
			repository := newCredentialReportTestRepository(nil, true)
			generatedAt := source.Now().Add(time.Hour)
			content := []byte("user,arn\n<root_account>,arn:aws:iam::123456789012:root")
			if err := repository.Repository.Update(ctx, func(tx iam.WriteTx) error {
				if err := tx.PutAccountMetadata(scope, iam.AccountMetadata{CreatedAt: source.Now()}); err != nil {
					return err
				}
				return tx.PutCredentialReport(scope, iam.CredentialReportRecord{Generation: 7, State: state, RequestedAt: source.Now(), GeneratedAt: generatedAt, Content: content})
			}); err != nil {
				t.Fatal(err)
			}
			service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: source})
			t.Cleanup(func() { repository.release(); _ = service.Close() })
			client := clientFor(t, service, scope.AccountID, "us-east-1")
			if state == iam.CredentialReportFailed {
				result, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
				requireCode(t, err, "ServiceFailure")
				if result != nil {
					t.Fatal("failed generation exposed retained content")
				}
			} else {
				for _, advance := range []time.Duration{0, 4 * time.Hour, time.Hour} {
					if err := source.Advance(advance); err != nil {
						t.Fatal(err)
					}
					result, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
					if err != nil || !result.GeneratedTime.Equal(generatedAt) || !bytes.Equal(result.Content, content) {
						t.Fatalf("future report was expired relative to request/account time: %+v %v", result, err)
					}
					generated, err := client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{})
					if err != nil || generated.State != types.ReportStateTypeComplete {
						t.Fatalf("future cache=%+v error=%v", generated, err)
					}
				}
				if err := source.Advance(time.Nanosecond); err != nil {
					t.Fatal(err)
				}
				_, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
				requireCode(t, err, "ReportExpired")
			}
			retried, err := client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{})
			if err != nil || retried.State != types.ReportStateTypeStarted {
				t.Fatalf("retry generation=%+v error=%v", retried, err)
			}
			pending := storedCredentialReport(t, repository, scope)
			if pending.Generation != 8 || len(pending.Content) != 0 || !pending.GeneratedAt.IsZero() {
				t.Fatalf("retry did not clear previous state: %+v", pending)
			}
			repository.release()
			waitCredentialReportCommit(t, ctx, repository, scope, 8)
		})
	}
}

func TestCredentialReportAccountAndPartitionIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	repository := newCredentialReportTestRepository(nil, true)
	service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: clock.NewManual(time.Time{})})
	t.Cleanup(func() { repository.release(); _ = service.Close() })
	scopes := []iam.Scope{{Partition: "aws", AccountID: "111111111111"}, {Partition: "aws", AccountID: "222222222222"}, {Partition: "aws-cn", AccountID: "111111111111"}}
	clients := make(map[iam.Scope]*sdkiam.Client)
	for _, scope := range scopes {
		client := clientForPartition(t, service, scope.AccountID, "us-east-1", scope.Partition)
		clients[scope] = client
		_, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
		requireCode(t, err, "ReportNotPresent")
		if _, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("private-" + scope.Partition + "-" + scope.AccountID)}); err != nil {
			t.Fatal(err)
		}
		started, err := client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{})
		if err != nil || started.State != types.ReportStateTypeStarted {
			t.Fatalf("scope %+v generation=%+v error=%v", scope, started, err)
		}
	}
	repository.release()
	completed := make(map[iam.Scope]iam.CredentialReportRecord)
	for len(completed) != len(scopes) {
		select {
		case event := <-repository.committed:
			if event.record.State == iam.CredentialReportComplete {
				completed[event.scope] = event.record
			}
		case <-ctx.Done():
			t.Fatalf("only %d/%d scoped reports committed", len(completed), len(scopes))
		}
	}
	for _, scope := range scopes {
		get, err := clients[scope].GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
		if err != nil || !bytes.Equal(get.Content, completed[scope].Content) {
			t.Fatalf("scope %+v result=%+v error=%v", scope, get, err)
		}
		rows := credentialReportRows(t, get.Content)
		prefix := "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":"
		if len(rows) != 2 || rows[prefix+"root"] == nil || rows[prefix+"user/private-"+scope.Partition+"-"+scope.AccountID] == nil {
			t.Fatalf("report leaked or omitted scoped identities: scope=%+v rows=%v", scope, rows)
		}
		get.Content[0] = '?'
		detached := storedCredentialReport(t, repository, scope)
		detached.Content[0] = '!'
		fresh, err := clients[scope].GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
		if err != nil || !bytes.Equal(fresh.Content, completed[scope].Content) {
			t.Fatal("caller-owned report bytes mutated persisted state")
		}
	}
}
