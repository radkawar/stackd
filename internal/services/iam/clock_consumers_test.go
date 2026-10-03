package iam

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsctx"
)

type clockWaitingRepository struct {
	Repository
	updateEntered chan struct{}
	wait          atomic.Bool
}

func (r *clockWaitingRepository) Update(ctx context.Context, fn func(WriteTx) error) error {
	if r.wait.CompareAndSwap(true, false) {
		close(r.updateEntered)
	}
	return r.Repository.Update(ctx, fn)
}

func TestIAMClockMFACapturesAfterLockAcquisition(t *testing.T) {
	epoch := time.Date(2035, 2, 3, 4, 5, 0, 0, time.UTC)
	source := clock.NewManual(epoch)
	repository := &clockWaitingRepository{Repository: NewMemoryRepository(nil), updateEntered: make(chan struct{})}
	scope := Scope{Partition: "aws", AccountID: "123456789012"}
	user := User{UserId: "AIDACLOCK", UserName: "clock", Arn: "arn:aws:iam::123456789012:user/clock"}
	device := MFADevice{SerialNumber: "arn:aws:iam::123456789012:mfa/clock", Binding: Propagated[MFABinding]{Value: MFABinding{UserID: user.UserId, Seed: "12345678901234567890"}, VisibleValue: MFABinding{UserID: user.UserId, Seed: "12345678901234567890"}}}
	if err := repository.Update(t.Context(), func(tx WriteTx) error {
		if err := tx.PutUser(scope, user); err != nil {
			return err
		}
		return tx.PutMFADevice(scope, device)
	}); err != nil {
		t.Fatal(err)
	}
	s := NewWithConfig(Config{Repository: repository, Clock: source})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, PrincipalARN: user.Arn, PrincipalID: user.UserId})
	held, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- repository.Update(ctx, func(WriteTx) error {
			close(held)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-held:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	repository.wait.Store(true)
	verified := make(chan error, 1)
	later := epoch.Add(5 * time.Minute)
	go func() {
		at, err := s.VerifyMFA(ctx, device.SerialNumber, totp([]byte(device.Binding.Value.Seed), later.Unix()/30))
		if err == nil && !at.Equal(later) {
			err = errors.New("MFA timestamp was captured before lock acquisition")
		}
		verified <- err
	}()
	select {
	case <-repository.updateEntered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := source.Advance(5 * time.Minute); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-verified:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := s.VerifyMFA(ctx, device.SerialNumber, totp([]byte(device.Binding.Value.Seed), epoch.Unix()/30)); err == nil {
		t.Fatal("old MFA code ignored manual advance")
	}
}

func TestIAMClockOIDCCacheUsesServiceTimeAndTLSUsesWallTime(t *testing.T) {
	epoch := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	source := clock.NewManual(epoch)
	var server *httptest.Server
	var noCache atomic.Bool
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Cache-Control", "max-age=120")
			_, _ = io.WriteString(w, `{"issuer":"`+server.URL+`","jwks_uri":"`+server.URL+`/keys"}`)
			return
		}
		w.Header().Set("Cache-Control", "max-age=30")
		if noCache.Load() {
			w.Header().Set("Cache-Control", "max-age=30,no-cache")
		}
		_, _ = io.WriteString(w, `{"keys":[{"kid":"one","kty":"RSA","n":"AQAB","e":"AQAB"}]}`)
	}))
	defer server.Close()
	discovery, err := NewHTTPOIDCDiscoveryWithClock(server.Client().Transport.(*http.Transport), source)
	if err != nil {
		t.Fatal(err)
	}
	first, err := discovery.Discover(t.Context(), OIDCDiscoveryRequest{IssuerURL: server.URL})
	if err != nil {
		t.Fatal("service epoch incorrectly changed external TLS validity", err)
	}
	if !first.CacheUntil.Equal(epoch.Add(30 * time.Second)) {
		t.Fatal("HTTP cache did not use service epoch", first.CacheUntil)
	}
	if err := source.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	noCache.Store(true)
	next, err := discovery.Discover(t.Context(), OIDCDiscoveryRequest{IssuerURL: server.URL})
	if err != nil || !next.CacheUntil.Equal(source.Now()) {
		t.Fatal("no-cache expiry did not use current service time", err)
	}
}

type clockRecoveryRepository struct {
	Repository
	fail      atomic.Bool
	failed    chan struct{}
	committed chan struct{}
}

func (r *clockRecoveryRepository) Update(ctx context.Context, fn func(WriteTx) error) error {
	if r.fail.CompareAndSwap(true, false) {
		close(r.failed)
		return errors.New("retry storage failure")
	}
	err := r.Repository.Update(ctx, fn)
	if err == nil {
		select {
		case r.committed <- struct{}{}:
		default:
		}
	}
	return err
}

func TestIAMClockServiceLinkedRetryAndTimerCleanup(t *testing.T) {
	epoch := time.Date(2035, 2, 3, 4, 5, 0, 0, time.UTC)
	source := clock.NewManual(epoch)
	repository := &clockRecoveryRepository{Repository: NewMemoryRepository(nil), failed: make(chan struct{}), committed: make(chan struct{}, 10)}
	scope, _, job := seedLinkedJob(t, repository.Repository, serviceLinkedNotStarted)
	s := NewWithConfig(Config{Repository: repository, Clock: source})
	t.Cleanup(func() { _ = s.Close() })
	repository.fail.Store(true)
	s.StartWorkers()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	select {
	case <-repository.failed:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := source.WaitForTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(time.Second - time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if got := readLinkedJob(t, repository.Repository, scope, job.ID); got.Status != serviceLinkedNotStarted {
		t.Fatal("worker retried before scheduled deadline")
	}
	if err := source.Advance(time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case <-repository.committed:
		case <-ctx.Done():
			t.Fatal("manual retry did not complete", ctx.Err())
		}
		got := readLinkedJob(t, repository.Repository, scope, job.ID)
		if got.Status == serviceLinkedSucceeded {
			if !got.UpdatedAt.Equal(epoch.Add(time.Second)) {
				t.Fatal("worker job timestamp ignored service clock")
			}
			break
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if source.Pending() != 0 {
		t.Fatal("IAM Close leaked a service timer")
	}
	if err := source.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := readLinkedJob(t, repository.Repository, scope, job.ID); !got.UpdatedAt.Equal(epoch.Add(time.Second)) {
		t.Fatal("closed worker mutated job")
	}
}
