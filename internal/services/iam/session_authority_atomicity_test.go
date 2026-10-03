package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/internal/identity"
)

func TestIAMSessionAuthorityRollbackAndCancellation(t *testing.T) {
	failure := errors.New("injected issuance failure")
	for _, scenario := range []string{"callback", "canceled-callback", "commit", "canceled-before-commit", "pre-canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newSessionAuthorityFixture(t, "aws", time.Time{})
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			want := failure
			if scenario == "pre-canceled" {
				cancel()
			}
			if scenario == "commit" {
				f.repository.beforeCommit = func() error { return failure }
			}
			if scenario == "canceled-before-commit" {
				f.repository.beforeCommit = func() error { cancel(); return nil }
			}
			if scenario == "pre-canceled" || scenario == "canceled-callback" || scenario == "canceled-before-commit" {
				want = context.Canceled
			}
			var callbackCtx context.Context
			var issued identity.Credential
			calls := 0
			err := f.service.WithSession(ctx, func(ctx context.Context, repository identity.Repository, now time.Time) error {
				calls++
				callbackCtx = ctx
				var err error
				issued, err = f.store.WithRepositoryAt(repository, now).IssueSession(ctx, f.parent, identity.SessionSpec{Duration: time.Hour})
				if err != nil {
					return err
				}
				switch scenario {
				case "callback":
					return failure
				case "canceled-callback":
					cancel()
				}
				return nil
			})
			if !errors.Is(err, want) {
				t.Fatalf("error=%v; want %v", err, want)
			}
			wantCalls := 1
			if scenario == "pre-canceled" {
				wantCalls = 0
			}
			if calls != wantCalls || int(f.source.reads.Load()) != wantCalls {
				t.Fatal("failed authority ran callback or clock the wrong number of times")
			}
			if callbackCtx != nil && !errors.Is(callbackCtx.Err(), context.Canceled) {
				t.Fatal("failed authority left callback context live")
			}
			if err := f.repository.View(f.ctx, func(tx ReadTx) error {
				if issued.AccessKeyID != "" {
					if _, err := tx.Credential(issued.AccessKeyID); !errors.Is(err, identity.ErrNotFound) {
						t.Fatalf("failed session was persisted: %v", err)
					}
				}
				rows, err := tx.PrincipalCredentials(f.scope.AccountID, f.parent.PrincipalID)
				if err == nil && len(rows) != 1 {
					t.Fatal("failed authority changed caller credentials")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIAMSessionAuthorityCapturesStateAndTimeAfterLock(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "acquire-current-state", true: "cancel-waiting"}[canceled], func(t *testing.T) {
			epoch := time.Date(2035, 2, 3, 4, 5, 0, 0, time.UTC)
			f := newSessionAuthorityFixture(t, "aws", epoch)
			ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
			defer cancel()
			held, release := make(chan struct{}), make(chan struct{})
			writerDone := make(chan error, 1)
			updated := f.role
			updated.RoleId = "AROARECREATED"
			updated.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}}`
			updatedDocument := `{"Statement":{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"*"}}`
			updatedDevice := f.device
			updatedDevice.Binding.Value.Seed = "new-secret-for-device"
			updatedDevice.Binding.VisibleValue = updatedDevice.Binding.Value
			go func() {
				writerDone <- f.repository.Repository.Update(ctx, func(tx WriteTx) error {
					if err := tx.PutRole(f.targetScope, updated); err != nil {
						return err
					}
					if err := tx.PutManagedPolicy(f.scope, ManagedPolicy{Arn: f.policyARN, DefaultVersionId: "v3", Versions: map[string]*PolicyVersion{"v3": {Document: updatedDocument}}}); err != nil {
						return err
					}
					if err := tx.PutMFADevice(f.scope, updatedDevice); err != nil {
						return err
					}
					close(held)
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-release:
						return nil
					}
				})
			}()
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-held:
			}
			entered := make(chan struct{})
			f.repository.beforeUpdate = func() { close(entered) }
			waitingCtx, cancelWaiting := context.WithCancel(ctx)
			defer cancelWaiting()
			result := make(chan error, 1)
			later := epoch.Add(5 * time.Minute)
			go func() {
				result <- f.service.WithSession(waitingCtx, func(ctx context.Context, repository identity.Repository, now time.Time) error {
					if canceled {
						return errors.New("canceled waiting callback ran")
					}
					if !now.Equal(later) {
						return errors.New("authority captured time before lock acquisition")
					}
					role, err := f.service.RoleForAssumption(ctx, f.role.Arn)
					if err != nil {
						return err
					}
					if role.ID != updated.RoleId || role.TrustPolicy != updated.AssumeRolePolicyDocument {
						return errors.New("authority observed pre-lock role incarnation or trust")
					}
					policies, err := f.service.IdentityPolicies(ctx)
					if err != nil {
						return err
					}
					if len(policies.Identity) != 1 || policies.Identity[0].Document != updatedDocument {
						return errors.New("authority observed pre-lock identity policy version")
					}
					at, err := f.service.VerifyMFA(ctx, f.device.SerialNumber, totp([]byte(updatedDevice.Binding.Value.Seed), later.Unix()/30))
					if err != nil {
						return err
					}
					if !at.Equal(now) {
						return errors.New("MFA ignored captured transaction time")
					}
					_, err = f.store.WithRepositoryAt(repository, now).IssueSession(ctx, f.parent, identity.SessionSpec{Duration: time.Hour, MFAPresent: true, MFAAuthenticatedAt: at})
					return err
				})
			}()
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-entered:
			}
			if f.source.reads.Load() != 0 {
				t.Fatal("clock sampled while storage lock was held")
			}
			if err := f.source.Advance(5 * time.Minute); err != nil {
				t.Fatal(err)
			}
			if canceled {
				cancelWaiting()
				if err := <-result; !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if f.source.reads.Load() != 0 {
					t.Fatal("canceled waiter sampled clock")
				}
			}
			close(release)
			if err := <-writerDone; err != nil {
				t.Fatal(err)
			}
			if !canceled {
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
