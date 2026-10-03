package lambda

import (
	"errors"
	"testing"
	"time"

	"stackd/internal/scheduler"
)

func TestAsyncRecreationSettingsDetachAndApply(t *testing.T) {
	s, ctx, accepted, manual, _ := missingAliasFixture(t)
	accepted.FunctionARN = accepted.Key.ARN()
	missingAliasPut(t, ctx, s.repository, accepted)
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteFunction(accepted.Key) }); err != nil {
		t.Fatal(err)
	}
	retained := missingAliasRead(t, ctx, s.repository, accepted.ID)
	if !retained.SettingsDetached || retained.RequestID != accepted.RequestID || retained.Settings != accepted.Settings {
		t.Fatalf("deletion lost accepted queue controls: %+v", retained)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		_, err := selectInvocation(r, &retained)
		if !errors.Is(err, ErrNotFound) || retained.Settings != accepted.Settings || retained.RoleARN != accepted.RoleARN {
			t.Fatalf("absent identity changed retained work: %+v %v", retained, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	replacement := FunctionRecord{Key: accepted.Key, Role: "arn:aws:iam::111111111111:role/replacement", DeadLetterARN: "arn:aws:sqs:us-east-1:111111111111:replacement-dlq"}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutFunction(replacement) }); err != nil {
		t.Fatal(err)
	}
	selectCurrent := func(want EventInvokeSettings, detached bool) {
		t.Helper()
		if err := s.repository.View(ctx, func(r Reader) error {
			current, err := selectInvocation(r, &retained)
			if err != nil {
				return err
			}
			if current.Role != replacement.Role || retained.RoleARN != replacement.Role || retained.DeadLetterARN != replacement.DeadLetterARN {
				t.Fatalf("recreation reused stale deployment authority: current=%+v event=%+v", current, retained)
			}
			if retained.Settings != want || retained.SettingsDetached != detached {
				t.Fatalf("applied queue settings=%+v detached=%v; want %+v detached=%v", retained.Settings, retained.SettingsDetached, want, detached)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	selectCurrent(accepted.Settings, true)
	config := EventInvokeConfig{Key: retained.Reference(), MaxAgeSeconds: 240, MaxRetries: 0, HasMaxAge: true, HasMaxRetries: true,
		OnSuccessARN: "arn:aws:sqs:us-east-1:111111111111:new", Effective: defaultEventInvokeSettings()}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return s.stageEventInvokeConfig(tx, &config) }); err != nil {
		t.Fatal(err)
	}
	selectCurrent(accepted.Settings, true)
	if err := manual.Advance(2 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := (eventInvokeConfigJobs{s}).Run(ctx, scheduler.Job{Key: config.Key.ARN(), Due: *config.AppliesAt, Version: config.Version}); err != nil {
		t.Fatal(err)
	}
	retained = missingAliasRead(t, ctx, s.repository, accepted.ID)
	selectCurrent(configuredEventInvokeSettings(config), false)
}

func TestAsyncDetachedConfigurationDeletionRestoresDefaults(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending-replacement", true: "applied-replacement"}[applied], func(t *testing.T) {
			s, ctx, accepted, manual, _ := missingAliasFixture(t)
			accepted.FunctionARN = accepted.Key.ARN() + ":$LATEST"
			accepted.SettingsDetached = true
			missingAliasPut(t, ctx, s.repository, accepted)
			config := EventInvokeConfig{Key: eventInvokeConfigReference(accepted.Reference()), Deleted: true,
				Effective: defaultEventInvokeSettings()}
			if applied {
				config.Effective = accepted.Settings
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error { return s.stageEventInvokeConfig(tx, &config) }); err != nil {
				t.Fatal(err)
			}
			if applied {
				if err := manual.Advance(2 * time.Minute); err != nil {
					t.Fatal(err)
				}
				if err := (eventInvokeConfigJobs{s}).Run(ctx, scheduler.Job{Key: config.Key.ARN(), Due: *config.AppliesAt, Version: config.Version}); err != nil {
					t.Fatal(err)
				}
			}
			retained := missingAliasRead(t, ctx, s.repository, accepted.ID)
			if err := s.repository.View(ctx, func(r Reader) error {
				if _, err := selectInvocation(r, &retained); err != nil {
					return err
				}
				if retained.SettingsDetached || retained.Settings != defaultEventInvokeSettings() {
					t.Fatalf("explicit config deletion revived detached controls: %+v", retained)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
