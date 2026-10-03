package elbv2

import (
	"context"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/elbv2"
)

func TestHealthThresholdsAndStaleObservation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	timer := clock.NewManual(now)
	repo := NewMemoryRepository(nil)
	service := New(Config{Repository: repo, Clock: timer})
	defer service.Close()
	scope := Scope{"aws", "123456789012", "us-east-1"}
	group := TargetGroupRecord{Scope: scope, Data: api.TargetGroup{TargetGroupArn: new(api.TargetGroupArn("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/health/1")), HealthCheckIntervalSeconds: new(api.HealthCheckIntervalSeconds(5)), HealthyThresholdCount: new(api.HealthCheckThresholdCount(2)), UnhealthyThresholdCount: new(api.HealthCheckThresholdCount(2))}}
	target := TargetRecord{Scope: scope, TargetGroupARN: value(group.Data.TargetGroupArn), Data: api.TargetDescription{Id: new(api.TargetId("10.20.1.9")), Port: new(api.Port(8080))}, OwnerARN: "task/first", Incarnation: "eni-first", State: "initial", Version: 1, NextCheck: now}
	if err := repo.Update(ctx, func(tx Transaction) error {
		if e := tx.PutTargetGroup(group); e != nil {
			return e
		}
		return tx.PutTarget(target)
	}); err != nil {
		t.Fatal(err)
	}
	load := func() TargetRecord {
		t.Helper()
		var current TargetRecord
		if err := repo.View(ctx, func(tx Reader) error {
			var e error
			current, e = tx.Target(scope, target.TargetGroupARN, value(target.Data.Id), 8080)
			return e
		}); err != nil {
			t.Fatal(err)
		}
		return current
	}
	observe := func(success bool) {
		t.Helper()
		current := load()
		state, reason := "unhealthy", "Target.ResponseCodeMismatch"
		if success {
			state, reason = "healthy", ""
		}
		if err := service.runtime.commitHealth(ctx, current, state, reason, "", success, true); err != nil {
			t.Fatal(err)
		}
	}
	observe(true)
	if got := load(); got.State != "healthy" {
		t.Fatalf("initial successful native probe must admit target: %+v", got)
	}
	observe(false)
	if got := load(); got.State != "healthy" || got.Failures != 1 {
		t.Fatalf("one failed probe must not remove healthy target: %+v", got)
	}
	observe(false)
	if got := load(); got.State != "unhealthy" || got.Reason != "Target.ResponseCodeMismatch" {
		t.Fatalf("failure threshold must remove target: %+v", got)
	}
	observe(true)
	if got := load(); got.State != "unhealthy" {
		t.Fatalf("recovery needs configured successes: %+v", got)
	}
	observe(true)
	if got := load(); got.State != "healthy" || got.Reason != "" {
		t.Fatalf("recovery must clear failure: %+v", got)
	}
	stale := load()
	if err := repo.Update(ctx, func(tx Transaction) error {
		replacement := stale
		replacement.Version++
		replacement.Incarnation = "eni-replacement"
		replacement.OwnerARN = "task/replacement"
		replacement.State = "initial"
		replacement.Successes = 0
		return tx.PutTarget(replacement)
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.runtime.commitHealth(ctx, stale, "healthy", "", "", true, true); err != nil {
		t.Fatal(err)
	}
	if got := load(); got.State != "initial" || got.Successes != 0 {
		t.Fatalf("old socket result admitted a replacement incarnation: %+v", got)
	}
}

func TestDrainCancelsOldRequestWithoutCancellingReregistration(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	repo := NewMemoryRepository(nil)
	service := New(Config{Repository: repo, Clock: clock.NewManual(now)})
	defer service.Close()
	scope := Scope{"aws", "123456789012", "us-east-1"}
	groupARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/drain/1"
	target := TargetRecord{Scope: scope, TargetGroupARN: groupARN, Data: api.TargetDescription{Id: new(api.TargetId("10.20.1.9")), Port: new(api.Port(8080))}, OwnerARN: "task/first", Incarnation: "eni-first", State: "draining", Version: 2, DrainUntil: now}
	if err := repo.Update(ctx, func(tx Transaction) error {
		if e := tx.PutTargetGroup(TargetGroupRecord{Scope: scope, Data: api.TargetGroup{TargetGroupArn: new(api.TargetGroupArn(groupARN))}}); e != nil {
			return e
		}
		return tx.PutTarget(target)
	}); err != nil {
		t.Fatal(err)
	}
	old, cancelOld := context.WithCancel(ctx)
	defer cancelOld()
	replacement, cancelReplacement := context.WithCancel(ctx)
	defer cancelReplacement()
	key := runtimeTargetKey(target)
	service.runtime.inflight[key] = map[uint64]forwardFlight{1: {cancel: cancelOld, version: 1, incarnation: target.Incarnation, owner: target.OwnerARN}, 2: {cancel: cancelReplacement, version: 3, incarnation: target.Incarnation, owner: target.OwnerARN}}
	if err := service.runtime.reconcileTarget(ctx, key, now, 2); err != nil {
		t.Fatal(err)
	}
	if old.Err() == nil {
		t.Fatal("expired drain did not cancel pre-drain native request")
	}
	if replacement.Err() != nil {
		t.Fatal("expired drain cancelled newer registration")
	}
	var lookup error
	_ = repo.View(ctx, func(tx Reader) error { _, lookup = tx.Target(scope, groupARN, value(target.Data.Id), 8080); return nil })
	if lookup != ErrNotFound {
		t.Fatalf("drained target retained: %v", lookup)
	}
}
