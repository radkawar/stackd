package elbv2_test

import (
	"context"
	"errors"
	"path/filepath"
	api "stackd/internal/awsapi/elbv2"
	"stackd/journal"
	domain "stackd/storage/elbv2"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/elbv2"
	journaldb "stackd/storage/sqlite/journal"
	"testing"
	"time"
)

func TestRetainedOwnerHealthDrainAndAuditRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alb.sqlite")
	db, e := sqlite.Open(t.Context(), path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := backend.New(db)
	events := journaldb.New(db)
	sc := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	now := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	a := "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/owned/first"
	lbArn := "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/owned/first"
	target := domain.TargetRecord{Scope: sc, TargetGroupARN: a, Data: api.TargetDescription{Id: new(api.TargetId("10.0.0.9")), Port: new(api.Port(8080)), AvailabilityZone: new(api.ZoneName("us-east-1a"))}, OwnerARN: "arn:aws:ecs:us-east-1:111111111111:task/cluster/task-first", Incarnation: "eni-first", State: "draining", Reason: "Target.DeregistrationInProgress", Description: "Target deregistration is in progress", Successes: 3, Failures: 1, NextCheck: now.Add(17 * time.Second), DrainUntil: now.Add(17 * time.Second), Version: 8}
	lb := domain.LoadBalancerRecord{Scope: sc, Data: api.LoadBalancer{LoadBalancerArn: new(api.LoadBalancerArn(lbArn)), LoadBalancerName: new(api.LoadBalancerName("owned")), State: &api.LoadBalancerState{Code: new(api.LoadBalancerStateEnumPROVISIONING)}, CreatedTime: new(api.CreatedTime(now))}, Tags: api.TagList{{Key: new(api.TagKey("team")), Value: new(api.TagValue("blue"))}}, AttachmentIDs: map[string]string{"subnet-first": "eni-alb-first"}, AttachmentGenerations: map[string]uint64{"subnet-first": 17, "subnet-pending": 18}, NextReconcile: time.Unix(0, 0).UTC(), Version: 9, IdleTimeout: 71 * time.Second, DeletionProtection: true}
	appendAudit := func(ctx context.Context) error {
		return events.AppendAPICallCompleted(ctx, journal.Envelope{At: now, Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, journal.APICallCompleted{EventID: "owned-drain", EventSource: "elasticloadbalancing.amazonaws.com", EventName: "DeregisterTargets", Category: journal.CategoryManagement})
	}
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		if _, e := tx.NextID(); e != nil {
			return e
		}
		if e := tx.PutLoadBalancer(lb); e != nil {
			return e
		}
		if e := tx.PutTarget(target); e != nil {
			return e
		}
		return appendAudit(tx.Context())
	}); e != nil {
		t.Fatal(e)
	}
	changed := target
	changed.OwnerARN = "replacement"
	changed.Incarnation = "eni-replacement"
	changed.State = "healthy"
	changed.DrainUntil = time.Time{}
	changed.Version++
	if e = repo.Attempt(t.Context(), func(tx domain.Transaction) error {
		if e := tx.PutTarget(changed); e != nil {
			return e
		}
		return appendAudit(tx.Context())
	}); e == nil {
		t.Fatal("duplicate journal completion committed replacement identity")
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	db, e = sqlite.Open(t.Context(), path)
	if e != nil {
		t.Fatal(e)
	}
	repo = backend.New(db)
	if e = repo.View(t.Context(), func(tx domain.Reader) error {
		got, e := tx.Target(sc, a, "10.0.0.9", 8080)
		if e != nil {
			return e
		}
		if got.OwnerARN != target.OwnerARN || got.Incarnation != "eni-first" || got.State != "draining" || got.Version != 8 || got.Successes != 3 || got.Failures != 1 || !got.DrainUntil.Equal(target.DrainUntil) || !got.NextCheck.Equal(target.NextCheck) {
			t.Fatalf("rollback or restart lost exact target: %#v", got)
		}
		retained, e := tx.LoadBalancer(sc, lbArn)
		if e != nil {
			return e
		}
		if retained.AttachmentIDs["subnet-first"] != "eni-alb-first" || retained.AttachmentGenerations["subnet-pending"] != 18 || retained.AttachmentGenerations["subnet-first"] != 17 || retained.Version != 9 || !retained.NextReconcile.Equal(time.Unix(0, 0)) || !retained.DeletionProtection || retained.IdleTimeout != 71*time.Second {
			t.Fatalf("native intent lost across restart: %#v", retained)
		}
		other := sc
		other.AccountID = "222222222222"
		if _, e = tx.Target(other, a, "10.0.0.9", 8080); !errors.Is(e, domain.ErrNotFound) {
			t.Fatalf("target lookup crossed scope: %v", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = repo.Update(t.Context(), func(tx domain.Transaction) error {
		id, e := tx.NextID()
		if e != nil {
			return e
		}
		if id != 2 {
			t.Fatalf("retained identity sequence reset: %d", id)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
