package autoscaling

import (
	"context"
	"testing"
	"time"

	api "stackd/internal/awsapi/autoscaling"
)

func refreshFixture(g GroupRecord, now time.Time, members ...InstanceRecord) RefreshRecord {
	p, _ := refreshPreferences(g, &api.RefreshPreferences{MinHealthyPercentage: new(api.IntPercent(100)), MaxHealthyPercentage: new(api.IntPercent100To200(100)), InstanceWarmup: new(api.RefreshInstanceWarmup(30))})
	r := RefreshRecord{Group: g.Key, GroupID: g.ID, RequestedAt: now, ActiveDeadline: now.Add(14 * 24 * time.Hour), Original: *g.Data.LaunchTemplate, Target: *g.Data.LaunchTemplate, Data: api.InstanceRefresh{AutoScalingGroupName: g.Data.AutoScalingGroupName, InstanceRefreshId: new(api.XmlStringMaxLen255("test-refresh")), Status: new(api.InstanceRefreshStatus("InProgress")), StartTime: &now, Preferences: &p, Strategy: new(api.RefreshStrategy("Rolling"))}}
	text(&r.Target.Version, "2")
	r.Data.DesiredConfiguration = &api.DesiredConfiguration{LaunchTemplate: &r.Target}
	for _, m := range members {
		r.Members = append(r.Members, RefreshMember{value(m.Data.InstanceId), warmMember(m)})
	}
	return r
}

func refreshPasses(t *testing.T, s *Service, ctx context.Context, g GroupRecord, n int) {
	t.Helper()
	for range n {
		if _, _, err := s.reconcileRefresh(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
}
func storedRefresh(t *testing.T, s *Service, ctx context.Context, g GroupRecord) RefreshRecord {
	t.Helper()
	var rows []RefreshRecord
	if err := s.repository.View(ctx, func(tx Reader) error { var err error; rows, err = tx.Refreshes(g.Key); return err }); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("refresh history: %+v", rows)
	}
	return rows[0]
}

func TestRefreshWarmupProtectsHealthyFloorAndDoesNotCommitDesiredEarly(t *testing.T) {
	s, ctx, g, source, _ := ownedControlService(t)
	s.instances = transitionInstances{}
	number(&g.Data.DesiredCapacity, 1)
	g.Data.LaunchTemplate = &api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-refresh")), Version: new(api.XmlStringMaxLen255("1"))}
	old := transitionMember(g, "i-old", "InService", source.Now())
	old.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(*g.Data.LaunchTemplate))
	r := refreshFixture(g, source.Now(), old)
	replacement := transitionMember(g, "i-new", "InService", source.Now())
	replacement.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(r.Target))
	replacement.WarmUntil = source.Now().Add(30 * time.Second)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutGroup(g); err != nil {
			return err
		}
		if err := tx.PutInstance(old); err != nil {
			return err
		}
		if err := tx.PutInstance(replacement); err != nil {
			return err
		}
		activity := s.newActivity(g, "launch", refreshCause(r))
		activity.InstanceID = value(replacement.Data.InstanceId)
		activity.Data.EndTime = new(source.Now())
		if err := tx.PutActivity(activity); err != nil {
			return err
		}
		return tx.PutRefresh(r)
	}); err != nil {
		t.Fatal(err)
	}
	refreshPasses(t, s, ctx, g, 4)
	if readTransition(t, s, ctx, g, "i-old").TerminationRequested {
		t.Fatal("warm replacement counted toward minimum healthy capacity")
	}
	if err := source.Advance(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	refreshPasses(t, s, ctx, g, 4)
	if !readTransition(t, s, ctx, g, "i-old").TerminationRequested {
		t.Fatal("healthy warmed replacement did not release original")
	}
	if err := s.repository.View(ctx, func(tx Reader) error {
		current, err := tx.Group(g.Key)
		if err == nil && value(current.Data.LaunchTemplate.Version) != "1" {
			t.Fatal("desired template committed before original termination")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshProtectedBlockedHourAndRollbackPreservesOriginal(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed", true: "automatic-rollback"}[automatic], func(t *testing.T) {
			s, ctx, g, source, _ := ownedControlService(t)
			number(&g.Data.DesiredCapacity, 1)
			s.instances = transitionInstances{}
			g.Data.LaunchTemplate = &api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-refresh")), Version: new(api.XmlStringMaxLen255("1"))}
			old := transitionMember(g, "i-protected", "InService", source.Now())
			boolean(&old.Data.ProtectedFromScaleIn, true)
			old.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(*g.Data.LaunchTemplate))
			r := refreshFixture(g, source.Now(), old)
			boolean(&r.Data.Preferences.AutoRollback, automatic)
			storeTransition(t, s, ctx, g, old)
			if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutRefresh(r) }); err != nil {
				t.Fatal(err)
			}
			refreshPasses(t, s, ctx, g, 3)
			if err := source.Advance(time.Hour - time.Second); err != nil {
				t.Fatal(err)
			}
			refreshPasses(t, s, ctx, g, 2)
			if value(storedRefresh(t, s, ctx, g).Data.Status) != "InProgress" {
				t.Fatal("blocked refresh failed before one hour")
			}
			if err := source.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			refreshPasses(t, s, ctx, g, 4)
			want := "Failed"
			if automatic {
				want = "RollbackSuccessful"
			}
			got := storedRefresh(t, s, ctx, g)
			if value(got.Data.Status) != want {
				t.Fatalf("blocked refresh status=%s want %s", value(got.Data.Status), want)
			}
			if readTransition(t, s, ctx, g, "i-protected").TerminationRequested {
				t.Fatal("rollback replaced untouched protected original")
			}
		})
	}
}

func TestRefreshCheckpointBakeAndActiveDeadline(t *testing.T) {
	s, ctx, g, source, _ := ownedControlService(t)
	number(&g.Data.DesiredCapacity, 2)
	s.instances = transitionInstances{}
	g.Data.LaunchTemplate = &api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-refresh")), Version: new(api.XmlStringMaxLen255("1"))}
	old := transitionMember(g, "i-old", "InService", source.Now())
	old.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(*g.Data.LaunchTemplate))
	retired := transitionMember(g, "i-retired", "InService", source.Now())
	r := refreshFixture(g, source.Now(), old, retired)
	r.Data.Preferences.CheckpointPercentages = api.CheckpointPercentages{25, 50, 100}
	number(&r.Data.Preferences.CheckpointDelay, 60)
	number(&r.Data.Preferences.BakeTime, 90)
	replacement := transitionMember(g, "i-new", "InService", source.Now())
	replacement.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(r.Target))
	r.ActiveDeadline = source.Now().Add(30 * time.Second)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutGroup(g); err != nil {
			return err
		}
		if err := tx.PutInstance(old); err != nil {
			return err
		}
		if err := tx.PutInstance(replacement); err != nil {
			return err
		}
		return tx.PutRefresh(r)
	}); err != nil {
		t.Fatal(err)
	}
	refreshPasses(t, s, ctx, g, 3)
	paused := storedRefresh(t, s, ctx, g)
	if paused.Checkpoint != 2 || !paused.ActiveDeadline.Equal(r.ActiveDeadline.Add(time.Minute)) {
		t.Fatal("checkpoint skipping or active replacement deadline is incorrect")
	}
	source.Advance(time.Minute)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.DeleteInstance(g.Key.Scope, value(old.Data.InstanceId)); err != nil {
			return err
		}
		replacement.Data.InstanceId = new(api.XmlStringMaxLen19("i-final"))
		return tx.PutInstance(replacement)
	}); err != nil {
		t.Fatal(err)
	}
	refreshPasses(t, s, ctx, g, 4)
	if value(storedRefresh(t, s, ctx, g).Data.Status) != "Baking" {
		t.Fatal("completed deployment did not enter bake")
	}
	source.Advance(89 * time.Second)
	refreshPasses(t, s, ctx, g, 2)
	if value(storedRefresh(t, s, ctx, g).Data.Status) != "Baking" {
		t.Fatal("bake ended early or active timeout included bake")
	}
	source.Advance(time.Second)
	refreshPasses(t, s, ctx, g, 2)
	if value(storedRefresh(t, s, ctx, g).Data.Status) != "Successful" {
		t.Fatal("bake never completed")
	}
}

func TestRefreshFinalCheckpointStopsAtPartialDeployment(t *testing.T) {
	s, ctx, g, source, _ := ownedControlService(t)
	s.instances = transitionInstances{}
	g.Data.LaunchTemplate = &api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-refresh")), Version: new(api.XmlStringMaxLen255("1"))}
	old := transitionMember(g, "i-old", "InService", source.Now())
	old.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(*g.Data.LaunchTemplate))
	retired := transitionMember(g, "i-retired", "InService", source.Now())
	r := refreshFixture(g, source.Now(), old, retired)
	r.Data.Preferences.CheckpointPercentages = api.CheckpointPercentages{50}
	number(&r.Data.Preferences.CheckpointDelay, 3600)
	replacement := transitionMember(g, "i-new", "InService", source.Now())
	replacement.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(r.Target))
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutGroup(g); err != nil {
			return err
		}
		if err := tx.PutInstance(old); err != nil {
			return err
		}
		if err := tx.PutInstance(replacement); err != nil {
			return err
		}
		return tx.PutRefresh(r)
	}); err != nil {
		t.Fatal(err)
	}
	refreshPasses(t, s, ctx, g, 5)
	got := storedRefresh(t, s, ctx, g)
	if value(got.Data.Status) != "Successful" || intValue(got.Data.PercentageComplete) != 50 || intValue(got.Data.InstancesToUpdate) != 1 {
		t.Fatalf("partial refresh continued past its final checkpoint: %+v", got.Data)
	}
	if readTransition(t, s, ctx, g, "i-old").TerminationRequested {
		t.Fatal("partial refresh retired a member beyond its final checkpoint")
	}
}
