package autoscaling

import (
	"context"
	"testing"
	"time"

	api "stackd/internal/awsapi/autoscaling"
)

func TestRefreshLongHealthyWarmupDoesNotConsumeBlockedDeadline(t *testing.T) {
	for _, mode := range []string{"launch-before", "terminate-before", "unhealthy-replacement"} {
		t.Run(mode, func(t *testing.T) {
			s, ctx, g, source, _ := ownedControlService(t)
			s.instances = transitionInstances{}
			number(&g.Data.DesiredCapacity, 1)
			g.Data.LaunchTemplate = &api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-refresh")), Version: new(api.XmlStringMaxLen255("1"))}
			old := transitionMember(g, "i-original", "InService", source.Now())
			old.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(*g.Data.LaunchTemplate))
			r := refreshFixture(g, source.Now(), old)
			number(&r.Data.Preferences.InstanceWarmup, 7200)
			if mode == "terminate-before" {
				number(&r.Data.Preferences.MinHealthyPercentage, 0)
			}
			replacement := transitionMember(g, "i-replacement", "InService", source.Now())
			replacement.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(r.Target))
			replacement.WarmUntil = source.Now().Add(2 * time.Hour)
			if mode == "unhealthy-replacement" {
				text(&replacement.Data.HealthStatus, "Unhealthy")
			}
			activity := s.newActivity(g, "launch", refreshCause(r))
			activity.InstanceID = value(replacement.Data.InstanceId)
			activity.InstanceWarmup = new(int32(7200))
			text(&activity.Data.StatusCode, "WaitingForInstanceWarmup")
			replacement.ActivityID = activity.Key.ID
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutGroup(g); err != nil {
					return err
				}
				if mode != "terminate-before" {
					if err := tx.PutInstance(old); err != nil {
						return err
					}
				}
				if err := tx.PutInstance(replacement); err != nil {
					return err
				}
				if err := tx.PutActivity(activity); err != nil {
					return err
				}
				return tx.PutRefresh(r)
			}); err != nil {
				t.Fatal(err)
			}
			refreshPasses(t, s, ctx, g, 4)
			if err := source.Advance(time.Hour + time.Second); err != nil {
				t.Fatal(err)
			}
			refreshPasses(t, s, ctx, g, 4)
			current := storedRefresh(t, s, ctx, g)
			if mode == "unhealthy-replacement" {
				if value(current.Data.Status) != "Failed" {
					t.Fatalf("unhealthy replacement escaped blocked timeout: %+v", current.Data)
				}
				return
			}
			if value(current.Data.Status) != "InProgress" || !current.BlockedSince.IsZero() {
				t.Fatalf("healthy two-hour warmup consumed failure budget: %+v", current)
			}
			if mode == "launch-before" && readTransition(t, s, ctx, g, "i-original").TerminationRequested {
				t.Fatal("original retired before replacement finished warming")
			}
			if err := source.Advance(time.Hour - time.Second); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error { return s.finishActivity(tx.Context(), tx, g, activity, nil) }); err != nil {
				t.Fatal(err)
			}
			refreshPasses(t, s, ctx, g, 4)
			if mode == "launch-before" {
				if !readTransition(t, s, ctx, g, "i-original").TerminationRequested {
					t.Fatal("completed healthy warmup did not release original")
				}
			} else if value(storedRefresh(t, s, ctx, g).Data.Status) != "Successful" {
				t.Fatal("terminate-before refresh did not complete after long warmup")
			}
		})
	}
}

func TestRefreshAndScaleInRejectPreviousExecutionRoleSnapshot(t *testing.T) {
	type executionRoleKey struct{}
	for _, mode := range []string{"refresh", "scale-in"} {
		t.Run(mode, func(t *testing.T) {
			s, ctx, snapshot, source, _ := ownedControlService(t)
			s.instances = transitionInstances{}
			snapshot.Data.LaunchTemplate = &api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-refresh")), Version: new(api.XmlStringMaxLen255("1"))}
			text(&snapshot.Data.ServiceLinkedRoleARN, "arn:aws:iam::000000000000:role/previous")
			current := cloneGroup(snapshot)
			current.Version++
			text(&current.Data.ServiceLinkedRoleARN, "arn:aws:iam::000000000000:role/current")
			current.Data.TerminationPolicies = api.TerminationPolicies{"arn:aws:lambda:us-east-1:000000000000:function:current-policy"}
			if mode == "scale-in" {
				number(&current.Data.DesiredCapacity, 1)
			}
			previousChoice := transitionMember(current, "i-previous-context", "InService", source.Now())
			currentChoice := transitionMember(current, "i-current-context", "InService", source.Now())
			previousChoice.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(*current.Data.LaunchTemplate))
			currentChoice.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(*current.Data.LaunchTemplate))
			refresh := refreshFixture(current, source.Now(), previousChoice, currentChoice)
			number(&refresh.Data.Preferences.MinHealthyPercentage, 0)
			s.terminationSelector = terminationSelectFunc(func(ctx context.Context, _ TerminationPolicyRequest) ([]string, error) {
				if ctx.Value(executionRoleKey{}) == "previous" {
					return []string{"i-previous-context"}, nil
				}
				return []string{"i-current-context"}, nil
			})
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutGroup(current); err != nil {
					return err
				}
				if err := tx.PutInstance(previousChoice); err != nil {
					return err
				}
				if err := tx.PutInstance(currentChoice); err != nil {
					return err
				}
				if mode == "refresh" {
					return tx.PutRefresh(refresh)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			staleContext := context.WithValue(ctx, executionRoleKey{}, "previous")
			if mode == "refresh" {
				refreshPasses(t, s, staleContext, snapshot, 4)
			} else {
				if changed, err := s.reconcileCapacity(staleContext, snapshot); err != nil || changed {
					t.Fatalf("stale capacity pass accepted: changed=%v err=%v", changed, err)
				}
			}
			for _, id := range []string{"i-previous-context", "i-current-context"} {
				if readTransition(t, s, ctx, current, id).TerminationRequested {
					t.Fatalf("new role/policy executed using stale role authority: %s", id)
				}
			}
			freshContext := context.WithValue(ctx, executionRoleKey{}, "current")
			if mode == "refresh" {
				refreshPasses(t, s, freshContext, current, 4)
			} else {
				if changed, err := s.reconcileCapacity(freshContext, current); err != nil || !changed {
					t.Fatalf("fresh capacity pass rejected: changed=%v err=%v", changed, err)
				}
			}
			if !readTransition(t, s, ctx, current, "i-current-context").TerminationRequested || readTransition(t, s, ctx, current, "i-previous-context").TerminationRequested {
				t.Fatal("fresh role policy did not own the admitted termination")
			}
		})
	}
}
