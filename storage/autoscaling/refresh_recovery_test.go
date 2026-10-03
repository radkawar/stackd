package autoscaling_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/autoscaling"
	"stackd/journal"
	domain "stackd/storage/autoscaling"
)

func TestRefreshReopenPreservesRollbackAndAdmittedLaunch(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository, _ journal.Storage, reopen func() domain.Repository) {
		g := fixtureGroup()
		now := g.ReconcileAt
		original := api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-refresh")), LaunchTemplateName: new(api.LaunchTemplateName("refresh-template")), Version: new(api.XmlStringMaxLen255("1"))}
		target := api.CloneLaunchTemplateSpecification(original)
		target.Version = new(api.XmlStringMaxLen255("2"))
		refresh := domain.RefreshRecord{Group: g.Key, GroupID: g.ID, Original: original, Target: target, RequestedAt: now, OriginEventID: "refresh-origin", BlockedSince: now.Add(time.Minute), PauseUntil: now.Add(time.Hour), ActiveDeadline: now.Add(14 * 24 * time.Hour), Checkpoint: 1, WaitForTransitioning: true, Members: []domain.RefreshMember{{InstanceID: "i-original", Warm: false}, {InstanceID: "i-warm", Warm: true}}, Data: api.InstanceRefresh{InstanceRefreshId: new(api.XmlStringMaxLen255("refresh-one")), AutoScalingGroupName: new(api.XmlStringMaxLen255(g.Key.Name)), StartTime: &now, Status: new(api.InstanceRefreshStatus("RollbackInProgress")), StatusReason: new(api.XmlStringMaxLen1023("alarm")), Strategy: new(api.RefreshStrategy("Rolling")), PercentageComplete: new(api.IntPercent(50)), InstancesToUpdate: new(api.InstancesToUpdate(1)), DesiredConfiguration: &api.DesiredConfiguration{LaunchTemplate: &target}, Preferences: &api.RefreshPreferences{MinHealthyPercentage: new(api.IntPercent(100)), MaxHealthyPercentage: new(api.IntPercent100To200(150)), InstanceWarmup: new(api.RefreshInstanceWarmup(30)), CheckpointPercentages: api.CheckpointPercentages{50, 100}, CheckpointDelay: new(api.CheckpointDelay(70)), BakeTime: new(api.BakeTime(90)), SkipMatching: new(api.SkipMatching(true)), AutoRollback: new(api.AutoRollback(true)), ScaleInProtectedInstances: new(api.ScaleInProtectedInstances("Refresh")), StandbyInstances: new(api.StandbyInstances("Terminate")), AlarmSpecification: &api.AlarmSpecification{Alarms: api.AlarmList{"deployment"}}}, RollbackDetails: &api.RollbackDetails{RollbackStartTime: &now, RollbackReason: new(api.XmlStringMaxLen1023("alarm")), PercentageCompleteOnRollback: new(api.IntPercent(50)), InstancesToUpdateOnRollback: new(api.InstancesToUpdate(1))}}}
		activity := domain.ActivityRecord{Key: domain.ActivityKey{Scope: g.Key.Scope, ID: "admitted-replacement"}, Group: g.Key, GroupID: g.ID, Kind: "launch", LaunchTemplate: target, OriginEventID: refresh.OriginEventID, Data: api.Activity{ActivityId: new(api.XmlString("admitted-replacement")), StartTime: &now, StatusCode: new(api.ScalingActivityStatusCode("InProgress"))}}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.PutGroup(g); err != nil {
				return err
			}
			if err := tx.PutRefresh(refresh); err != nil {
				return err
			}
			return tx.PutActivity(activity)
		}); err != nil {
			t.Fatal(err)
		}
		aborted := errors.New("abort transition")
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			copy := refresh
			copy.Data = api.CloneInstanceRefresh(refresh.Data)
			copy.Data.Status = new(api.InstanceRefreshStatus("RollbackSuccessful"))
			if err := tx.PutRefresh(copy); err != nil {
				return err
			}
			return aborted
		}); !errors.Is(err, aborted) {
			t.Fatal(err)
		}
		repo = reopen()
		if err := repo.View(t.Context(), func(tx domain.Reader) error {
			rows, err := tx.Refreshes(g.Key)
			if err != nil {
				return err
			}
			if len(rows) != 1 || !reflect.DeepEqual(rows[0], refresh) {
				t.Fatalf("reopened deployment changed: got %#v want %#v", rows, refresh)
			}
			admitted, err := tx.Activity(activity.Key)
			if err != nil {
				return err
			}
			if admitted.LaunchTemplate.Version == nil || *admitted.LaunchTemplate.Version != "2" {
				t.Fatal("rollback rewrote admitted launch client-token input")
			}
			rows[0].Members[0].InstanceID = "reader-mutated"
			rows[0].Data.Preferences.AlarmSpecification.Alarms[0] = "reader-mutated"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.DeleteGroup(g.Key); err != nil {
				return err
			}
			g.ID = "new-incarnation"
			return tx.PutGroup(g)
		}); err != nil {
			t.Fatal(err)
		}
		repo = reopen()
		if err := repo.View(t.Context(), func(tx domain.Reader) error {
			rows, err := tx.Refreshes(g.Key)
			if err != nil {
				return err
			}
			if len(rows) != 1 || rows[0].GroupID == g.ID || rows[0].Members[0].InstanceID != "i-original" || rows[0].Data.Preferences.AlarmSpecification.Alarms[0] != "deployment" {
				t.Fatalf("incarnation history or reader isolation lost: %#v", rows)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
