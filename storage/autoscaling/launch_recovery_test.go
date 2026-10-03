package autoscaling_test

import (
	"testing"
	"time"

	api "stackd/internal/awsapi/autoscaling"
	"stackd/journal"
	domain "stackd/storage/autoscaling"
)

func TestPendingLaunchKeepsAdmittedTagsAndProtectionAfterMutationAndReopen(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository, _ journal.Storage, reopen func() domain.Repository) {
		group := fixtureGroup()
		tags := api.TagDescriptionList{{Key: new(api.TagKey("generation")), Value: new(api.TagValue("admitted")), PropagateAtLaunch: new(api.PropagateAtLaunch(true))}}
		group.Data.Tags = tags
		activity := domain.ActivityRecord{
			Key: domain.ActivityKey{Scope: group.Key.Scope, ID: "pending-launch"}, Group: group.Key, GroupID: group.ID,
			Kind: "launch", SubnetID: "subnet-admitted", LaunchTags: tags, ProtectedFromScaleIn: true, InstanceWarmup: new(int32(17)),
			LaunchTemplate: api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-workers")), Version: new(api.XmlStringMaxLen255("7"))},
			Data:           api.Activity{ActivityId: new(api.XmlString("pending-launch")), StartTime: &group.ReconcileAt, StatusCode: new(api.ScalingActivityStatusCode("InProgress"))},
			RetryAt:        group.ReconcileAt.Add(time.Second),
		}
		requireAdmitted := func(r domain.Reader) error {
			t.Helper()
			got, err := r.Activity(activity.Key)
			if err != nil {
				return err
			}
			if !got.ProtectedFromScaleIn || got.InstanceWarmup == nil || *got.InstanceWarmup != 17 || got.SubnetID != "subnet-admitted" || got.LaunchTemplate.Version == nil || *got.LaunchTemplate.Version != "7" {
				t.Fatalf("pending launch selection changed: %#v", got)
			}
			if len(got.LaunchTags) != 1 || got.LaunchTags[0].Key == nil || *got.LaunchTags[0].Key != "generation" || got.LaunchTags[0].Value == nil || *got.LaunchTags[0].Value != "admitted" || got.LaunchTags[0].PropagateAtLaunch == nil || !*got.LaunchTags[0].PropagateAtLaunch {
				t.Fatalf("pending launch tags changed: %#v", got.LaunchTags)
			}
			// A reader must not hand mutable stored launch inputs to its caller either.
			*got.LaunchTags[0].Value = "reader-mutated"
			return nil
		}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.PutGroup(group); err != nil {
				return err
			}
			if err := tx.PutActivity(activity); err != nil {
				return err
			}
			*tags[0].Value = "latest-group"
			*tags[0].PropagateAtLaunch = false
			*activity.LaunchTemplate.Version = "8"
			*activity.InstanceWarmup = 91
			activity.ProtectedFromScaleIn = false
			if err := requireAdmitted(tx); err != nil {
				return err
			}
			// A later accepted group update must not change an in-flight ClientToken retry.
			group.Data.NewInstancesProtectedFromScaleIn = new(api.InstanceProtected(false))
			group.Data.LaunchTemplate.Version = new(api.XmlStringMaxLen255("8"))
			return tx.PutGroup(group)
		}); err != nil {
			t.Fatal(err)
		}
		repo = reopen()
		if err := repo.View(t.Context(), func(r domain.Reader) error {
			if err := requireAdmitted(r); err != nil {
				return err
			}
			got, err := r.Group(group.Key)
			if err != nil {
				return err
			}
			if len(got.Data.Tags) != 1 || got.Data.Tags[0].Value == nil || *got.Data.Tags[0].Value != "latest-group" {
				t.Fatalf("latest group update was not retained independently: %#v", got.Data.Tags)
			}
			return requireAdmitted(r)
		}); err != nil {
			t.Fatal(err)
		}
	})
}
