package autoscaling_test

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/autoscaling"
	"stackd/journal"
	domain "stackd/storage/autoscaling"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/autoscaling"
	journaldb "stackd/storage/sqlite/journal"
)

func repositories(t *testing.T, fn func(*testing.T, domain.Repository, journal.Storage, func() domain.Repository)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		d := memory.NewDomain()
		repo := domain.NewMemory(d)
		fn(t, repo, journal.NewMemory(d), func() domain.Repository { return repo })
	})
	t.Run("sqlite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "autoscaling.sqlite")
		db, err := sqlite.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		fn(t, backend.New(db), journaldb.New(db), func() domain.Repository {
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = sqlite.Open(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			return backend.New(db)
		})
	})
}

func fixtureGroup() domain.GroupRecord {
	now := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	key := domain.GroupKey{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "workers"}
	return domain.GroupRecord{
		Key: key, ID: "incarnation-first", OriginEventID: "create-workers", ReconcileAt: now, Version: math.MaxUint64,
		ReconcileCause: "desired capacity increased", PendingInstanceWarmup: new(int32(17)),
		MetricAt: now.Truncate(time.Minute),
		Data: api.AutoScalingGroup{
			AutoScalingGroupName: new(api.XmlStringMaxLen255(key.Name)), AutoScalingGroupARN: new(api.ResourceName("arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:incarnation-first:autoScalingGroupName/workers")),
			CreatedTime: &now, DesiredCapacity: new(api.AutoScalingGroupDesiredCapacity(2)), MinSize: new(api.AutoScalingGroupMinSize(1)), MaxSize: new(api.AutoScalingGroupMaxSize(4)),
			DefaultCooldown: new(api.Cooldown(300)), DefaultInstanceWarmup: new(api.DefaultInstanceWarmup(17)), HealthCheckGracePeriod: new(api.HealthCheckGracePeriod(30)), HealthCheckType: new(api.XmlStringMaxLen32("ELB")),
			AvailabilityZones: api.AvailabilityZones{"us-east-1b", "us-east-1a"}, AvailabilityZoneIds: api.AvailabilityZoneIds{},
			AvailabilityZoneDistribution:     &api.AvailabilityZoneDistribution{CapacityDistributionStrategy: new(api.CapacityDistributionStrategy("balanced-best-effort"))},
			CapacityReservationSpecification: &api.CapacityReservationSpecification{CapacityReservationPreference: new(api.CapacityReservationPreference("default"))},
			InstanceLifecyclePolicy:          &api.InstanceLifecyclePolicy{RetentionTriggers: &api.RetentionTriggers{TerminateHookAbandon: new(api.RetentionAction("retain"))}},
			LaunchTemplate:                   &api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-workers")), Version: new(api.XmlStringMaxLen255("$Latest"))},
			VPCZoneIdentifier:                new(api.XmlStringMaxLen5000("subnet-a,subnet-b")), TargetGroupARNs: api.TargetGroupARNs{"arn:targetgroup/web"},
			TerminationPolicies: api.TerminationPolicies{"OldestLaunchTemplate", "Default"}, LoadBalancerNames: api.LoadBalancerNames{},
			NewInstancesProtectedFromScaleIn: new(api.InstanceProtected(false)), ServiceLinkedRoleARN: new(api.ResourceName("arn:aws:iam::111111111111:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling")),
			Tags:               api.TagDescriptionList{{Key: new(api.TagKey("owner")), Value: new(api.TagValue("fleet")), ResourceId: new(api.XmlString(key.Name)), ResourceType: new(api.XmlString("auto-scaling-group")), PropagateAtLaunch: new(api.PropagateAtLaunch(true))}},
			EnabledMetrics:     api.EnabledMetrics{{Metric: new(api.XmlStringMaxLen255("GroupInServiceInstances")), Granularity: new(api.XmlStringMaxLen255("1Minute"))}},
			SuspendedProcesses: api.SuspendedProcesses{{ProcessName: new(api.XmlStringMaxLen255("AZRebalance")), SuspensionReason: new(api.XmlStringMaxLen255("user suspended"))}},
			TrafficSources:     api.TrafficSources{{Identifier: new(api.XmlStringMaxLen511("arn:targetgroup/web")), Type: new(api.XmlStringMaxLen511("elbv2"))}},
		},
	}
}

func requireEqual[T any](t *testing.T, label string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s lost durable state:\n got %#v\nwant %#v", label, got, want)
	}
}

func TestRecoveryIntentSurvivesReopenAndGroupIncarnation(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository, _ journal.Storage, reopen func() domain.Repository) {
		group := fixtureGroup()
		now := group.ReconcileAt
		admitted := api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-workers")), LaunchTemplateName: new(api.LaunchTemplateName("workers")), Version: new(api.XmlStringMaxLen255("7"))}
		member := domain.InstanceRecord{Group: group.Key, GroupID: group.ID, JoinedAt: now, InServiceAt: now.Add(time.Minute), WarmUntil: now.Add(77 * time.Second), ActivityID: "launch-1", TerminationRequested: true, DetachRequested: true,
			HealthCheckGraceIgnored: true,
			Data:                    api.Instance{InstanceId: new(api.XmlStringMaxLen19("i-worker")), AvailabilityZone: new(api.XmlStringMaxLen255("us-east-1b")), AvailabilityZoneId: new(api.XmlStringMaxLen255("use1-az2")), ImageId: new(api.XmlStringMaxLen255("ami-guest")), InstanceType: new(api.XmlStringMaxLen255("t3.micro")), LaunchTemplate: &admitted, LifecycleState: new(api.LifecycleState("Terminating:Wait")), HealthStatus: new(api.XmlStringMaxLen32("Healthy")), ProtectedFromScaleIn: new(api.InstanceProtected(true))}}
		activity := domain.ActivityRecord{Key: domain.ActivityKey{Scope: group.Key.Scope, ID: "launch-1"}, Group: group.Key, GroupID: group.ID, Kind: "launch", SubnetID: "subnet-b", LaunchTemplate: admitted, OriginEventID: "create-workers", RetryAt: now.Add(13 * time.Second),
			InstanceWarmup:       new(int32(17)),
			LaunchTags:           api.TagDescriptionList{{Key: new(api.TagKey("owner")), Value: new(api.TagValue("launch-generation")), ResourceId: new(api.XmlString(group.Key.Name)), ResourceType: new(api.XmlString("auto-scaling-group")), PropagateAtLaunch: new(api.PropagateAtLaunch(true))}},
			ProtectedFromScaleIn: true,
			Data:                 api.Activity{ActivityId: new(api.XmlString("launch-1")), AutoScalingGroupName: group.Data.AutoScalingGroupName, AutoScalingGroupARN: group.Data.AutoScalingGroupARN, StartTime: &now, StatusCode: new(api.ScalingActivityStatusCode("InProgress")), Cause: new(api.XmlStringMaxLen1023("desired capacity increased")), Progress: new(api.Progress(30))}}
		policy := domain.PolicyRecord{Key: domain.PolicyKey{GroupKey: group.Key, Name: "requests"}, GroupID: group.ID, LastScaleAt: now,
			Data: api.ScalingPolicy{PolicyName: new(api.XmlStringMaxLen255("requests")), PolicyType: new(api.XmlStringMaxLen64("TargetTrackingScaling")), Enabled: new(api.ScalingPolicyEnabled(true)), EstimatedInstanceWarmup: new(api.EstimatedInstanceWarmup(17)), Alarms: api.Alarms{{AlarmName: new(api.XmlStringMaxLen255("requests-high")), AlarmARN: new(api.ResourceName("arn:alarm:requests-high"))}},
				TargetTrackingConfiguration: &api.TargetTrackingConfiguration{TargetValue: new(api.MetricScale(10)), DisableScaleIn: new(api.DisableScaleIn(false)), CustomizedMetricSpecification: &api.CustomizedMetricSpecification{MetricName: new(api.MetricName("QueueDepth")), Namespace: new(api.MetricNamespace("Workers")), Statistic: new(api.MetricStatistic("Average")), Period: new(api.MetricGranularityInSeconds(60)), Dimensions: api.MetricDimensions{{Name: new(api.MetricDimensionName("Queue")), Value: new(api.MetricDimensionValue("jobs"))}}}}}}
		schedule := domain.ScheduleRecord{Key: domain.ScheduleKey{GroupKey: group.Key, Name: "morning"}, GroupID: group.ID, NextDue: now.Add(time.Hour), OriginEventID: "put-morning", Data: api.ScheduledUpdateGroupAction{ScheduledActionName: new(api.XmlStringMaxLen255("morning")), DesiredCapacity: new(api.AutoScalingGroupDesiredCapacity(3)), Recurrence: new(api.XmlStringMaxLen255("0 9 * * *")), TimeZone: new(api.XmlStringMaxLen255("America/New_York")), StartTime: &now}}
		hook := domain.HookRecord{Key: domain.HookKey{GroupKey: group.Key, Name: "drain"}, GroupID: group.ID, Data: api.LifecycleHook{LifecycleHookName: new(api.AsciiStringMaxLen255("drain")), AutoScalingGroupName: group.Data.AutoScalingGroupName, LifecycleTransition: new(api.LifecycleTransition("autoscaling:EC2_INSTANCE_TERMINATING")), DefaultResult: new(api.LifecycleActionResult("ABANDON")), HeartbeatTimeout: new(api.HeartbeatTimeout(120)), GlobalTimeout: new(api.GlobalTimeout(12000)), NotificationMetadata: new(api.AnyPrintableAsciiStringMaxLen4000("drain queues"))}}
		action := domain.LifecycleAction{Group: group.Key, GroupID: group.ID, Token: "token-1", HookName: "drain", InstanceID: "i-worker", Transition: "autoscaling:EC2_INSTANCE_TERMINATING", DefaultResult: "ABANDON", HeartbeatTimeout: 120 * time.Second, Deadline: now.Add(120 * time.Second), GlobalDeadline: now.Add(12000 * time.Second), OriginEventID: "terminate-worker"}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			for _, put := range []func() error{func() error { return tx.PutGroup(group) }, func() error { return tx.PutInstance(member) }, func() error { return tx.PutActivity(activity) }, func() error { return tx.PutPolicy(policy) }, func() error { return tx.PutSchedule(schedule) }, func() error { return tx.PutHook(hook) }, func() error { return tx.PutLifecycleAction(action) }} {
				if err := put(); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		repo = reopen()
		if err := repo.View(t.Context(), func(r domain.Reader) error {
			g, err := r.Group(group.Key)
			if err != nil {
				return err
			}
			requireEqual(t, "group", g, group)
			i, err := r.Instance(group.Key.Scope, "i-worker")
			if err != nil {
				return err
			}
			requireEqual(t, "membership", i, member)
			a, err := r.Activity(activity.Key)
			if err != nil {
				return err
			}
			requireEqual(t, "frozen launch intent", a, activity)
			p, err := r.Policy(policy.Key)
			if err != nil {
				return err
			}
			requireEqual(t, "policy cooldown and metrics", p, policy)
			s, err := r.Schedule(schedule.Key)
			if err != nil {
				return err
			}
			requireEqual(t, "scheduled action", s, schedule)
			h, err := r.Hook(hook.Key)
			if err != nil {
				return err
			}
			requireEqual(t, "lifecycle hook", h, hook)
			actions, err := r.PendingLifecycleActions()
			if err != nil {
				return err
			}
			requireEqual(t, "lifecycle deadlines", actions, []domain.LifecycleAction{action})
			work, err := r.PendingGroups()
			if err != nil {
				return err
			}
			requireEqual(t, "reconcile fencing", work, []domain.GroupWork{{Key: group.Key, ID: group.ID, Version: math.MaxUint64, Due: now, MetricAt: group.MetricAt, Deleting: group.Deleting}})
			schedules, err := r.PendingSchedules()
			if err != nil {
				return err
			}
			requireEqual(t, "scheduled recovery", schedules, []domain.ScheduleRecord{schedule})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.DeleteGroup(group.Key); err != nil {
				return err
			}
			group.ID = "incarnation-second"
			group.Data.LaunchTemplate.Version = new(api.XmlStringMaxLen255("12"))
			group.Data.Tags = api.TagDescriptionList{{Key: new(api.TagKey("owner")), Value: new(api.TagValue("replacement-generation")), PropagateAtLaunch: new(api.PropagateAtLaunch(true))}}
			return tx.PutGroup(group)
		}); err != nil {
			t.Fatal(err)
		}
		repo = reopen()
		if err := repo.View(t.Context(), func(r domain.Reader) error {
			if _, err := r.Instance(group.Key.Scope, "i-worker"); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("deleted group kept membership: %v", err)
			}
			if _, err := r.Policy(policy.Key); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("deleted group kept policy: %v", err)
			}
			if _, err := r.Schedule(schedule.Key); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("deleted group kept schedule: %v", err)
			}
			if _, err := r.Hook(hook.Key); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("deleted group kept hook: %v", err)
			}
			actions, err := r.LifecycleActions(group.Key)
			if err != nil {
				return err
			}
			if len(actions) != 0 {
				t.Fatalf("old lifecycle tokens crossed incarnation: %#v", actions)
			}
			visible, err := r.Activities(group.Key.Scope, group.Key.Name, false)
			if err != nil {
				return err
			}
			if len(visible) != 0 {
				t.Fatalf("old activities became current: %#v", visible)
			}
			history, err := r.Activities(group.Key.Scope, group.Key.Name, true)
			if err != nil {
				return err
			}
			requireEqual(t, "deleted-group history and launch selection", history, []domain.ActivityRecord{activity})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAttemptAndAuditRollbackShareDomain(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository, events journal.Storage, _ func() domain.Repository) {
		original := fixtureGroup()
		appendEvent := func(ctx context.Context, id string) error {
			return events.AppendAPICallCompleted(ctx, journal.Envelope{At: original.ReconcileAt, Partition: original.Key.Partition, AccountID: original.Key.AccountID, Region: original.Key.Region}, journal.APICallCompleted{EventID: id, EventSource: "autoscaling.amazonaws.com", EventName: "SetDesiredCapacity", Category: journal.CategoryManagement})
		}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := tx.PutGroup(original); err != nil {
				return err
			}
			return appendEvent(tx.Context(), "original")
		}); err != nil {
			t.Fatal(err)
		}
		changed := original
		changed.Data = api.CloneAutoScalingGroup(original.Data)
		changed.Data.DesiredCapacity = new(api.AutoScalingGroupDesiredCapacity(3))
		changed.ReconcileCause = "manual desired-capacity change"
		changed.PendingInstanceWarmup = nil
		changed.MetricAt = time.Time{}
		changed.Data.Tags = nil
		changed.Data.TargetGroupARNs = api.TargetGroupARNs{}
		changed.Data.CapacityReservationSpecification = nil
		rejected := errors.New("reject scale")
		stage := func(tx domain.Transaction) error {
			if err := tx.PutGroup(changed); err != nil {
				return err
			}
			return appendEvent(tx.Context(), "changed")
		}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			if err := repo.Attempt(tx.Context(), func(child domain.Transaction) error {
				if err := stage(child); err != nil {
					return err
				}
				return rejected
			}); !errors.Is(err, rejected) {
				t.Fatalf("savepoint result: %v", err)
			}
			got, err := tx.Group(original.Key)
			if err != nil {
				return err
			}
			requireEqual(t, "failed attempt", got, original)
			if err := repo.Attempt(tx.Context(), stage); err != nil {
				return err
			}
			got, err = tx.Group(original.Key)
			if err != nil {
				return err
			}
			requireEqual(t, "accepted attempt", got, changed)
			return rejected
		}); !errors.Is(err, rejected) {
			t.Fatalf("outer rollback: %v", err)
		}
		if err := repo.View(t.Context(), func(r domain.Reader) error {
			got, err := r.Group(original.Key)
			if err != nil {
				return err
			}
			requireEqual(t, "outer rollback", got, original)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		gotEvents, err := events.Read(t.Context(), 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(gotEvents) != 1 || gotEvents[0].APICallCompleted.EventID != "original" {
			t.Fatalf("rolled-back audit escaped: %#v", gotEvents)
		}
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return repo.Attempt(tx.Context(), stage) }); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r domain.Reader) error {
			got, err := r.Group(original.Key)
			if err != nil {
				return err
			}
			requireEqual(t, "accepted replacement removes stale child fields", got, changed)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		gotEvents, err = events.Read(t.Context(), 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(gotEvents) != 2 || gotEvents[1].APICallCompleted.EventID != "changed" {
			t.Fatalf("accepted audit missing: %#v", gotEvents)
		}
	})
}

func TestScopeCursorAndActivityRetentionBoundaries(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository, _ journal.Storage, _ func() domain.Repository) {
		original := fixtureGroup()
		keys := []domain.GroupKey{original.Key, original.Key, original.Key, original.Key, original.Key}
		keys[0].Name = "alpha"
		keys[1].Name = "beta"
		keys[2].Name = "gamma"
		keys[3].AccountID = "222222222222"
		keys[4].Region = "us-west-2"
		cutoff := original.ReconcileAt.Add(time.Hour)
		expired := cutoff.Add(-time.Nanosecond)
		if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
			for _, index := range []int{4, 2, 0, 3, 1} {
				g := original
				g.Key = keys[index]
				if err := tx.PutGroup(g); err != nil {
					return err
				}
			}
			for index, end := range []*time.Time{&expired, &cutoff, nil} {
				id := []string{"expired", "boundary", "pending"}[index]
				a := domain.ActivityRecord{Key: domain.ActivityKey{Scope: original.Key.Scope, ID: id}, Group: keys[0], GroupID: original.ID, Data: api.Activity{StartTime: &original.ReconcileAt, EndTime: end}}
				if err := tx.PutActivity(a); err != nil {
					return err
				}
			}
			a := domain.ActivityRecord{Key: domain.ActivityKey{Scope: keys[3].Scope, ID: "expired"}, Group: keys[3], GroupID: original.ID, Data: api.Activity{StartTime: &original.ReconcileAt, EndTime: &expired}}
			if err := tx.PutActivity(a); err != nil {
				return err
			}
			return tx.DeleteActivitiesBefore(original.Key.Scope, cutoff)
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r domain.Reader) error {
			groups, err := r.Groups(domain.GroupQuery{Scope: original.Key.Scope, Names: []string{"gamma", "alpha", "beta", "alpha"}, After: "alpha", Limit: 1})
			if err != nil {
				return err
			}
			if len(groups) != 1 || groups[0].Key != keys[1] {
				t.Fatalf("scope/filter/cursor precedence: %#v", groups)
			}
			groups, err = r.Groups(domain.GroupQuery{Scope: original.Key.Scope, After: "beta", Limit: 1})
			if err != nil {
				return err
			}
			if len(groups) != 1 || groups[0].Key != keys[2] {
				t.Fatalf("cursor did not advance: %#v", groups)
			}
			if _, err := r.Activity(domain.ActivityKey{Scope: original.Key.Scope, ID: "expired"}); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("completed history before cutoff survived: %v", err)
			}
			for _, id := range []string{"boundary", "pending"} {
				if _, err := r.Activity(domain.ActivityKey{Scope: original.Key.Scope, ID: id}); err != nil {
					return err
				}
			}
			if _, err := r.Activity(domain.ActivityKey{Scope: keys[3].Scope, ID: "expired"}); err != nil {
				t.Fatalf("retention crossed account: %v", err)
			}
			foreign := original.Key
			foreign.Partition = "aws-cn"
			if _, err := r.Group(foreign); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("lookup crossed partition: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
