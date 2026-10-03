package autoscaling

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/autoscaling"
	ec2api "stackd/internal/awsapi/ec2"
	elbapi "stackd/internal/awsapi/elbv2"
	"stackd/internal/services/elbv2"
)

func transitionMember(g GroupRecord, id, lifecycle string, now time.Time) InstanceRecord {
	return InstanceRecord{Group: g.Key, GroupID: g.ID, JoinedAt: now, InServiceAt: now, Data: api.Instance{InstanceId: new(api.XmlStringMaxLen19(id)), LifecycleState: new(api.LifecycleState(lifecycle)), HealthStatus: new(api.XmlStringMaxLen32("Healthy"))}}
}

func transitionObservation(id, state string, healthy bool) InstanceObservation {
	return InstanceObservation{Instance: ec2api.Instance{InstanceId: new(ec2api.String(id)), State: &ec2api.InstanceState{Name: new(ec2api.InstanceStateName(state))}}, Healthy: healthy}
}

func storeTransition(t *testing.T, s *Service, ctx context.Context, g GroupRecord, m InstanceRecord) {
	t.Helper()
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutGroup(g); err != nil {
			return err
		}
		return tx.PutInstance(m)
	}); err != nil {
		t.Fatal(err)
	}
}

func readTransition(t *testing.T, s *Service, ctx context.Context, g GroupRecord, id string) InstanceRecord {
	t.Helper()
	var m InstanceRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		m, err = r.Instance(g.Key.Scope, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return m
}

// AWS documents Terminate as disabling ReplaceUnhealthy, not HealthCheck, and
// both Launch and Terminate as blocking maximum-lifetime replacement.
func TestSuspendedProcessesReplacementAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, process string
		lifetime      bool
	}{
		{"unhealthy-terminate", "Terminate", false},
		{"lifetime-terminate", "Terminate", true},
		{"lifetime-launch", "Launch", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, ctx, g, source, _ := ownedControlService(t)
			g.Data.SuspendedProcesses = api.SuspendedProcesses{{ProcessName: new(api.XmlStringMaxLen255(tc.process))}}
			number(&g.Data.DesiredCapacity, 1)
			m := transitionMember(g, "i-replacement", "InService", source.Now())
			s.instances = transitionInstances{healthy: new(tc.lifetime)}
			if tc.lifetime {
				number(&g.Data.MaxInstanceLifetime, 86400)
				m.JoinedAt = source.Now().Add(-24 * time.Hour)
			}
			storeTransition(t, s, ctx, g, m)
			if _, err := s.runGroup(ctx, g.Key, g.ID); err != nil {
				t.Fatal(err)
			}
			m = readTransition(t, s, ctx, g, value(m.Data.InstanceId))
			if m.TerminationRequested || value(m.Data.LifecycleState) != "InService" {
				t.Fatalf("%s suspension admitted automatic replacement: %+v", tc.process, m)
			}
			if !tc.lifetime && value(m.Data.HealthStatus) != "Unhealthy" {
				t.Fatal("Terminate suspension also stopped health marking")
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.resumeProcesses(ctx, tx, &api.ResumeProcessesInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, ScalingProcesses: api.ProcessNames{api.XmlStringMaxLen255(tc.process)}})
				if err != nil {
					return err
				}
				g, err = tx.Group(g.Key)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.runGroup(ctx, g.Key, g.ID); err != nil {
				t.Fatal(err)
			}
			m = readTransition(t, s, ctx, g, value(m.Data.InstanceId))
			if !m.TerminationRequested {
				t.Fatalf("resume did not admit replacement: %+v", m)
			}
		})
	}
}

func TestMaximumLifetimeWaitsForReplacementCapacity(t *testing.T) {
	for _, state := range []string{"terminating", "absent", "Pending", "warming", "Unhealthy", "ready"} {
		t.Run(state, func(t *testing.T) {
			s, ctx, g, source, _ := ownedControlService(t)
			g.Data.SuspendedProcesses = nil
			number(&g.Data.DesiredCapacity, 2)
			number(&g.Data.MaxInstanceLifetime, 86400)
			expired := transitionMember(g, "i-expired", "InService", source.Now())
			expired.JoinedAt = source.Now().Add(-24 * time.Hour)
			members := []InstanceRecord{expired}
			if state != "absent" {
				replacement := transitionMember(g, "i-replacement", "InService", source.Now())
				switch state {
				case "terminating":
					retiring := transitionMember(g, "i-retiring", "Terminating:Wait", source.Now())
					retiring.TerminationRequested = true
					members = append(members, retiring)
				case "Pending":
					text(&replacement.Data.LifecycleState, "Pending")
				case "warming":
					replacement.WarmUntil = source.Now().Add(time.Hour)
				case "Unhealthy":
					text(&replacement.Data.HealthStatus, "Unhealthy")
				}
				members = append(members, replacement)
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutGroup(g); err != nil {
					return err
				}
				for _, member := range members {
					if err := tx.PutInstance(member); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				var err error
				members, err = r.Instances(g.Key)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.reconcileExpiredInstances(ctx, g, members); err != nil {
				t.Fatal(err)
			}
			expired = readTransition(t, s, ctx, g, value(expired.Data.InstanceId))
			if expired.TerminationRequested != (state == "ready") {
				t.Fatalf("replacement state %s: expired member termination=%v", state, expired.TerminationRequested)
			}
		})
	}
}

func TestSuspendedTerminateAllowsAdmittedAndManualTermination(t *testing.T) {
	for _, mode := range []string{"admitted", "manual", "force-delete", "pending-failure"} {
		t.Run(mode, func(t *testing.T) {
			s, ctx, g, source, _ := ownedControlService(t)
			g.Data.SuspendedProcesses = nil
			m := transitionMember(g, "i-termination", "InService", source.Now())
			if mode == "pending-failure" {
				text(&m.Data.LifecycleState, "Pending")
			}
			storeTransition(t, s, ctx, g, m)
			if mode == "force-delete" || mode == "pending-failure" {
				if err := s.repository.Update(ctx, func(tx Transaction) error {
					activity := s.newActivity(g, "launch", "fixture launch")
					activity.InstanceID = value(m.Data.InstanceId)
					if mode == "force-delete" {
						if err := s.finishActivity(ctx, tx, g, activity, nil); err != nil {
							return err
						}
					} else if err := tx.PutActivity(activity); err != nil {
						return err
					}
					m.ActivityID = activity.Key.ID
					return tx.PutInstance(m)
				}); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "admitted" {
				if _, err := s.reconcileInstance(ctx, g, m, transitionObservation(value(m.Data.InstanceId), "running", false), true); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.suspendProcesses(ctx, tx, &api.SuspendProcessesInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, ScalingProcesses: api.ProcessNames{"Terminate"}})
				if err != nil {
					return err
				}
				switch mode {
				case "manual":
					_, err = s.terminateInstanceInAutoScalingGroup(ctx, tx, &api.TerminateInstanceInAutoScalingGroupInput{InstanceId: m.Data.InstanceId})
				case "force-delete":
					_, err = s.deleteAutoScalingGroup(ctx, tx, &api.DeleteAutoScalingGroupInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, ForceDelete: new(api.ForceDelete(true))})
				}
				if err != nil {
					return err
				}
				g, err = tx.Group(g.Key)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			state := "running"
			if mode == "pending-failure" {
				state = "stopped"
			}
			for range 3 {
				m = readTransition(t, s, ctx, g, value(m.Data.InstanceId))
				if value(m.Data.LifecycleState) == "Terminating:Proceed" {
					break
				}
				if _, err := s.reconcileInstance(ctx, g, m, transitionObservation(value(m.Data.InstanceId), state, true), true); err != nil {
					t.Fatal(err)
				}
			}
			m = readTransition(t, s, ctx, g, value(m.Data.InstanceId))
			if !m.TerminationRequested || value(m.Data.LifecycleState) != "Terminating:Proceed" {
				t.Fatalf("Terminate suspension halted %s termination: %+v", mode, m)
			}
		})
	}
}

func TestSuspendedHealthCheckPreservesManualReplacement(t *testing.T) {
	for _, state := range []string{"running", "stopped", "stopping", "shutting-down"} {
		t.Run(state, func(t *testing.T) {
			s, ctx, g, source, _ := ownedControlService(t)
			g.Data.SuspendedProcesses = api.SuspendedProcesses{{ProcessName: new(api.XmlStringMaxLen255("HealthCheck"))}}
			m := transitionMember(g, "i-health", "InService", source.Now())
			storeTransition(t, s, ctx, g, m)
			observation := transitionObservation(value(m.Data.InstanceId), state, false)
			if _, err := s.reconcileInstance(ctx, g, m, observation, true); err != nil {
				t.Fatal(err)
			}
			m = readTransition(t, s, ctx, g, value(m.Data.InstanceId))
			if value(m.Data.HealthStatus) != "Healthy" || m.TerminationRequested {
				t.Fatalf("suspended HealthCheck marked %s instance unhealthy: %+v", state, m)
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.setInstanceHealth(ctx, tx, &api.SetInstanceHealthInput{InstanceId: m.Data.InstanceId, HealthStatus: new(api.XmlStringMaxLen32("Unhealthy")), ShouldRespectGracePeriod: new(api.ShouldRespectGracePeriod(false))})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			m = readTransition(t, s, ctx, g, value(m.Data.InstanceId))
			if _, err := s.reconcileInstance(ctx, g, m, observation, true); err != nil {
				t.Fatal(err)
			}
			m = readTransition(t, s, ctx, g, value(m.Data.InstanceId))
			if !m.TerminationRequested {
				t.Fatalf("HealthCheck suspension suppressed explicit unhealthy replacement for %s", state)
			}
		})
	}
}

// Network observations are fixture inputs; target registration and ownership are
// handled by the real ELB service and typed target repository.
type transitionNetwork struct{ elbv2.NetworkAuthority }

func (transitionNetwork) ResolveTarget(_ context.Context, scope elbv2.Scope, _, _, id string) (elbv2.TargetEndpoint, error) {
	return elbv2.TargetEndpoint{Address: "10.0.0.8", AvailabilityZone: "us-east-1a", InterfaceID: "eni-member", OwnerARN: "arn:" + scope.Partition + ":ec2:" + scope.Region + ":" + scope.AccountID + ":instance/" + id, Incarnation: id}, nil
}

type transitionTargets struct {
	TargetGroups
	service *elbv2.Service
	scope   elbv2.Scope
}

func (a transitionTargets) Register(ctx context.Context, group, target, id string) error {
	return a.service.RegisterOwnedTarget(ctx, a.scope, target, elbapi.TargetDescription{Id: new(elbapi.TargetId(id))}, group, id)
}

func TestAddToLoadBalancerResumeDoesNotBackfill(t *testing.T) {
	s, ctx, g, source, _ := ownedControlService(t)
	g.Data.SuspendedProcesses = api.SuspendedProcesses{{ProcessName: new(api.XmlStringMaxLen255("AddToLoadBalancer"))}}
	scope := elbv2.Scope{Partition: g.Key.Partition, AccountID: g.Key.AccountID, Region: g.Key.Region}
	target := "arn:aws:elasticloadbalancing:us-east-1:" + g.Key.AccountID + ":targetgroup/workers/1234567890123456"
	g.Data.TargetGroupARNs = api.TargetGroupARNs{api.XmlStringMaxLen511(target)}
	targets := elbv2.NewMemoryRepository(nil)
	owner := elbv2.New(elbv2.Config{Repository: targets, Clock: source, Networks: transitionNetwork{}})
	t.Cleanup(func() { owner.Close() })
	if err := targets.Update(ctx, func(tx elbv2.Transaction) error {
		return tx.PutTargetGroup(elbv2.TargetGroupRecord{Scope: scope, Data: elbapi.TargetGroup{TargetGroupArn: new(elbapi.TargetGroupArn(target)), VpcId: new(elbapi.VpcId("vpc-members")), TargetType: new(elbapi.TargetTypeEnum("instance")), Port: new(elbapi.Port(80))}})
	}); err != nil {
		t.Fatal(err)
	}
	s.targetGroups = transitionTargets{service: owner, scope: scope}
	admit := func(id string) InstanceRecord {
		m := transitionMember(g, id, "Pending:Proceed", source.Now())
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			a := s.newActivity(g, "launch", "fixture launch")
			a.InstanceID = id
			m.ActivityID = a.Key.ID
			if err := tx.PutActivity(a); err != nil {
				return err
			}
			if err := tx.PutGroup(g); err != nil {
				return err
			}
			return tx.PutInstance(m)
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.reconcileInstance(ctx, g, m, transitionObservation(id, "running", true), true); err != nil {
			t.Fatal(err)
		}
		m = readTransition(t, s, ctx, g, id)
		if value(m.Data.LifecycleState) != "InService" {
			t.Fatalf("launch did not enter service: %+v", m)
		}
		return m
	}
	first := admit("i-suspended")
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.resumeProcesses(ctx, tx, &api.ResumeProcessesInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, ScalingProcesses: api.ProcessNames{"AddToLoadBalancer"}})
		if err != nil {
			return err
		}
		g, err = tx.Group(g.Key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reconcileInstance(ctx, g, first, transitionObservation(value(first.Data.InstanceId), "running", true), true); err != nil {
		t.Fatal(err)
	}
	second := admit("i-resumed")
	if err := targets.View(ctx, func(r elbv2.Reader) error {
		if _, err := r.Target(scope, target, value(first.Data.InstanceId), 80); !errors.Is(err, elbv2.ErrNotFound) {
			t.Fatalf("resumption retroactively registered suspended launch: %v", err)
		}
		registered, err := r.Target(scope, target, value(second.Data.InstanceId), 80)
		if err == nil && (registered.OwnerARN != g.Key.ARN(g.ID) || registered.Incarnation != value(second.Data.InstanceId)) {
			t.Fatalf("new launch registered with wrong ownership: %+v", registered)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// These observations bound controller behavior without running a guest.
// Assertions inspect committed state rather than dependency calls.
type transitionInstances struct {
	Instances
	healthy *bool
}

func (v transitionInstances) Observe(_ context.Context, ids []string) ([]InstanceObservation, error) {
	out := make([]InstanceObservation, len(ids))
	for i, id := range ids {
		out[i] = transitionObservation(id, "running", v.healthy == nil || *v.healthy)
		out[i].Instance.VpcId = new(ec2api.String("vpc-members"))
		out[i].Instance.Placement = &ec2api.Placement{AvailabilityZone: new(ec2api.String("us-east-1a"))}
	}
	return out, nil
}
func (transitionInstances) Placement(context.Context, []string, []string) ([]ec2api.Subnet, error) {
	return []ec2api.Subnet{{VpcId: new(ec2api.String("vpc-members"))}}, nil
}
func (transitionInstances) SetGroup(context.Context, string, string) error { return nil }

func TestLaunchSuspensionRejectsMembershipAdmission(t *testing.T) {
	for _, action := range []string{"attach", "exit-standby"} {
		t.Run(action, func(t *testing.T) {
			s, ctx, g, source, _ := ownedControlService(t)
			s.instances = transitionInstances{}
			g.Data.AvailabilityZones = api.AvailabilityZones{"us-east-1a"}
			text(&g.Data.VPCZoneIdentifier, "subnet-members")
			m := transitionMember(g, "i-membership", "Standby", source.Now())
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutGroup(g); err != nil {
					return err
				}
				if action == "exit-standby" {
					return tx.PutInstance(m)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			apply := func(tx Transaction) error {
				if action == "attach" {
					_, err := s.attachInstances(ctx, tx, &api.AttachInstancesInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, InstanceIds: api.InstanceIds{*m.Data.InstanceId}})
					return err
				}
				_, err := s.exitStandby(ctx, tx, &api.ExitStandbyInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, InstanceIds: api.InstanceIds{*m.Data.InstanceId}})
				return err
			}
			err := s.repository.Update(ctx, apply)
			if err == nil || wireError(err).Code != "ValidationError" {
				t.Errorf("Launch-suspended %s error=%v; want ValidationError", action, err)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				stored, err := r.Group(g.Key)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(stored, g) {
					t.Errorf("rejected %s changed group capacity or reconciliation state", action)
				}
				member, err := r.Instance(g.Key.Scope, value(m.Data.InstanceId))
				if action == "attach" {
					if !errors.Is(err, ErrNotFound) {
						t.Errorf("rejected attachment retained membership: %+v %v", member, err)
					}
				} else if err != nil || !reflect.DeepEqual(member, m) {
					t.Errorf("rejected exit changed Standby member: %+v %v", member, err)
				}
				activities, err := r.Activities(g.Key.Scope, g.Key.Name, false)
				if err == nil && len(activities) != 0 {
					t.Errorf("rejected %s retained scaling activity: %+v", action, activities)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if t.Failed() {
				return
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.resumeProcesses(ctx, tx, &api.ResumeProcessesInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, ScalingProcesses: api.ProcessNames{"Launch"}})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.Update(ctx, apply); err != nil {
				t.Fatal(err)
			}
			member := readTransition(t, s, ctx, g, value(m.Data.InstanceId))
			if value(member.Data.LifecycleState) != "Pending" {
				t.Fatalf("resumed %s failed to admit membership: %+v", action, member)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				current, err := r.Group(g.Key)
				if err == nil && (intValue(current.Data.DesiredCapacity) != 3 || current.ScaleUpVersion != 1) {
					t.Fatalf("%s did not atomically increase capacity and ownership: desired=%d counter=%d", action, intValue(current.Data.DesiredCapacity), current.ScaleUpVersion)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
