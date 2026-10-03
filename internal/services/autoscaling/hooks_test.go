package autoscaling

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awswire"
)

type hookTestEvents struct{ tokens map[string]string }

func (e *hookTestEvents) Publish(_ context.Context, _ GroupRecord, _ string, payload []byte) error {
	var detail struct{ LifecycleHookName, LifecycleActionToken string }
	if err := json.Unmarshal(payload, &detail); err != nil {
		return err
	}
	e.tokens[detail.LifecycleHookName] = detail.LifecycleActionToken
	return nil
}
func (*hookTestEvents) Notify(context.Context, HookRecord, []byte) error {
	return invalid("No notification target is configured in this fixture")
}

func TestLifecycleHeartbeatExpiryAndMultiHookBarrier(t *testing.T) {
	s, ctx, g, source, _ := ownedControlService(t)
	events := &hookTestEvents{tokens: map[string]string{}}
	s.events = events
	id := "i-lifecycle"
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutInstance(InstanceRecord{Group: g.Key, GroupID: g.ID, Data: api.Instance{InstanceId: new(api.XmlStringMaxLen19(id)), LifecycleState: new(api.LifecycleState("Pending"))}}); err != nil {
			return err
		}
		for _, name := range []string{"prepare", "observe"} {
			if err := s.installLifecycleHook(ctx, tx, g, api.LifecycleHookSpecification{LifecycleHookName: new(api.AsciiStringMaxLen255(name)), LifecycleTransition: new(api.LifecycleTransition(launchTransition)), HeartbeatTimeout: new(api.HeartbeatTimeout(30)), DefaultResult: new(api.LifecycleActionResult("ABANDON"))}); err != nil {
				return err
			}
		}
		waiting, err := s.beginLifecycleHooks(ctx, tx, g, id, launchTransition)
		if err == nil && !waiting {
			t.Fatal("launch did not enter its hook barrier")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	initial := source.Now()
	if err := source.Advance(20 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.recordLifecycleActionHeartbeat(ctx, tx, &api.RecordLifecycleActionHeartbeatInput{AutoScalingGroupName: new(api.ResourceName(g.Key.Name)), LifecycleHookName: new(api.AsciiStringMaxLen255("prepare")), LifecycleActionToken: new(api.LifecycleActionToken(events.tokens["prepare"]))})
		if err != nil {
			return err
		}
		_, err = s.completeLifecycleAction(ctx, tx, &api.CompleteLifecycleActionInput{AutoScalingGroupName: new(api.ResourceName(g.Key.Name)), LifecycleHookName: new(api.AsciiStringMaxLen255("observe")), LifecycleActionToken: new(api.LifecycleActionToken(events.tokens["observe"])), LifecycleActionResult: new(api.LifecycleActionResult("CONTINUE"))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		instance, err := r.Instance(g.Key.Scope, id)
		if err != nil {
			return err
		}
		if value(instance.Data.LifecycleState) != "Pending:Wait" {
			t.Fatal("one CONTINUE bypassed another outstanding hook")
		}
		actions, err := r.LifecycleActions(g.Key)
		if err == nil && (len(actions) != 1 || !actions[0].Deadline.Equal(initial.Add(50*time.Second)) || !actions[0].GlobalDeadline.Equal(initial.Add(3000*time.Second))) {
			t.Fatalf("heartbeat moved the wrong deadlines: %+v", actions)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.recordLifecycleActionHeartbeat(ctx, tx, &api.RecordLifecycleActionHeartbeatInput{AutoScalingGroupName: new(api.ResourceName(g.Key.Name)), LifecycleHookName: new(api.AsciiStringMaxLen255("prepare")), InstanceId: new(api.XmlStringMaxLen19(id))})
		return err
	})
	if err == nil {
		t.Fatal("heartbeat revived an action at its deadline")
	}
	jobs := lifecycleJobs{s}
	job, found, err := jobs.Next(ctx)
	if err != nil || !found {
		t.Fatalf("expiry selection=%v,%v", found, err)
	}
	if err = jobs.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err = s.repository.View(ctx, func(r Reader) error {
		instance, err := r.Instance(g.Key.Scope, id)
		if err != nil {
			return err
		}
		if !instance.TerminationRequested || value(instance.Data.LifecycleState) != "Pending:Proceed" {
			t.Fatalf("expired ABANDON did not request real termination: %+v", instance)
		}
		actions, err := r.LifecycleActions(g.Key)
		if err == nil && len(actions) != 0 {
			t.Fatal("expired action remained completable")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeLifecycleRejectsMissingAction(t *testing.T) {
	s, ctx, g, _, _ := ownedControlService(t)
	var put api.PutLifecycleHookInput
	if err := json.Unmarshal(nativeControl(t, "put-launch-hook").Input, &put); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return s.storeLifecycleHook(ctx, tx, g, &put) }); err != nil {
		t.Fatal(err)
	}
	call := nativeControl(t, "heartbeat-no-action")
	var input api.RecordLifecycleActionHeartbeatInput
	if err := json.Unmarshal(call.Input, &input); err != nil {
		t.Fatal(err)
	}
	err := s.repository.Update(ctx, func(tx Transaction) error { _, err := s.recordLifecycleActionHeartbeat(ctx, tx, &input); return err })
	if err == nil || wireError(err).Code != call.Code {
		t.Fatalf("missing action error=%v, native code=%s", err, call.Code)
	}
}

func TestDeletingHookAbandonsLaunchButContinuesTermination(t *testing.T) {
	for _, transition := range []string{launchTransition, terminateTransition} {
		t.Run(transition, func(t *testing.T) {
			s, ctx, g, _, _ := ownedControlService(t)
			s.events = &hookTestEvents{tokens: map[string]string{}}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutInstance(InstanceRecord{Group: g.Key, GroupID: g.ID, Data: api.Instance{InstanceId: new(api.XmlStringMaxLen19("i-delete")), LifecycleState: new(api.LifecycleState("Pending"))}}); err != nil {
					return err
				}
				if err := s.installLifecycleHook(ctx, tx, g, api.LifecycleHookSpecification{LifecycleHookName: new(api.AsciiStringMaxLen255("remove/me")), LifecycleTransition: new(api.LifecycleTransition(transition))}); err != nil {
					return err
				}
				if _, err := s.beginLifecycleHooks(ctx, tx, g, "i-delete", transition); err != nil {
					return err
				}
				_, err := s.deleteLifecycleHook(ctx, tx, &api.DeleteLifecycleHookInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, LifecycleHookName: new(api.AsciiStringMaxLen255("remove/me"))})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				instance, err := r.Instance(g.Key.Scope, "i-delete")
				if err != nil {
					return err
				}
				if instance.TerminationRequested != (transition == launchTransition) {
					t.Fatalf("hook deletion termination request=%v for %s", instance.TerminationRequested, transition)
				}
				state := "Pending:Proceed"
				if transition == terminateTransition {
					state = "Terminating:Proceed"
				}
				if value(instance.Data.LifecycleState) != state {
					t.Fatalf("lifecycle state=%s want %s", value(instance.Data.LifecycleState), state)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.deleteLifecycleHook(ctx, tx, &api.DeleteLifecycleHookInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, LifecycleHookName: new(api.AsciiStringMaxLen255("remove/me"))})
				return err
			})
			if err == nil || wireError(err).Code != "ValidationError" {
				t.Fatalf("native missing-hook delete contract=%v", err)
			}
		})
	}
}

func TestLifecycleHeartbeatCannotExtendGlobalLifetime(t *testing.T) {
	s, ctx, g, source, _ := ownedControlService(t)
	s.events = &hookTestEvents{tokens: map[string]string{}}
	initial := source.Now()
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutInstance(InstanceRecord{Group: g.Key, GroupID: g.ID, Data: api.Instance{InstanceId: new(api.XmlStringMaxLen19("i-global")), LifecycleState: new(api.LifecycleState("Pending"))}}); err != nil {
			return err
		}
		if err := s.installLifecycleHook(ctx, tx, g, api.LifecycleHookSpecification{LifecycleHookName: new(api.AsciiStringMaxLen255("global")), LifecycleTransition: new(api.LifecycleTransition(launchTransition)), HeartbeatTimeout: new(api.HeartbeatTimeout(30))}); err != nil {
			return err
		}
		_, err := s.beginLifecycleHooks(ctx, tx, g, "i-global", launchTransition)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	heartbeat := func() error {
		return s.repository.Update(ctx, func(tx Transaction) error {
			_, err := s.recordLifecycleActionHeartbeat(ctx, tx, &api.RecordLifecycleActionHeartbeatInput{AutoScalingGroupName: new(api.ResourceName(g.Key.Name)), LifecycleHookName: new(api.AsciiStringMaxLen255("global")), InstanceId: new(api.XmlStringMaxLen19("i-global"))})
			return err
		})
	}
	for range 103 {
		if err := source.Advance(29 * time.Second); err != nil {
			t.Fatal(err)
		}
		if err := heartbeat(); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		actions, err := r.LifecycleActions(g.Key)
		if err != nil {
			return err
		}
		want := initial.Add(3000 * time.Second)
		if len(actions) != 1 || !actions[0].Deadline.Equal(want) || !actions[0].GlobalDeadline.Equal(want) {
			t.Fatalf("heartbeats escaped global deadline: %+v", actions)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(13 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := heartbeat(); err == nil {
		t.Fatal("heartbeat renewed an action at its global deadline")
	}
}

type rejectedHookNotifications struct{ *hookTestEvents }

func (*rejectedHookNotifications) Notify(_ context.Context, _ HookRecord, payload []byte) error {
	var notification struct{ LifecycleActionToken string }
	if err := json.Unmarshal(payload, &notification); err != nil {
		return err
	}
	if notification.LifecycleActionToken == "" {
		return nil // The hook was admitted while its notification role still worked.
	}
	return &awswire.Error{Code: "AccessDenied", StatusCode: 403, Message: "Notification delivery is no longer authorized."}
}

func TestLifecycleNotificationRejectionKeepsBoundedOutcome(t *testing.T) {
	for _, transition := range []string{launchTransition, terminateTransition} {
		t.Run(transition, func(t *testing.T) {
			s, ctx, g, _, _ := ownedControlService(t)
			s.events = &rejectedHookNotifications{&hookTestEvents{tokens: map[string]string{}}}
			id, state := "i-0123456789abcdef0", "Pending"
			if transition == terminateTransition {
				state = "Terminating"
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutInstance(InstanceRecord{Group: g.Key, GroupID: g.ID, Data: api.Instance{
					InstanceId: new(api.XmlStringMaxLen19(id)), LifecycleState: new(api.LifecycleState(state)),
				}}); err != nil {
					return err
				}
				return s.installLifecycleHook(ctx, tx, g, api.LifecycleHookSpecification{
					LifecycleHookName:   new(api.AsciiStringMaxLen255("bounded")),
					LifecycleTransition: new(api.LifecycleTransition(transition)),
					HeartbeatTimeout:    new(api.HeartbeatTimeout(30)), DefaultResult: new(api.LifecycleActionResult("CONTINUE")),
					NotificationTargetARN: new(api.NotificationTargetResourceName("arn:aws:sqs:us-east-1:000000000000:notifications")),
					RoleARN:               new(api.XmlStringMaxLen255("arn:aws:iam::000000000000:role/notifications")),
				})
			}); err != nil {
				t.Fatal(err)
			}
			// Native deleted-queue capture completes before its 30-second
			// heartbeat: notification failure applies the default immediately.
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				waiting, err := s.beginLifecycleHooks(tx.Context(), tx, g, id, transition)
				if err == nil && waiting {
					t.Fatal("rejected notification retained its lifecycle barrier")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				instance, err := r.Instance(g.Key.Scope, id)
				if err != nil {
					return err
				}
				if value(instance.Data.LifecycleState) != state+":Proceed" {
					t.Fatalf("notification rejection lost the immediate CONTINUE outcome: state=%s", value(instance.Data.LifecycleState))
				}
				actions, err := r.LifecycleActions(g.Key)
				if err == nil && len(actions) != 0 {
					t.Fatal("notification failure left an action instead of applying its default")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
