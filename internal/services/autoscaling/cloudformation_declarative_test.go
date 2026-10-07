package autoscaling

import (
	"context"
	"testing"

	api "stackd/internal/awsapi/autoscaling"
)

// Drive native warm activation and scale-in admission without an execution
// backend. Observations are owner facts supplied to the native state machine;
// no mock engine can confer mutation authority or manufacture API success.
func TestDeclarativeProtectionRemovalChangesNewMemberScaleInAdmission(t *testing.T) {
	s, ctx, group, source, _ := ownedControlService(t)
	group.Ownership = "AWS::AutoScaling::AutoScalingGroup/private-incarnation"
	group.Data.LaunchTemplate = &api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-admission")), Version: new(api.XmlStringMaxLen255("1"))}
	applyGroupDefaults(&group)
	boolean(&group.Data.NewInstancesProtectedFromScaleIn, true)
	number(&group.Data.DefaultInstanceWarmup, 180)
	number(&group.Data.DesiredCapacity, 0)
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutGroup(group) }); err != nil {
		t.Fatal(err)
	}
	activate := func(id string) InstanceRecord {
		t.Helper()
		member := transitionMember(group, id, "Warmed:Running", source.Now())
		if err := s.repository.Update(ctx, func(tx Transaction) error { return s.activateWarmMember(tx, group, member) }); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			member = readTransition(t, s, ctx, group, id)
			if _, err := s.reconcileInstance(ctx, group, member, transitionObservation(id, "running", true), true); err != nil {
				t.Fatal(err)
			}
		}
		member = readTransition(t, s, ctx, group, id)
		if value(member.Data.LifecycleState) != "InService" {
			t.Fatalf("native activation did not enter service: %+v", member)
		}
		return member
	}
	old := activate("i-before-removal")
	if old.Data.ProtectedFromScaleIn == nil || !bool(*old.Data.ProtectedFromScaleIn) || !old.WarmUntil.After(source.Now()) {
		t.Fatalf("initial activation ignored configured protection/warmup: %+v", old)
	}
	in := &api.UpdateAutoScalingGroupInput{AutoScalingGroupName: group.Data.AutoScalingGroupName}
	managedScalingCommand(t, s, ctx, "UpdateAutoScalingGroup", in)
	group = managedScalingGroup(t, s, ctx, group.Key)
	if group.Data.NewInstancesProtectedFromScaleIn == nil || !bool(*group.Data.NewInstancesProtectedFromScaleIn) || intValue(group.Data.DefaultInstanceWarmup) != 180 || group.Ownership == "" {
		t.Fatal("ordinary native omission cleared configuration/private claim")
	}
	removed := GroupUpdateRemovals{NewInstancesProtectedFromScaleIn: true, DefaultInstanceWarmup: true}
	trusted := WithGroupUpdateRemovals(ctx, removed)
	wrong := WithCloudFormationOwnership(trusted, "AutoScalingGroup", "foreign-incarnation", group.Key.Name, true, nil)
	if _, err := executePrepared(s, wrong, "UpdateAutoScalingGroup", in, s.prepareUpdateAutoScalingGroup); err == nil {
		t.Fatal("declarative removal bypassed native private claim")
	}
	group = managedScalingGroup(t, s, ctx, group.Key)
	if !bool(*group.Data.NewInstancesProtectedFromScaleIn) || intValue(group.Data.DefaultInstanceWarmup) != 180 {
		t.Fatal("rejected private removal changed native configuration")
	}
	trusted = WithCloudFormationOwnership(trusted, "AutoScalingGroup", group.Ownership, group.Key.Name, true, nil)
	managedScalingCommand(t, s, trusted, "UpdateAutoScalingGroup", in)
	group = managedScalingGroup(t, s, ctx, group.Key)
	if group.Data.NewInstancesProtectedFromScaleIn == nil || bool(*group.Data.NewInstancesProtectedFromScaleIn) || group.Data.DefaultInstanceWarmup != nil || group.Ownership == "" {
		t.Fatalf("removed fields did not restore native omission defaults: %+v", group)
	}
	newMember := activate("i-after-removal")
	if newMember.Data.ProtectedFromScaleIn == nil || bool(*newMember.Data.ProtectedFromScaleIn) || newMember.WarmUntil.After(source.Now()) {
		t.Fatalf("new activation retained removed protection/warmup: %+v", newMember)
	}
	if changed, err := s.reconcileCapacity(ctx, group); err != nil || !changed {
		t.Fatalf("native scale-in did not admit newly unprotected member: changed=%t err=%v", changed, err)
	}
	old = readTransition(t, s, ctx, group, value(old.Data.InstanceId))
	newMember = readTransition(t, s, ctx, group, value(newMember.Data.InstanceId))
	if old.TerminationRequested || !bool(*old.Data.ProtectedFromScaleIn) || !newMember.TerminationRequested {
		t.Fatalf("scale-in changed old protection or failed to retire new member: old=%+v new=%+v", old, newMember)
	}
}

func TestScalingPolicyExpectedARNDoesNotCreateOrReplaceNativeIdentity(t *testing.T) {
	s, ctx, group, _, _ := ownedControlService(t)
	in := &api.PutScalingPolicyInput{AutoScalingGroupName: group.Data.AutoScalingGroupName, PolicyName: new(api.XmlStringMaxLen255("scale-out")), AdjustmentType: new(api.XmlStringMaxLen255("ChangeInCapacity")), ScalingAdjustment: new(api.PolicyIncrement(1)), Cooldown: new(api.Cooldown(0))}
	put := func(ctx context.Context) (*api.PutScalingPolicyOutput, error) {
		return executePrepared(s, ctx, "PutScalingPolicy", in, func(ctx context.Context, in *api.PutScalingPolicyInput) (func(Transaction) (*api.PutScalingPolicyOutput, error), error) {
			return func(tx Transaction) (*api.PutScalingPolicyOutput, error) {
				return s.putScalingPolicy(tx.Context(), tx, in)
			}, nil
		})
	}
	if _, err := put(WithScalingPolicyARN(ctx, "arn:aws:autoscaling:us-east-1:000000000000:scalingPolicy:absent:autoScalingGroupName/"+group.Key.Name+":policyName/scale-out")); err == nil {
		t.Fatal("trusted immutable identity fence created an absent policy")
	}
	first, err := put(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := PolicyKey{GroupKey: group.Key, Name: "scale-out"}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.DeletePolicy(key) }); err != nil {
		t.Fatal(err)
	}
	replacement, err := put(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if value(first.PolicyARN) == value(replacement.PolicyARN) {
		t.Fatal("native policy recreation reused the immutable ARN")
	}
	in.ScalingAdjustment = new(api.PolicyIncrement(9))
	if _, err := put(WithScalingPolicyARN(ctx, value(first.PolicyARN))); err == nil {
		t.Fatal("trusted immutable identity fence updated a replacement")
	}
	if err := s.repository.View(ctx, func(tx Reader) error {
		policy, err := tx.Policy(key)
		if err == nil && (value(policy.Data.PolicyARN) != value(replacement.PolicyARN) || intValue(policy.Data.ScalingAdjustment) != 1) {
			t.Fatal("rejected immutable identity fence changed native replacement")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	updated, err := put(ctx)
	if err != nil || value(updated.PolicyARN) != value(replacement.PolicyARN) {
		t.Fatalf("ordinary native upsert no longer preserves identity: %+v %v", updated, err)
	}
}
