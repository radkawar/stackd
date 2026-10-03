package autoscaling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/autoscaling"
	ec2api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

func (s *Service) newActivity(group GroupRecord, kind, cause string) ActivityRecord {
	id := uuid.NewString()
	if cause == "" {
		cause = group.ReconcileCause
	}
	if cause == "" {
		cause = "Reconciling desired and actual Auto Scaling capacity."
	}
	return ActivityRecord{Key: ActivityKey{Scope: group.Key.Scope, ID: id}, Group: group.Key, GroupID: group.ID, Kind: kind, OriginEventID: group.OriginEventID,
		Data: api.Activity{ActivityId: new(api.XmlString(id)), AutoScalingGroupARN: new(api.ResourceName(group.Key.ARN(group.ID))), AutoScalingGroupName: new(api.XmlStringMaxLen255(group.Key.Name)), AutoScalingGroupState: new(api.AutoScalingGroupState("InService")), Cause: new(api.XmlStringMaxLen1023(cause)), StartTime: new(api.TimestampType(s.clock.Now().Truncate(time.Millisecond))), StatusCode: new(api.ScalingActivityStatusCode("InProgress")), Progress: new(api.Progress(0))},
	}
}

func (s *Service) finishActivity(ctx context.Context, tx Transaction, group GroupRecord, activity ActivityRecord, err error) error {
	if err != nil {
		return s.completeActivity(ctx, tx, group, activity, "Failed", err.Error())
	}
	return s.completeActivity(ctx, tx, group, activity, "Successful", "")
}

func (s *Service) cancelActivity(ctx context.Context, tx Transaction, group GroupRecord, activity ActivityRecord, message string) error {
	return s.completeActivity(ctx, tx, group, activity, "Cancelled", message)
}

func (s *Service) completeActivity(ctx context.Context, tx Transaction, group GroupRecord, activity ActivityRecord, status, message string) error {
	finished := s.clock.Now().Truncate(time.Millisecond)
	eventStatus := status
	if status == "Successful" {
		eventStatus = value(activity.Data.StatusCode)
		if launchActivity(activity.Kind) {
			eventStatus = "InProgress"
		}
	}
	text(&activity.Data.StatusCode, status)
	if message != "" {
		text(&activity.Data.StatusMessage, message)
	}
	number(&activity.Data.Progress, 100)
	activity.Data.EndTime = new(api.TimestampType(finished.Truncate(time.Second)))
	activity.RetryAt = time.Time{}
	if err := tx.PutActivity(activity); err != nil {
		return err
	}
	if s.events == nil || !launchActivity(activity.Kind) && !terminateActivity(activity.Kind) {
		return nil
	}
	eventType := "EC2 Instance Launch Successful"
	if terminateActivity(activity.Kind) {
		eventType = "EC2 Instance Terminate Successful"
	}
	if status != "Successful" {
		if launchActivity(activity.Kind) {
			eventType = "EC2 Instance Launch Unsuccessful"
		} else {
			eventType = "EC2 Instance Terminate Unsuccessful"
		}
	}
	details := map[string]string{}
	if raw := value(activity.Data.Details); raw != "" {
		if err := json.Unmarshal([]byte(raw), &details); err != nil {
			return err
		}
	}
	origin, destination, action := "", "", ""
	if activity.Kind != "launch" && activity.Kind != "terminate" {
		origin, destination = lifecycleEndpoints(activity.Kind, "")
		action = "Terminate"
		if launchActivity(activity.Kind) {
			action = "Launch"
		}
	}
	body, err := json.Marshal(struct {
		ActivityID    string            `json:"ActivityId"`
		RequestID     string            `json:"RequestId"`
		GroupName     string            `json:"AutoScalingGroupName"`
		InstanceID    string            `json:"EC2InstanceId,omitempty"`
		StatusCode    string            `json:"StatusCode"`
		StatusMessage string            `json:"StatusMessage,omitempty"`
		Cause         string            `json:"Cause"`
		Description   string            `json:"Description"`
		StartTime     time.Time         `json:"StartTime"`
		EndTime       time.Time         `json:"EndTime"`
		Details       map[string]string `json:"Details"`
		Origin        string            `json:"Origin,omitempty"`
		Destination   string            `json:"Destination,omitempty"`
		Action        string            `json:"Action,omitempty"`
	}{activity.Key.ID, activity.Key.ID, group.Key.Name, activity.InstanceID, eventStatus, message, value(activity.Data.Cause), value(activity.Data.Description), *activity.Data.StartTime, finished, details, origin, destination, action})
	if err != nil {
		return err
	}
	metadata := awsctx.FromContext(ctx)
	metadata.ParentEventID = activity.OriginEventID
	return s.events.Publish(awsctx.WithMetadata(ctx, metadata), group, eventType, body)
}

func (s *Service) executeLaunch(ctx context.Context, group GroupRecord, activity ActivityRecord) (bool, error) {
	instance, launchErr := s.instances.Launch(ctx, group, activity)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Group(group.Key)
		if err != nil {
			return err
		}
		if current.ID != group.ID {
			return errors.New("launch activity lost its owning group")
		}
		if launchErr != nil {
			return s.finishActivity(tx.Context(), tx, current, activity, launchErr)
		}
		activity.InstanceID = value(instance.InstanceId)
		text(&activity.Data.Description, "Launching a new EC2 instance: "+activity.InstanceID)
		text(&activity.Data.StatusCode, "PreInService")
		number(&activity.Data.Progress, 30)
		details := map[string]string{"Subnet ID": value(instance.SubnetId)}
		if instance.Placement != nil {
			details["Availability Zone"] = value(instance.Placement.AvailabilityZone)
			details["Availability Zone ID"] = value(instance.Placement.AvailabilityZoneId)
		}
		body, err := json.Marshal(details)
		if err != nil {
			return err
		}
		text(&activity.Data.Details, string(body))
		if err := tx.PutActivity(activity); err != nil {
			return err
		}
		member := membershipFromInstance(current, instance, s.clock.Now())
		member.ActivityID = activity.Key.ID
		if activity.Kind == "warm-launch" {
			text(&member.Data.LifecycleState, "Warmed:Pending")
		}
		member.TerminationRequested = current.Deleting || activity.Kind == "warm-launch" && (current.Data.WarmPoolConfiguration == nil || warmPoolDeleting(current))
		member.Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(activity.LaunchTemplate))
		return tx.PutInstance(member)
	})
	if err != nil {
		return false, err
	}
	if launchErr != nil {
		return false, launchErr
	}
	return true, nil
}

func membershipFromInstance(group GroupRecord, instance ec2api.Instance, at time.Time) InstanceRecord {
	member := InstanceRecord{Group: group.Key, GroupID: group.ID, JoinedAt: at, Data: api.Instance{LifecycleState: new(api.LifecycleState("Pending")), HealthStatus: new(api.XmlStringMaxLen32("Healthy")), ProtectedFromScaleIn: new(api.InstanceProtected(false))}}
	text(&member.Data.InstanceId, value(instance.InstanceId))
	text(&member.Data.InstanceType, value(instance.InstanceType))
	text(&member.Data.ImageId, value(instance.ImageId))
	if instance.Placement != nil {
		text(&member.Data.AvailabilityZone, value(instance.Placement.AvailabilityZone))
		text(&member.Data.AvailabilityZoneId, value(instance.Placement.AvailabilityZoneId))
	}
	return member
}

func (s *Service) finishMemberActivity(ctx context.Context, tx Transaction, group GroupRecord, member InstanceRecord, err error) error {
	if member.ActivityID == "" {
		return nil
	}
	activity, lookupErr := tx.Activity(ActivityKey{Scope: group.Key.Scope, ID: member.ActivityID})
	if lookupErr != nil {
		return lookupErr
	}
	if activity.Data.EndTime != nil {
		return nil
	}
	if activity.InstanceID == "" {
		activity.InstanceID = value(member.Data.InstanceId)
	}
	return s.finishActivity(ctx, tx, group, activity, err)
}

func (s *Service) terminateMember(tx Transaction, group GroupRecord, member *InstanceRecord, cause string) (ActivityRecord, error) {
	if member.TerminationRequested {
		return ActivityRecord{}, nil
	}
	if err := s.finishMemberActivity(tx.Context(), tx, group, *member, fmt.Errorf("Instance left service before scaling completed")); err != nil {
		return ActivityRecord{}, err
	}
	if err := deleteInstanceActions(tx, group, value(member.Data.InstanceId)); err != nil {
		return ActivityRecord{}, err
	}
	kind := "terminate"
	if warmMember(*member) {
		kind = "warm-terminate"
	}
	activity := s.newActivity(group, kind, cause)
	activity.InstanceID = value(member.Data.InstanceId)
	text(&activity.Data.Description, "Terminating EC2 instance: "+activity.InstanceID)
	if err := tx.PutActivity(activity); err != nil {
		return ActivityRecord{}, err
	}
	member.ActivityID = activity.Key.ID
	member.TerminationRequested = true
	if retainedMember(*member) {
		// Release starts a fresh termination attempt, including its lifecycle hooks.
		state := "Terminating"
		if warmMember(*member) {
			state = "Warmed:Terminating"
		}
		text(&member.Data.LifecycleState, state)
	}
	if err := tx.PutInstance(*member); err != nil {
		return ActivityRecord{}, err
	}
	return activity, nil
}
