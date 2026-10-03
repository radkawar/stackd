package autoscaling

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/autoscaling"
)

func (key GroupKey) ARN(id string) string {
	return fmt.Sprintf("arn:%s:autoscaling:%s:%s:autoScalingGroup:%s:autoScalingGroupName/%s", key.Partition, key.Region, key.AccountID, id, key.Name)
}

func groupConditions(group GroupRecord) map[string][]string {
	conditions := make(map[string][]string, 2*len(group.Data.Tags)+8)
	for _, tag := range group.Data.Tags {
		conditions["aws:ResourceTag/"+value(tag.Key)] = []string{value(tag.Value)}
		conditions["autoscaling:ResourceTag/"+value(tag.Key)] = []string{value(tag.Value)}
	}
	return conditions
}

func groupRequestConditions(conditions map[string][]string, data api.AutoScalingGroup) {
	if data.MinSize != nil {
		conditions["autoscaling:MinSize"] = []string{strconv.FormatInt(intValue(data.MinSize), 10)}
	}
	if data.MaxSize != nil {
		conditions["autoscaling:MaxSize"] = []string{strconv.FormatInt(intValue(data.MaxSize), 10)}
	}
	if data.VPCZoneIdentifier != nil {
		conditions["autoscaling:VPCZoneIdentifiers"] = strings.Split(value(data.VPCZoneIdentifier), ",")
	}
	if data.LaunchTemplate != nil {
		version := value(data.LaunchTemplate.Version)
		conditions["autoscaling:LaunchTemplateVersionSpecified"] = []string{strconv.FormatBool(version != "" && version != "$Default" && version != "$Latest")}
	}
	if role := value(data.ServiceLinkedRoleARN); role != "" {
		conditions["autoscaling:ServiceLinkedRoleARN"] = []string{role}
	}
}

func requestTagConditions(conditions map[string][]string, tags api.Tags) {
	keys := make([]string, 0, len(tags))
	for _, tag := range tags {
		key := value(tag.Key)
		conditions["aws:RequestTag/"+key] = []string{value(tag.Value)}
		keys = append(keys, key)
	}
	if len(keys) > 0 {
		slices.Sort(keys)
		conditions["aws:TagKeys"] = slices.Compact(keys)
	}
}

func (s *Service) authorize(ctx context.Context, action, resourceARN string, conditions map[string][]string) error {
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{
		Action: "autoscaling:" + action, ResourceARN: resourceARN, ResourceAccountID: scopeFor(ctx).AccountID,
		Context: conditions, EvaluationTime: &now,
	}); rejected != nil {
		return rejected
	}
	return nil
}

func (s *Service) loadGroup(ctx context.Context, tx Reader, name, action string) (GroupRecord, error) {
	group, err := tx.Group(GroupKey{Scope: scopeFor(ctx), Name: name})
	if errors.Is(err, ErrNotFound) {
		if denied := s.authorize(ctx, action, GroupKey{Scope: scopeFor(ctx), Name: name}.ARN("*"), nil); denied != nil {
			return GroupRecord{}, denied
		}
		return GroupRecord{}, invalid("AutoScalingGroup name not found - AutoScalingGroup " + name + " not found")
	}
	if err != nil {
		return GroupRecord{}, err
	}
	if err := s.authorize(ctx, action, group.Key.ARN(group.ID), groupConditions(group)); err != nil {
		return GroupRecord{}, err
	}
	return group, nil
}

func (s *Service) authorizeLinkedRole(ctx context.Context, group GroupRecord) error {
	role := value(group.Data.ServiceLinkedRoleARN)
	prefix := fmt.Sprintf("arn:%s:iam::%s:role/aws-service-role/%s/AWSServiceRoleForAutoScaling", group.Key.Partition, group.Key.AccountID, ServicePrincipal)
	if role != prefix && !strings.HasPrefix(role, prefix+"_") {
		return invalid("The service-linked role ARN is not a valid Auto Scaling service-linked role.")
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{
		Action: "iam:PassRole", ResourceARN: role, ResourceAccountID: group.Key.AccountID, EvaluationTime: &now,
		Context: map[string][]string{"iam:PassedToService": {ServicePrincipal}, "iam:AssociatedResourceArn": {group.Key.ARN(group.ID)}},
	}); rejected != nil {
		return rejected
	}
	return nil
}

// WithRoleUsage holds group mutations while IAM decides linked-role deletion.
func (s *Service) WithRoleUsage(ctx context.Context, partition, accountID, roleARN string, fn func(context.Context, []string) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		keys, err := tx.GroupKeys(partition, accountID)
		if err != nil {
			return err
		}
		var resources []string
		for _, key := range keys {
			group, err := tx.Group(key)
			if err != nil {
				return err
			}
			if value(group.Data.ServiceLinkedRoleARN) == roleARN {
				resources = append(resources, key.ARN(group.ID))
			}
		}
		return fn(tx.Context(), resources)
	})
}
