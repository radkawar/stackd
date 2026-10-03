package resourcegroups

import (
	"slices"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/resourcegroups"
)

func (s *Service) groupResources(tx Transaction, in *api.GroupResourcesInput) (*api.GroupResourcesOutput, error) {
	g, err := s.loadGroup(tx, value(in.Group), "GroupResources")
	if err != nil {
		return nil, err
	}
	return s.changeMembers(tx, g, in.ResourceArns, false)
}
func (s *Service) ungroupResources(tx Transaction, in *api.UngroupResourcesInput) (*api.UngroupResourcesOutput, error) {
	g, err := s.loadGroup(tx, value(in.Group), "UngroupResources")
	if err != nil {
		return nil, err
	}
	out, err := s.changeMembers(tx, g, in.ResourceArns, true)
	if err != nil {
		return nil, err
	}
	return &api.UngroupResourcesOutput{Succeeded: out.Succeeded, Failed: out.Failed, Pending: out.Pending}, nil
}
func (s *Service) changeMembers(tx Transaction, g Group, arns api.ResourceArnList, remove bool) (*api.GroupResourcesOutput, error) {
	if g.ManagedType != applicationGroupType {
		return nil, failure("BadRequestException", "This operation does not support the target")
	}
	if s.applicationResources == nil {
		return nil, failure("NotImplementedException", "Application grouping requires current resource owners.")
	}
	tagAction := "tag:TagResources"
	if remove {
		tagAction = "tag:UntagResources"
	}
	for _, action := range []string{"tag:GetResources", tagAction} {
		if denied := s.authorizer.Authorize(tx.Context(), authorization.Request{Action: action, ResourceARN: "*"}); denied != nil {
			return nil, denied
		}
	}
	out := &api.GroupResourcesOutput{Succeeded: api.ResourceArnList{}, Failed: api.FailedResourceList{}, Pending: api.PendingResourceList{}}
	for _, arn := range arns {
		var attempted ApplicationResource
		pending := false
		err := s.repository.Attempt(tx.Context(), func(child Transaction) error {
			r, ok, err := s.applicationResources.Resolve(child.Context(), string(arn))
			if err != nil {
				return err
			}
			if !ok {
				return failure("ResourceGroupsValidationException", "The resource does not exist or its owner does not support application grouping.")
			}
			attempted = r
			if err := s.changeApplicationMember(child, g, r, remove); err != nil {
				return err
			}
			live, ok, err := s.applicationResources.Resolve(child.Context(), r.ARN)
			if err != nil {
				return err
			}
			if !ok || live.Incarnation != r.Incarnation {
				return failure("ResourceGroupsValidationException", "The resource incarnation changed.")
			}
			action := "GROUP"
			if remove {
				action = "UNGROUP"
			}
			pending = groupingStatus(g.ARN, action, live) == "IN_PROGRESS"
			return nil
		})
		if err != nil {
			rejected := wireError(err)
			if attempted.ARN != "" {
				action := "GROUP"
				if remove {
					action = "UNGROUP"
				}
				row := Grouping{GroupARN: g.ARN, ResourceARN: attempted.ARN, ResourceType: attempted.Type, Incarnation: attempted.Incarnation, Action: action, Status: "FAILED", ErrorCode: rejected.Code, ErrorMessage: rejected.Message, Updated: s.clock.Now()}
				previous, readErr := tx.Groupings(g.ARN)
				if readErr != nil {
					return nil, readErr
				}
				for _, old := range previous {
					if old.ResourceARN == row.ResourceARN && old.Incarnation == row.Incarnation {
						row.TaskARN = old.TaskARN
						break
					}
				}
				if err := tx.PutGrouping(row); err != nil {
					return nil, err
				}
			}
			out.Failed = append(out.Failed, api.FailedResource{ResourceArn: new(arn), ErrorCode: new(api.ErrorCode(rejected.Code)), ErrorMessage: new(api.ErrorMessage(rejected.Message))})
		} else if pending {
			out.Pending = append(out.Pending, api.PendingResource{ResourceArn: new(arn)})
		} else {
			out.Succeeded = append(out.Succeeded, arn)
		}
	}
	return out, nil
}
func groupingStatus(groupARN, action string, live ApplicationResource) string {
	matches := live.Tags[applicationTagKey] == groupARN
	if action == "UNGROUP" {
		matches = !matches
	}
	if matches {
		return "SUCCESS"
	}
	if live.TaggingPending {
		return "IN_PROGRESS"
	}
	return "FAILED"
}
func (s *Service) listGroupingStatuses(tx Transaction, in *api.ListGroupingStatusesInput) (*api.ListGroupingStatusesOutput, error) {
	g, err := s.loadGroup(tx, value(in.Group), "ListGroupingStatuses")
	if err != nil {
		return nil, err
	}
	if g.ManagedType != applicationGroupType {
		return nil, failure("BadRequestException", "The target must be an application group")
	}
	for _, f := range in.Filters {
		if value(f.Name) != "status" && value(f.Name) != "resource-arn" {
			return nil, failure("BadRequestException", "Invalid grouping status filter.")
		}
		if len(f.Values) == 0 {
			return nil, failure("BadRequestException", "Grouping status filters require values.")
		}
		if value(f.Name) == "status" {
			for _, v := range f.Values {
				if !slices.Contains([]string{"SUCCESS", "FAILED", "IN_PROGRESS", "SKIPPED"}, string(v)) {
					return nil, failure("BadRequestException", "Invalid grouping status.")
				}
			}
		}
	}
	rows, err := tx.Groupings(g.ARN)
	if err != nil {
		return nil, err
	}
	selected := make([]Grouping, 0, len(rows))
	if s.applicationResources == nil {
		return nil, failure("NotImplementedException", "Application grouping requires current resource owners.")
	}
	for _, row := range rows {
		live, ok, err := s.applicationResources.Resolve(tx.Context(), row.ResourceARN)
		if err != nil {
			return nil, err
		}
		if !ok || live.Incarnation != row.Incarnation {
			continue
		}
		if row.Status == "IN_PROGRESS" {
			status := groupingStatus(g.ARN, row.Action, live)
			if status != row.Status {
				row.Status = status
				row.Updated = s.clock.Now()
				if err := tx.PutGrouping(row); err != nil {
					return nil, err
				}
			}
		}
		match := true
		for _, f := range in.Filters {
			target := row.ResourceARN
			if value(f.Name) == "status" {
				target = row.Status
			}
			if !slices.Contains(f.Values, api.ListGroupingStatusesFilterValue(target)) {
				match = false
				break
			}
		}
		if match {
			selected = append(selected, row)
		}
	}
	request := struct {
		Group   string
		Filters api.ListGroupingStatusesFilterList
	}{g.ARN, in.Filters}
	page, next, err := paginate(tx.Context(), "ListGroupingStatuses", request, in.NextToken, in.MaxResults, selected, func(g Grouping) string { return g.ResourceARN })
	if err != nil {
		return nil, err
	}
	out := &api.ListGroupingStatusesOutput{Group: new(api.GroupStringV2(g.ARN)), GroupingStatuses: api.GroupingStatusesList{}, NextToken: next}
	for _, r := range page {
		item := api.GroupingStatusesItem{ResourceArn: new(api.ResourceArn(r.ResourceARN)), Action: new(api.GroupingType(r.Action)), Status: new(api.GroupingStatus(r.Status)), UpdatedAt: new(api.Timestamp(r.Updated))}
		if r.ErrorCode != "" {
			item.ErrorCode = new(api.ErrorCode(r.ErrorCode))
			item.ErrorMessage = new(api.ErrorMessage(r.ErrorMessage))
		}
		out.GroupingStatuses = append(out.GroupingStatuses, item)
	}
	return out, nil
}
