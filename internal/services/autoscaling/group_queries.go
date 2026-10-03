package autoscaling

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/autoscaling"
)

func canonicalFilters(filters api.Filters) api.Filters {
	out := make(api.Filters, len(filters))
	for i, f := range filters {
		out[i].Name = f.Name
		out[i].Values = slices.Clone(f.Values)
		slices.Sort(out[i].Values)
		out[i].Values = slices.Compact(out[i].Values)
	}
	slices.SortFunc(out, func(a, b api.Filter) int {
		return cmp.Or(strings.Compare(value(a.Name), value(b.Name)), strings.Compare(strings.Join(plainList(a.Values), "\x00"), strings.Join(plainList(b.Values), "\x00")))
	})
	return out
}

func groupMatches(group GroupRecord, names []string, filters api.Filters) bool {
	if len(names) > 0 && !slices.Contains(names, group.Key.Name) && !slices.Contains(names, group.Key.ARN(group.ID)) {
		return false
	}
	for _, filter := range filters {
		name := value(filter.Name)
		matched := false
		for _, tag := range group.Data.Tags {
			candidate := ""
			switch {
			case name == "tag-key":
				candidate = value(tag.Key)
			case name == "tag-value":
				candidate = value(tag.Value)
			case strings.HasPrefix(name, "tag:") && strings.TrimPrefix(name, "tag:") == value(tag.Key):
				candidate = value(tag.Value)
			default:
				continue
			}
			if slices.Contains(filter.Values, api.XmlString(candidate)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (s *Service) describeAutoScalingGroups(ctx context.Context, tx Transaction, in *api.DescribeAutoScalingGroupsInput) (*api.DescribeAutoScalingGroupsOutput, error) {
	if err := s.authorize(ctx, "DescribeAutoScalingGroups", "*", nil); err != nil {
		return nil, err
	}
	filters := canonicalFilters(in.Filters)
	for _, filter := range filters {
		name := value(filter.Name)
		if name != "tag-key" && name != "tag-value" && !strings.HasPrefix(name, "tag:") {
			return nil, invalid("The filter name is not valid: " + name)
		}
		if len(filter.Values) == 0 {
			return nil, invalid("Filter values must not be empty.")
		}
	}
	names := listSelection(in.AutoScalingGroupNames)
	groups, err := tx.Groups(GroupQuery{Scope: scopeFor(ctx)})
	if err != nil {
		return nil, err
	}
	groups = slices.DeleteFunc(groups, func(g GroupRecord) bool { return !groupMatches(g, names, filters) })
	groups, next, err := pageRows(scopeFor(ctx), "DescribeAutoScalingGroups", struct {
		Names   []string
		Filters api.Filters
	}{names, filters}, in.MaxRecords, in.NextToken, groups, func(g GroupRecord) string { return g.Key.Name })
	if err != nil {
		return nil, err
	}
	out := &api.DescribeAutoScalingGroupsOutput{AutoScalingGroups: api.AutoScalingGroups{}, NextToken: next}
	for _, group := range groups {
		data, err := describeGroup(tx, group, in.IncludeInstances == nil || bool(*in.IncludeInstances))
		if err != nil {
			return nil, err
		}
		out.AutoScalingGroups = append(out.AutoScalingGroups, data)
	}
	return out, nil
}

func describeGroup(tx Reader, group GroupRecord, include bool) (api.AutoScalingGroup, error) {
	group.Data.Instances = nil
	members, err := tx.Instances(group.Key)
	if err != nil {
		return api.AutoScalingGroup{}, err
	}
	warmSize := int64(0)
	if include {
		group.Data.Instances = api.Instances{}
	}
	for _, member := range members {
		if warmMember(member) {
			warmSize++
		} else if include {
			group.Data.Instances = append(group.Data.Instances, member.Data)
		}
	}
	if group.Data.WarmPoolConfiguration != nil {
		number(&group.Data.WarmPoolSize, warmSize)
	}
	return group.Data, nil
}

func (s *Service) describeScalingActivities(ctx context.Context, tx Transaction, in *api.DescribeScalingActivitiesInput) (*api.DescribeScalingActivitiesOutput, error) {
	if err := s.authorize(ctx, "DescribeScalingActivities", "*", nil); err != nil {
		return nil, err
	}
	var bounds [2]time.Time
	var bounded [2]bool
	for _, filter := range in.Filters {
		switch name := value(filter.Name); name {
		case "Status":
			if value(in.AutoScalingGroupName) == "" {
				return nil, invalid("The Status filter requires an Auto Scaling group name. Add the AutoScalingGroupName parameter and try again.")
			}
			if len(filter.Values) == 0 {
				return nil, invalid("Filter values must not be empty.")
			}
		case "StartTimeLowerBound", "StartTimeUpperBound":
			index := 0
			if name == "StartTimeUpperBound" {
				index = 1
			}
			if bounded[index] || len(filter.Values) > 1 {
				return nil, invalid("The filter configuration isn't valid. Multiple values for " + name + " aren't supported. Specify a single timestamp value.")
			}
			if len(filter.Values) == 0 {
				return nil, failure("InternalFailure", "The service has encountered an internal error. We apologize for the inconvenience.")
			}
			var valid bool
			bounds[index], valid = parseActivityTime(string(filter.Values[0]))
			if !valid {
				return nil, invalid("The filter configuration isn't valid. The specified timestamp isn't valid.")
			}
			bounded[index] = true
		default:
			return nil, invalid("The scaling activity filter name is not valid: " + name)
		}
	}
	filters := canonicalFilters(in.Filters)
	includeDeleted := in.IncludeDeletedGroups != nil && bool(*in.IncludeDeletedGroups)
	if !includeDeleted && value(in.AutoScalingGroupName) != "" {
		if _, err := tx.Group(GroupKey{Scope: scopeFor(ctx), Name: value(in.AutoScalingGroupName)}); errors.Is(err, ErrNotFound) {
			return nil, invalid("AutoScalingGroup name not found - AutoScalingGroup " + value(in.AutoScalingGroupName) + " not found")
		} else if err != nil {
			return nil, err
		}
	}
	activities, err := tx.Activities(scopeFor(ctx), value(in.AutoScalingGroupName), includeDeleted)
	if err != nil {
		return nil, err
	}
	ids := listSelection(in.ActivityIds)
	cutoff := s.clock.Now().Add(-6 * 7 * 24 * time.Hour)
	activities = slices.DeleteFunc(activities, func(a ActivityRecord) bool {
		if a.Data.StartTime.Before(cutoff) || len(ids) > 0 && !slices.Contains(ids, a.Key.ID) {
			return true
		}
		start := time.Time(*a.Data.StartTime).Truncate(time.Millisecond)
		if bounded[0] && start.Before(bounds[0]) || bounded[1] && start.After(bounds[1]) {
			return true
		}
		for _, filter := range filters {
			if value(filter.Name) == "Status" && !slices.Contains(filter.Values, api.XmlString(value(a.Data.StatusCode))) {
				return true
			}
		}
		return false
	})
	maximum := in.MaxRecords
	if maximum == nil {
		maximum = new(api.MaxRecords(100))
	}
	// Continuations retain their position when callers change filters or IDs.
	// TODO: Comeback establish why native continuation with a changed exact upper
	// bound can omit the oldest millisecond-equal record while first-page bounds
	// include it; preserve documented inclusive selection rather than special-case
	// a captured timestamp.
	activities, next, err := pageRows(scopeFor(ctx), "DescribeScalingActivities", struct {
		Group   string
		Deleted bool
	}{value(in.AutoScalingGroupName), includeDeleted}, maximum, in.NextToken, activities, func(a ActivityRecord) string {
		return fmt.Sprintf("%020d/%s", ^uint64(a.Data.StartTime.UnixNano()), a.Key.ID)
	})
	if err != nil {
		return nil, err
	}
	out := &api.DescribeScalingActivitiesOutput{Activities: api.Activities{}, NextToken: next}
	for _, activity := range activities {
		if group, err := tx.Group(activity.Group); err == nil && group.ID == activity.GroupID {
			// Activity state describes group existence, unlike group Status,
			// which can report "Delete in progress" during termination hooks.
			text(&activity.Data.AutoScalingGroupState, "InService")
		} else if err == nil || errors.Is(err, ErrNotFound) {
			text(&activity.Data.AutoScalingGroupState, "Deleted")
		} else {
			return nil, err
		}
		out.Activities = append(out.Activities, activity.Data)
	}
	return out, nil
}

var activityTimePattern = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?([Zz]|[+-]\d{2}:\d{2})$`)

// Activity filters accept minute precision and normalize calendar overflow,
// unlike Go's strict RFC3339 parser. Native comparisons use milliseconds.
func parseActivityTime(input string) (time.Time, bool) {
	fields := activityTimePattern.FindStringSubmatch(strings.TrimSpace(input))
	if fields == nil {
		return time.Time{}, false
	}
	var parts [6]int
	for i := range parts {
		parts[i], _ = strconv.Atoi(fields[i+1])
	}
	year, month, day, hour, minute, second := parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
	nanos := 0
	for i := range 9 {
		nanos *= 10
		if i < len(fields[7]) {
			nanos += int(fields[7][i] - '0')
		}
	}
	if month < 1 || month > 12 || day < 1 || day > 31 || hour > 24 || minute > 59 || second > 59 ||
		hour == 24 && (minute != 0 || second != 0 || nanos != 0) {
		return time.Time{}, false
	}
	offset := 0
	if zone := fields[8]; len(zone) > 1 {
		hours, _ := strconv.Atoi(zone[1:3])
		minutes, _ := strconv.Atoi(zone[4:6])
		if hours > 18 || minutes > 59 || hours == 18 && minutes != 0 {
			return time.Time{}, false
		}
		offset = hours*60 + minutes
		if zone[0] == '-' {
			offset = -offset
		}
	}
	day = min(day, time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day())
	result := time.Date(year, time.Month(month), day, hour, minute, second, nanos, time.UTC)
	return result.Add(-time.Duration(offset) * time.Minute).Truncate(time.Millisecond), true
}

func (s *Service) describeScalingProcessTypes(ctx context.Context, _ Transaction, _ *api.DescribeScalingProcessTypesInput) (*api.DescribeScalingProcessTypesOutput, error) {
	if err := s.authorize(ctx, "DescribeScalingProcessTypes", "*", nil); err != nil {
		return nil, err
	}
	out := &api.DescribeScalingProcessTypesOutput{Processes: api.Processes{}}
	for _, name := range scalingProcesses {
		out.Processes = append(out.Processes, api.ProcessType{ProcessName: new(api.XmlStringMaxLen255(name))})
	}
	return out, nil
}
func (s *Service) describeTerminationPolicyTypes(ctx context.Context, _ Transaction, _ *api.DescribeTerminationPolicyTypesInput) (*api.DescribeTerminationPolicyTypesOutput, error) {
	if err := s.authorize(ctx, "DescribeTerminationPolicyTypes", "*", nil); err != nil {
		return nil, err
	}
	out := &api.DescribeTerminationPolicyTypesOutput{TerminationPolicyTypes: api.TerminationPolicies{}}
	for _, name := range terminationPolicies {
		out.TerminationPolicyTypes = append(out.TerminationPolicyTypes, api.XmlStringMaxLen1600(name))
	}
	return out, nil
}
