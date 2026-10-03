package ssmcommands

import (
	"slices"
	"strings"

	api "stackd/internal/awsapi/ssm"
)

// commandTargets validates group syntax separately from resolving membership.
// The original selectors remain on the accepted command; invocations retain the
// selected nodes and never rescan a group after admission or controller restart.
func commandTargets(input api.Targets) ([]Target, string, bool, error) {
	targets := make([]Target, 0, len(input))
	name := ""
	group, filters, ordinary := false, false, false
	ec2 := true
	seen := make(map[string]bool, len(input))
	for _, target := range input {
		key := value(target.Key)
		if seen[key] {
			return nil, "", false, failure("ValidationException", "Duplicate keys are not supported for targets.")
		}
		seen[key] = true
		if len(target.Values) == 0 {
			return nil, "", false, failure("InvalidParameters", "Target values cannot be empty.")
		}
		t := Target{Key: key, Values: make([]string, len(target.Values))}
		for i, v := range target.Values {
			t.Values[i] = string(v)
			if slices.Contains(t.Values[:i], string(v)) {
				return nil, "", false, failure("ValidationException", "Duplicate values are not supported for targets.")
			}
		}
		switch {
		case key == "resource-groups:Name":
			group = true
			if len(t.Values) != 1 || t.Values[0] == "" {
				return nil, "", false, failure("ValidationException", "Specify exactly one resource group name.")
			}
			name = t.Values[0]
		case key == "resource-groups:ResourceTypeFilters":
			filters = true
			ec2 = slices.Contains(t.Values, "AWS::EC2::Instance")
			if !ec2 && !slices.Contains(t.Values, "AWS::SSM::ManagedInstance") {
				return nil, "", false, failure("ValidationException", "Resource type filters must include AWS::EC2::Instance or AWS::SSM::ManagedInstance.")
			}
			if len(t.Values) > 5 {
				return nil, "", false, failure("ValidationException", "Specify at most five resource type filters.")
			}
		case key == "InstanceIds" || key == "instanceids" || strings.HasPrefix(key, "tag:"):
			ordinary = true
		default:
			return nil, "", false, failure("NotImplementedException", "The target selector is not implemented.")
		}
		targets = append(targets, t)
	}
	if (group || filters) && ordinary {
		return nil, "", false, failure("ValidationException", "Resource group targets cannot be combined with instance IDs or tags.")
	}
	if filters && !group {
		return nil, "", false, failure("ValidationException", "Resource type filters require a resource group name.")
	}
	return targets, name, ec2, nil
}
