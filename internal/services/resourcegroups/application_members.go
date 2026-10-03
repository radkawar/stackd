package resourcegroups

import (
	"encoding/json"
	"slices"
	api "stackd/internal/awsapi/resourcegroups"
	"strings"
)

// groupMembers reads the actual owning definitions/deployments/tags. No grouping
// status or stale association row can resurrect a deleted resource incarnation.
func (s *Service) groupMembers(r Reader, g Group) ([]Resource, api.QueryErrorList, error) {
	switch g.ManagedType {
	case registryGroupType:
		groups, err := r.Groups(g.Scope)
		if err != nil {
			return nil, nil, err
		}
		out := []Resource{}
		for _, child := range groups {
			if child.ParentARN == g.ARN && child.ApplicationARN == g.ApplicationARN {
				out = append(out, Resource{ARN: child.ARN, Type: "AWS::ResourceGroups::Group", Tags: child.Tags})
			}
		}
		return out, nil, nil
	case stackGroupType:
		body, _ := json.Marshal(resourceQuery{ResourceTypeFilters: []string{"AWS::AllSupported"}, StackIdentifier: g.SourceARN})
		return s.selectResources(r.Context(), &api.ResourceQuery{Type: new(api.QueryTypeCLOUDFORMATION_STACK_1_0), Query: new(api.Query(body))})
	case applicationGroupType:
		if s.applicationResources == nil {
			return nil, nil, failure("NotImplementedException", "Application membership requires current resource owners.")
		}
		rows, err := s.applicationResources.List(r.Context())
		if err != nil {
			return nil, nil, err
		}
		out := []Resource{}
		transitions, err := r.Groupings(g.ARN)
		if err != nil {
			return nil, nil, err
		}
		pending := map[string]Grouping{}
		for _, transition := range transitions {
			if transition.Status == "IN_PROGRESS" {
				pending[transition.ResourceARN] = transition
			}
		}
		for _, row := range rows {
			waiting := false
			if transition, ok := pending[row.ARN]; ok && transition.Incarnation == row.Incarnation {
				waiting = groupingStatus(g.ARN, transition.Action, row) == "IN_PROGRESS"
			}
			if row.Tags[applicationTagKey] == g.ARN || waiting {
				out = append(out, Resource{ARN: row.ARN, Type: row.Type, Tags: row.Tags, Pending: waiting})
			}
		}
		slices.SortFunc(out, func(a, b Resource) int { return strings.Compare(a.ARN, b.ARN) })
		return out, nil, nil
	default:
		return s.selectResources(r.Context(), g.Query)
	}
}
