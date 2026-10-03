package resourcegroups

import (
	"context"
	"maps"

	tagging "stackd/internal/services/resourcegroupstaggingapi"
)

// ListTaggingResources exposes this owner's current definitions to the common
// discovery adapter, including groups matching their own tag query.
func (s *Service) ListTaggingResources(ctx context.Context) ([]tagging.Resource, error) {
	var out []tagging.Resource
	err := s.repository.View(ctx, func(r Reader) error {
		groups, err := r.Groups(scopeFor(r.Context()))
		if err != nil {
			return err
		}
		out = make([]tagging.Resource, 0, len(groups))
		for _, g := range groups {
			out = append(out, tagging.Resource{ARN: g.ARN, ResourceType: "resource-groups:group", Tags: maps.Clone(g.Tags)})
		}
		return nil
	})
	return out, err
}
