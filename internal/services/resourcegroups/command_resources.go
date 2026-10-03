package resourcegroups

import (
	"context"
	"errors"

	"stackd/internal/awswire"
)

// CommandResources resolves current membership for Run Command in the caller's
// scope and transaction. SSM requires ListGroupResources, not the interactive
// query API's additional tag:GetResources/GetGroupQuery permissions. Missing
// groups select no nodes, matching native Run Command's empty-target result.
func (s *Service) CommandResources(ctx context.Context, name string) ([]Resource, error) {
	var rows []Resource
	err := s.repository.View(ctx, func(r Reader) error {
		g, err := s.loadGroup(r, name, "ListGroupResources")
		if err != nil {
			var wire *awswire.Error
			if errors.As(err, &wire) && wire.Code == "NotFoundException" {
				return nil
			}
			return err
		}
		if g.Query == nil {
			resources, queryErrors, err := s.groupMembers(r, g)
			if err != nil {
				return err
			}
			if len(queryErrors) != 0 {
				return failure("BadRequestException", "The resource group's query cannot be resolved.")
			}
			rows = resources
			return nil
		}
		query, err := parseQuery(g.Query)
		if err != nil {
			return err
		}
		resources, queryErrors, err := s.resolveQueryResources(r.Context(), g.Query, query)
		if err != nil {
			return err
		}
		if len(queryErrors) != 0 {
			return failure("BadRequestException", "The resource group's query cannot be resolved.")
		}
		rows = resources
		return nil
	})
	return rows, err
}
