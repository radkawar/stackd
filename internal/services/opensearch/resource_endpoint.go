package opensearch

import (
	"context"

	"stackd/internal/endpoints"
)

// resourceDomain reads the native owner at request time. Incarnations remain
// immutable endpoint identities across replacement; no copied host registry is
// populated at creation or reconstructed after storage restart.
func (s *Service) resourceDomain(ctx context.Context, host string) (Domain, error) {
	id, region, matched := endpoints.ResourceHost(host, s.endpointDomain, "opensearch")
	if !matched || id == "" || region == "" {
		return Domain{}, ErrNotFound
	}
	var owner Domain
	err := s.repository.View(ctx, func(reader Reader) error {
		rows, err := reader.AllDomains()
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Incarnation == id && row.Key.Region == region && row.Status != "deleting" {
				owner = row
				return nil
			}
		}
		return ErrNotFound
	})
	return owner, err
}
