package apigateway

import (
	"context"
	"strconv"
)

// StageIncarnation returns the stage owner's private scoped creation sequence.
// It remains unchanged on updates and cannot repeat on delete/recreate, even
// while the service clock is paused. Missing stages return ErrNotFound.
func (s *Service) StageIncarnation(ctx context.Context, scope Scope, apiID, stage string) (string, error) {
	var incarnation string
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := r.Stage(StageKey{APIKey: APIKey{Scope: scope, ID: apiID}, Name: stage})
		if err != nil {
			return err
		}
		incarnation = strconv.FormatUint(v.Incarnation, 10)
		return nil
	})
	return incarnation, err
}
