package lambda

import (
	"context"
	"errors"
)

// Network retirement is an external effect. Retain the Deleting mapping until
// exact-owned namespace and ENI cleanup succeeds under current role authority.
func (s *Service) releaseMappingNetwork(ctx context.Context, mapping EventSourceMappingRecord) error {
	d := mapping.Settings.Kafka
	if d == nil || len(d.Network.SubnetIDs) == 0 {
		return nil
	}
	if s.sourceNetworks == nil {
		return errors.New("lambda source network cleanup requires its configured native owner")
	}
	role := d.NetworkRoleARN
	err := s.repository.View(ctx, func(r Reader) error {
		function, err := loadFunction(r, mapping.Function)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		role = function.Role
		return nil
	})
	if err != nil {
		return err
	}
	return s.sourceNetworks.Release(ownerContext(ctx, mapping.Function.FunctionKey), mapping.Function.FunctionKey, role, mapping.Key.ARN())
}
