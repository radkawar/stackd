package dynamodb

import (
	"context"
	"errors"
	"fmt"

	"stackd/internal/awswire"
)

var errReplicaChanged = errors.New("DynamoDB replica incarnation or membership changed")

// replicaAccess returns an independently owned service session, never a borrowed
// repository context. An immutable bootstrap may outlive its source table.
func (s *Service) replicaAccess(ctx context.Context, source TableKey, target *TableRecord, action string) (context.Context, error) {
	var sourcePhysical string
	err := s.repository.View(ctx, func(r Reader) error {
		bootstrap, err := r.ReplicaBootstrap(target.Key)
		if errors.Is(err, ErrNotFound) {
			table, err := r.Table(source)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err == nil && table.Replica.GroupID == target.Replica.GroupID {
				sourcePhysical = table.PhysicalName
			}
			return err
		}
		if err != nil {
			return err
		}
		if bootstrap.Source == source {
			sourcePhysical = bootstrap.SourcePhysicalName
		}
		return nil
	})
	if err != nil {
		return ctx, err
	}
	return s.replicaAccessIncarnation(ctx, source, sourcePhysical, target, action)
}

func (s *Service) replicaAccessIncarnation(ctx context.Context, source TableKey, sourcePhysical string, target *TableRecord, action string) (context.Context, error) {
	roleCtx, sessionErr := s.replicaRoleContext(ctx, target)
	if sessionErr != nil {
		return ctx, sessionErr
	}
	var sourceErr, targetErr error
	err := s.repository.Update(roleCtx, func(tx Transaction) error {
		current, err := tx.Table(target.Key)
		if errors.Is(err, ErrNotFound) {
			return errReplicaChanged
		}
		if err != nil {
			return err
		}
		if !sameReplicaIncarnation(&current, target) {
			return errReplicaChanged
		}
		sourceCtx := regionalContext(tx.Context(), source.Region)
		sourceErr = s.authorizeTable(sourceCtx, tx, source, "Scan", "", nil)
		if sourceErr == nil {
			sourceErr = s.authorizeTable(sourceCtx, tx, source, "GetItem", "", nil)
		}
		targetErr = s.authorizeTable(tx.Context(), tx, target.Key, action, "", nil)
		// A departed/replaced source can still own retained rows, but its
		// successor must not inherit this old incarnation's denial interval.
		if source != target.Key && sourcePhysical != "" {
			if err := s.setReplicaAuthorization(tx, source, sourcePhysical, target.Replica.GroupID, sourceErr); err != nil {
				return err
			}
		}
		permissionErr := targetErr
		if source == target.Key && sourceErr != nil {
			permissionErr = sourceErr
		}
		return s.setReplicaAuthorization(tx, target.Key, target.PhysicalName, target.Replica.GroupID, permissionErr)
	})
	return roleCtx, errors.Join(sourceErr, targetErr, err)
}

func replicaAuthorizationDenied(err error) bool {
	var rejected *awswire.Error
	if !errors.As(err, &rejected) {
		return false
	}
	switch rejected.Code {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
		return true
	default:
		return false
	}
}

// Native and repository failures never start or clear an authorization interval.
func (s *Service) setReplicaAuthorization(tx Transaction, key TableKey, physical, group string, permissionErr error) error {
	if permissionErr != nil && !replicaAuthorizationDenied(permissionErr) {
		return nil
	}
	table, err := tx.Table(key)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if table.PhysicalName != physical || table.Replica.GroupID != group || group == "" {
		return nil
	}
	if permissionErr == nil {
		if table.Replica.UnauthorizedAt == nil {
			return nil
		}
		// One member owns a single denial interval for both replication
		// directions. Success on PutItem alone must not erase a Scan denial,
		// or vice versa; clear only after the member's permissions recover.
		ctx := regionalContext(tx.Context(), key.Region)
		for _, action := range [...]string{"Scan", "GetItem", "PutItem", "DeleteItem", "UpdateTable"} {
			if err := s.authorizeTable(ctx, tx, key, action, "", nil); err != nil {
				if replicaAuthorizationDenied(err) {
					return nil
				}
				return err
			}
		}
		table.Replica.UnauthorizedAt = nil
	} else {
		if table.Replica.UnauthorizedAt != nil {
			return nil
		}
		table.Replica.UnauthorizedAt = new(s.clock.Now())
	}
	return tx.PutTable(table)
}

func sameReplicaIncarnation(current, expected *TableRecord) bool {
	return current.Key == expected.Key && current.DatabaseID == expected.DatabaseID && current.PhysicalName == expected.PhysicalName &&
		current.Replica.GroupID != "" && current.Replica.GroupID == expected.Replica.GroupID
}

func (s *Service) replicaRoleContext(ctx context.Context, target *TableRecord) (context.Context, error) {
	if s.replicationIdentity == nil {
		return ctx, fmt.Errorf("DynamoDB replication identity provider is unavailable")
	}
	// Session issuance may update IAM state and must precede the resource view.
	roleCtx, err := s.replicationIdentity.Context(ctx, target.Key)
	if !replicaAuthorizationDenied(err) {
		return roleCtx, err
	}
	marked := s.repository.Update(ctx, func(tx Transaction) error {
		return s.setReplicaAuthorization(tx, target.Key, target.PhysicalName, target.Replica.GroupID, err)
	})
	return ctx, errors.Join(err, marked)
}

func (s *Service) replicaSettingsAccess(ctx context.Context, target *TableRecord) error {
	roleCtx, err := s.replicaRoleContext(ctx, target)
	if err != nil {
		return err
	}
	var denied error
	err = s.repository.Update(roleCtx, func(tx Transaction) error {
		current, err := tx.Table(target.Key)
		if err != nil {
			return err
		}
		if !sameReplicaIncarnation(&current, target) {
			return errReplicaChanged
		}
		denied = s.authorizeTable(tx.Context(), tx, target.Key, "UpdateTable", "", nil)
		return s.setReplicaAuthorization(tx, target.Key, target.PhysicalName, target.Replica.GroupID, denied)
	})
	return errors.Join(denied, err)
}
