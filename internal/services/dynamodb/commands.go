package dynamodb

import (
	"context"
	"errors"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
)

// DescribeTable is the authorized command shared by clients and integrations.
func (s *Service) DescribeTable(ctx context.Context, in *api.DescribeTableInput) (*api.DescribeTableOutput, *awswire.Error) {
	return runCommand(s, ctx, "DescribeTable", in, s.describeTable)
}

// UpdateTable commits Go-owned controls before observing their admission limits.
// Physical changes remain pending until real engine reconciliation completes.
func (s *Service) UpdateTable(ctx context.Context, in *api.UpdateTableInput) (*api.UpdateTableOutput, *awswire.Error) {
	hasSettings := hasTableSettings(in)
	var inputErr error
	switch {
	case !hasSettings && in.ReplicaUpdates == nil && in.GlobalTableSettingsReplicationMode == nil && in.GlobalTableWitnessUpdates == nil && in.MultiRegionConsistency == nil:
		inputErr = invalidTable("At least one property must be specified to update the table")
	case in.GlobalSecondaryIndexUpdates != nil && len(in.GlobalSecondaryIndexUpdates) == 0:
		inputErr = invalidTable("List of GlobalSecondaryIndexUpdates is empty")
	case len(in.ReplicaUpdates) != 0 && hasSettings:
		inputErr = invalidTable("Replica modification must be the only operation in the request")
	}
	if inputErr != nil {
		return runCommand(s, ctx, "UpdateTable", in, func(context.Context, Transaction, *api.UpdateTableInput) (*api.UpdateTableOutput, error) {
			return nil, inputErr
		})
	}
	key, planErr := parseTableKey(ctx, value(in.TableName))
	var planned []TableRecord
	if planErr == nil {
		planned, planErr = s.planTableGroup(ctx, key)
	}
	if planErr == nil {
		var release func()
		release, planErr = s.engines.lockTableDatabases(ctx, planned)
		if release != nil {
			defer release()
		}
	}
	return s.updateTableCommand(ctx, in, func(ctx context.Context, tx Transaction, table TableRecord, in *api.UpdateTableInput) (*TableRecord, error) {
		if planErr != nil {
			return nil, planErr
		}
		if _, err := validateTableGroup(tx, &table, planned); err != nil {
			return nil, err
		}
		return s.updateTable(ctx, tx, table, in)
	})
}

// UpdateCapacity applies Application Auto Scaling's regional capacity change.
// Unlike a customer's UpdateTable, it must not overwrite other replicas' read
// overrides or capacity. Admission, authorization and command recording are shared.
// This only commits regional metadata and may join the scaling transaction:
// engine reconciliation owns physical changes after commit, without gate inversion.
func (s *Service) UpdateCapacity(ctx context.Context, in *api.UpdateTableInput) (*api.UpdateTableOutput, *awswire.Error) {
	return s.updateTableCommand(ctx, in, func(ctx context.Context, tx Transaction, table TableRecord, in *api.UpdateTableInput) (*TableRecord, error) {
		if err := s.requireEngine(); err != nil {
			return nil, err
		}
		return s.updateTableSettings(ctx, tx, table, in)
	})
}

func (s *Service) updateTableCommand(ctx context.Context, in *api.UpdateTableInput, update func(context.Context, Transaction, TableRecord, *api.UpdateTableInput) (*TableRecord, error)) (*api.UpdateTableOutput, *awswire.Error) {
	var updated *TableRecord
	out, rejected := runCommand(s, ctx, "UpdateTable", in, func(ctx context.Context, tx Transaction, in *api.UpdateTableInput) (*api.UpdateTableOutput, error) {
		table, err := s.controlTable(ctx, tx, value(in.TableName), "UpdateTable", nil)
		if err != nil {
			return nil, err
		}
		updated, err = update(ctx, tx, table, in)
		if err != nil {
			return nil, err
		}
		description, err := s.tableDescription(tx, updated)
		if err != nil {
			return nil, err
		}
		return &api.UpdateTableOutput{TableDescription: description}, nil
	})
	if rejected == nil && updated.PendingUpdate == nil {
		s.admission.observe(updated)
	}
	return out, rejected
}

func runCommand[I, O any](s *Service, ctx context.Context, action string, in *I, fn func(context.Context, Transaction, *I) (*O, error), prepare ...func(context.Context) error) (*O, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	var out *O
	for _, preparation := range prepare {
		if err = preparation(ctx); err != nil {
			break
		}
	}
	if err == nil {
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var err error
			out, err = fn(tx.Context(), tx, in)
			if err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
	}
	if err == nil {
		s.engines.wake()
		return out, nil
	}
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	var dependency interface{ RecordRejection(context.Context) error }
	if errors.As(err, &dependency) {
		if err := dependency.RecordRejection(completion); err != nil {
			return nil, wireError(err)
		}
	}
	if err := s.recordCall(completion, action, in, nil, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}
