package dynamodb

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
)

func (s *Service) writeTransaction(ctx context.Context, plan *dataPlan, in *api.TransactWriteItemsInput, out *api.TransactWriteItemsOutput) error {
	return s.withMutation(ctx, plan.table, func() error {
		if value(in.ClientRequestToken) == "" && !s.needsCapacity(in.ReturnConsumedCapacity, true, plan.table, plan.additional...) {
			return s.callEngine(ctx, plan.table, "TransactWriteItems", in, out)
		}
		key := TransactionCapacityKey{Scope: plan.table.Key.Scope, Token: value(in.ClientRequestToken)}
		replay, err := s.transactionReadCapacity(ctx, key, string(value(in.ReturnConsumedCapacity)), string(value(in.ReturnItemCollectionMetrics)), in)
		if err != nil {
			return err
		}
		if replay != nil && len(replay.Read) != 0 {
			if err := s.admitPlan(ctx, plan, false); err != nil {
				return err
			}
			// Keep native item equality and execution checks, after checking the
			// response modes that DynamoDB Local omits from token identity.
			if err := s.callEngine(ctx, plan.table, "TransactWriteItems", in, out); err != nil {
				return err
			}
			out.ConsumedCapacity = replay.capacity()
			s.chargeReplay(plan, replay)
			return s.completeCapacities(ctx, plan, &out.ConsumedCapacity, in.ReturnConsumedCapacity, false)
		}
		if err := s.admitPlan(ctx, plan, true); err != nil {
			return err
		}
		writes := make([]capacityWrite, len(in.TransactItems))
		for i, request := range in.TransactItems {
			write := &writes[i]
			switch {
			case request.Put != nil:
				write.table = plan.tables[value(request.Put.TableName)]
				write.after = api.AttributeMap(request.Put.Item)
				write.key = capacityKey(write.table.Data.KeySchema, write.after)
			case request.Update != nil:
				write.table = plan.tables[value(request.Update.TableName)]
				write.key, write.readAfter = request.Update.Key, true
			case request.Delete != nil:
				write.table = plan.tables[value(request.Delete.TableName)]
				write.key = request.Delete.Key
			case request.ConditionCheck != nil:
				write.table = plan.tables[value(request.ConditionCheck.TableName)]
				write.key = request.ConditionCheck.Key
				write.conditionOnly = true
			}
			// A native token replay can succeed without applying the request.
			// Captures retain the current item, not the assumed Put/Delete image.
			if key.Token != "" && (write.table.RecoveryID != "" || write.table.Replica.GroupID != "") && (request.Put != nil || request.Delete != nil) {
				write.readAfter = true
			}
		}
		if err := s.collectCapacityImages(ctx, plan, writes, false); err != nil {
			return err
		}
		for i, request := range in.TransactItems {
			if request.ConditionCheck != nil {
				writes[i].after = writes[i].before
			}
		}
		pending, err := s.beginMutationWrite(ctx, writes, nil, true)
		if err != nil {
			return err
		}
		if err := s.callEngine(ctx, plan.table, "TransactWriteItems", in, out); err != nil {
			if replay == nil {
				err = s.retainCanceledTransaction(ctx, key, string(value(in.ReturnConsumedCapacity)), string(value(in.ReturnItemCollectionMetrics)), in, err)
			}
			return s.observeTransactionFailure(ctx, writes, err)
		}
		if err := s.collectCapacityImages(ctx, plan, writes, true); err != nil {
			return err
		}
		if err := s.finishMutationWrite(ctx, pending, writes, nil); err != nil {
			return err
		}
		// Recovery uses observed postimages; capacity keeps the existing
		// request-image accounting for Put/Delete.
		for i, request := range in.TransactItems {
			if request.Put != nil {
				writes[i].after = api.AttributeMap(request.Put.Item)
			} else if request.Delete != nil {
				writes[i].after = nil
			}
		}
		charges := aggregateWrites(writes, true, nil)
		out.ConsumedCapacity = make(api.ConsumedCapacityMultiple, 0, len(charges))
		for _, charge := range charges {
			out.ConsumedCapacity = append(out.ConsumedCapacity, charge.capacity(charge.table.PhysicalName, true))
			s.admission.charge(charge.table, &out.ConsumedCapacity[len(out.ConsumedCapacity)-1], true)
		}
		if err := s.retainTransactionCapacity(ctx, key, charges, string(value(in.ReturnConsumedCapacity)), string(value(in.ReturnItemCollectionMetrics)), ""); err != nil {
			return err
		}
		return s.completeCapacities(ctx, plan, &out.ConsumedCapacity, in.ReturnConsumedCapacity, true)
	}, plan.additional...)
}

func (s *Service) transactionReadCapacity(ctx context.Context, key TransactionCapacityKey, requestedCapacity, requestedCollectionMetrics string, in any) (*TransactionCapacity, error) {
	if key.Token == "" {
		return nil, nil
	}
	var recorded TransactionCapacity
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		recorded, err = r.TransactionCapacity(key)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Native engine idempotency runs on its own clock, like its other internal
	// execution state; advancing service time does not advance container clocks.
	if !recorded.ExpiresAt.After(time.Now()) {
		return nil, nil
	}
	if recorded.ReturnConsumedCapacity != transactionResponseMode(requestedCapacity) || recorded.ReturnItemCollectionMetrics != transactionResponseMode(requestedCollectionMetrics) {
		return nil, failure("IdempotentParameterMismatchException", "A client request token cannot be reused with different parameters.")
	}
	if recorded.CanceledRequest != "" {
		identity, err := transactionRequestIdentity(in)
		if err != nil {
			return nil, err
		}
		if identity != recorded.CanceledRequest {
			return nil, failure("IdempotentParameterMismatchException", "A client request token cannot be reused with different parameters.")
		}
	}
	return &recorded, nil
}

func (s *Service) retainTransactionCapacity(ctx context.Context, key TransactionCapacityKey, charges []tableWriteCharge, requestedCapacity, requestedCollectionMetrics, canceledRequest string) error {
	if key.Token == "" {
		return nil
	}
	now := time.Now().UTC()
	recorded := TransactionCapacity{Key: key, ExpiresAt: now.Add(10 * time.Minute), Read: make([]TransactionReadCapacity, len(charges))}
	recorded.ReturnConsumedCapacity = transactionResponseMode(requestedCapacity)
	recorded.ReturnItemCollectionMetrics = transactionResponseMode(requestedCollectionMetrics)
	recorded.CanceledRequest = canceledRequest
	for i, charge := range charges {
		recorded.Read[i] = TransactionReadCapacity{TableName: charge.table.Key.Name, Units: charge.read}
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.DeleteExpiredTransactionCapacities(now); err != nil {
			return err
		}
		return tx.PutTransactionCapacity(recorded)
	})
}

// Canceled requests retain token parameters without claiming a completed write.
// Native ValidationException does not reserve the token.
func (s *Service) retainCanceledTransaction(ctx context.Context, key TransactionCapacityKey, requestedCapacity, requestedCollectionMetrics string, in any, err error) error {
	var rejected *awswire.Error
	if errors.As(err, &rejected) && rejected.Code == "TransactionCanceledException" {
		identity, identityErr := transactionRequestIdentity(in)
		if identityErr != nil {
			return identityErr
		}
		if retainErr := s.retainTransactionCapacity(ctx, key, nil, requestedCapacity, requestedCollectionMetrics, identity); retainErr != nil {
			return retainErr
		}
	}
	return err
}

func transactionResponseMode(mode string) string {
	if mode == "" {
		return "NONE"
	}
	return mode
}

func (recorded *TransactionCapacity) capacity() api.ConsumedCapacityMultiple {
	out := make(api.ConsumedCapacityMultiple, len(recorded.Read))
	for i, charge := range recorded.Read {
		units := api.ConsumedCapacityUnits(charge.Units)
		out[i] = api.ConsumedCapacity{
			TableName: new(api.TableArn(charge.TableName)), CapacityUnits: &units, ReadCapacityUnits: &units,
			Table: &api.Capacity{CapacityUnits: &units, ReadCapacityUnits: &units},
		}
	}
	return out
}
