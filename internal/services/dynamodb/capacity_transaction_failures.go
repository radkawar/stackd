package dynamodb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
)

// observeTransactionFailure records native cancellation results without changing
// the public error, cancellation positions, item state, or idempotency records.
func (s *Service) observeTransactionFailure(ctx context.Context, writes []capacityWrite, err error) error {
	var rejected *awswire.Error
	if !errors.As(err, &rejected) || rejected.Code != "TransactionCanceledException" {
		return err
	}
	raw := rejected.Details["CancellationReasons"]
	if len(raw) == 0 {
		return err
	}
	var reasons api.CancellationReasonList
	if decodeErr := json.Unmarshal(raw, &reasons); decodeErr != nil {
		return fmt.Errorf("decode DynamoDB transaction cancellation reasons: %w", decodeErr)
	}
	if len(reasons) == 0 {
		return err
	}
	if len(reasons) != len(writes) {
		return fmt.Errorf("DynamoDB transaction cancellation reasons: got %d positions for %d writes", len(reasons), len(writes))
	}

	writeCanceled, otherFailure := false, false
	for _, reason := range reasons {
		switch value(reason.Code) {
		case "ConditionalCheckFailed", "DuplicateItem":
			writeCanceled = true
		case "None":
		default:
			otherFailure = true
		}
	}
	if !writeCanceled {
		return err
	}

	type cancellationObservation struct {
		table           *TableRecord
		units, failures float64
	}
	charges := make(map[TableKey]cancellationObservation)
	for i, reason := range reasons {
		write := &writes[i]
		charge := charges[write.table.Key]
		charge.table = write.table
		if value(reason.Code) == "ConditionalCheckFailed" {
			charge.failures++
		}
		if !otherFailure {
			// Native canceled transactions charge the preimage, including items
			// with a None reason that were prepared but never committed. A large
			// attempted replacement does not enlarge that charge, and a missing
			// prepared item incurs the minimum. Do not use successful-transaction
			// index accounting or synthesize absent read/index observations.
			charge.units += 2 * writeUnits(itemSize(write.before))
		}
		charges[write.table.Key] = charge
	}
	for _, charge := range charges {
		s.observeWriteFailure(ctx, charge.table, charge.units, charge.failures)
	}
	return err
}
