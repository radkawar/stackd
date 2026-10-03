package dynamodb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	engine "stackd/engine/dynamodb"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
)

func tableSpecification(table *TableRecord) engine.Specification {
	k := table.Key
	return engine.Specification{ID: table.DatabaseID, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region}
}

// callEngine is the sole protocol boundary for item and table engine calls.
// Inputs and outputs remain generated types; no repository callback is held.
func (s *Service) callEngine(ctx context.Context, table *TableRecord, action string, in, out any) error {
	db, err := s.engines.database(ctx, tableSpecification(table))
	if err != nil {
		return err
	}
	model, _ := awscatalog.LookupService("dynamodb")
	return nativeCall(ctx, db, model, action, in, out, table)
}

// mutateEngine serializes native writes with stream ingestion. The pre-write
// flush separates recovered changes from this mutation's service-time/source
// interval; the engine still owns atomic item/transaction execution.
func (s *Service) mutateEngine(ctx context.Context, table *TableRecord, action string, in, out any, additional ...*TableRecord) error {
	return s.withMutation(ctx, table, func() error {
		return s.callEngine(ctx, table, action, in, out)
	}, additional...)
}

func (s *Service) withData(ctx context.Context, table *TableRecord, apply func() error) error {
	release, err := s.engines.lockData(ctx, table.DatabaseID)
	if err != nil {
		return err
	}
	defer release()
	return apply()
}

// withMutation keeps capacity observations and the native mutation in the same
// item-write interval. Engine reads here supply metadata absent from the write
// response; they do not authorize another customer operation or consume capacity.
func (s *Service) withMutation(ctx context.Context, table *TableRecord, apply func() error, additional ...*TableRecord) error {
	return s.withData(ctx, table, func() error {
		if err := s.prepareMutation(ctx, table.DatabaseID); err != nil {
			return err
		}
		if err := s.repository.View(ctx, func(r Reader) error {
			refresh := func(table *TableRecord) error {
				consumers, err := r.ActiveWriteConsumers(table.Key, table.PhysicalName)
				if err != nil {
					return err
				}
				table.RecoveryID = consumers.RecoveryID
				table.Replica.GroupID = consumers.ReplicationGroupID
				table.KinesisConsumers = consumers.Kinesis
				return nil
			}
			if err := refresh(table); err != nil {
				return err
			}
			for _, other := range additional {
				if err := refresh(other); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if err := s.captureTableStreams(ctx, table); err != nil {
			return err
		}
		for _, other := range additional {
			if err := s.captureTableStreams(ctx, other); err != nil {
				return err
			}
		}
		mutationErr := apply()
		if mutationErr != nil {
			mutationErr = errors.Join(mutationErr, s.failMutationWrite(ctx, table.DatabaseID, mutationErr))
		}
		captureErr := s.captureTableStreams(ctx, table)
		for _, other := range additional {
			captureErr = errors.Join(captureErr, s.captureTableStreams(ctx, other))
		}
		if mutationErr == nil {
			s.engines.wake()
		}
		return errors.Join(mutationErr, captureErr)
	})
}

func nativeCall(ctx context.Context, db engine.Database, model awscatalog.Service, action string, in, out any, table *TableRecord) error {
	op, ok := model.Operation(action)
	if !ok {
		return fmt.Errorf("missing generated %s operation %s", model.Name, action)
	}
	body, err := awsapi.EncodeDocument(model, op.Input, in, nil)
	if err != nil {
		return err
	}
	response, err := db.Request(ctx, model.TargetPrefix+"."+action, body)
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(response.Body, &fields); err != nil {
			return fmt.Errorf("decode %s engine HTTP %d error: %w", action, response.StatusCode, err)
		}
		var code, message string
		if err := json.Unmarshal(fields["__type"], &code); err != nil {
			return fmt.Errorf("%s engine HTTP %d omitted error type", action, response.StatusCode)
		}
		if _, suffix, found := strings.Cut(code, "#"); found {
			code = suffix
		}
		raw := fields["message"]
		if raw == nil {
			raw = fields["Message"]
		}
		if raw != nil {
			if err := json.Unmarshal(raw, &message); err != nil {
				return fmt.Errorf("decode %s engine error message: %w", action, err)
			}
		}
		if table != nil && table.PhysicalName != "" {
			message = strings.ReplaceAll(message, table.PhysicalName, table.Key.Name)
		}
		rejected := failure(code, message, response.StatusCode)
		delete(fields, "__type")
		delete(fields, "message")
		delete(fields, "Message")
		rejected.Details = fields
		return rejected
	}
	if err := awsapi.BindJSON(model, op.Output, response.Body, out); err != nil {
		return fmt.Errorf("decode %s engine response: %w", action, err)
	}
	return nil
}
