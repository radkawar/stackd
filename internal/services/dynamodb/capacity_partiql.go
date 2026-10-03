package dynamodb

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
)

func statementCapacityWrite(statement *dataStatement) (capacityWrite, bool) {
	key, ok := statement.parsed.CapacityKey(statement.table.Data.KeySchema, statement.parameters)
	return capacityWrite{table: statement.table, key: key, readBefore: true,
		readAfter: statement.action == "PartiQLInsert" || statement.action == "PartiQLUpdate"}, ok
}

func (s *Service) accountStatement(ctx context.Context, statement *dataStatement, in *api.ExecuteStatementInput, out *api.ExecuteStatementOutput) error {
	observePartiQLMetricOperation(ctx, "", statement.action)
	return s.withMutation(ctx, statement.table, func() error {
		if !s.needsCapacity(in.ReturnConsumedCapacity, statement.action != "PartiQLSelect", statement.table) {
			if statement.action == "PartiQLSelect" {
				return s.executeStatementRead(ctx, statement, in, out)
			}
			return s.callEngine(ctx, statement.table, "ExecuteStatement", in, out)
		}
		if err := s.admit(ctx, statement.table, statement.parsed.Index(), statement.action != "PartiQLSelect"); err != nil {
			return err
		}
		if statement.action == "PartiQLSelect" {
			native := *in
			native.ReturnConsumedCapacity = s.capacityRequest(in.ReturnConsumedCapacity, statement.table)
			if err := s.executeStatementRead(ctx, statement, &native, out); err != nil {
				return err
			}
			if out.ConsumedCapacity != nil {
				s.admission.charge(statement.table, out.ConsumedCapacity, false)
				return s.completeCapacity(ctx, statement.table, &out.ConsumedCapacity, in.ReturnConsumedCapacity, false)
			}
			capacity, err := s.statementReadCapacity(ctx, statement, in, false)
			if err != nil {
				return err
			}
			out.ConsumedCapacity = capacity
			s.admission.charge(statement.table, out.ConsumedCapacity, false)
			return s.completeCapacity(ctx, statement.table, &out.ConsumedCapacity, in.ReturnConsumedCapacity, false)
		}
		write, measurable := statementCapacityWrite(statement)
		var plan dataPlan
		if err := plan.add(&statement.table, statement.selector); err != nil {
			return err
		}
		writes := []capacityWrite{write}
		var imageErr error
		if measurable {
			imageErr = s.collectCapacityImages(ctx, &plan, writes, false)
		}
		// The original native request always decides validation and conditional
		// errors, including invalid keys that an image read cannot measure.
		native := *in
		native.ReturnValuesOnConditionCheckFailure = s.conditionCapacityRequest(in.ReturnValuesOnConditionCheckFailure, statement.table)
		pending, err := s.beginMutationWrite(ctx, writes, nil)
		if err != nil {
			return err
		}
		if err := s.callEngine(ctx, statement.table, "ExecuteStatement", &native, out); err != nil {
			var rejected *awswire.Error
			if measurable && imageErr == nil && errors.As(err, &rejected) && rejected.Code == "DuplicateItemException" {
				s.observeWriteFailure(ctx, statement.table, writeUnits(itemSize(writes[0].before)), 0)
			}
			return s.conditionFailure(ctx, statement.table, err, in.ReturnValuesOnConditionCheckFailure)
		}
		if imageErr != nil {
			return imageErr
		}
		if !measurable {
			return errors.New("native PartiQL write key was not available for capacity measurement")
		}
		if err := s.collectCapacityImages(ctx, &plan, writes, true); err != nil {
			return err
		}
		if err := s.finishMutationWrite(ctx, pending, writes, nil); err != nil {
			return err
		}
		var charge writeCharge
		charge.add(&writes[0], false)
		out.ConsumedCapacity = new(charge.capacity(statement.table.PhysicalName, false))
		s.admission.charge(statement.table, out.ConsumedCapacity, true)
		return s.completeCapacity(ctx, statement.table, &out.ConsumedCapacity, in.ReturnConsumedCapacity, true)
	})
}

func (s *Service) accountStatementBatch(ctx context.Context, group *dataStatementBatch, out *api.BatchExecuteStatementOutput, mutation bool) error {
	if !mutation && !s.needsCapacity(group.input.ReturnConsumedCapacity, false, group.plan.table, group.plan.additional...) {
		return s.callEngine(ctx, group.plan.table, "BatchExecuteStatement", &group.input, out)
	}
	return s.withMutation(ctx, group.plan.table, func() error {
		if mutation && !s.needsCapacity(group.input.ReturnConsumedCapacity, true, group.plan.table, group.plan.additional...) {
			return s.callEngine(ctx, group.plan.table, "BatchExecuteStatement", &group.input, out)
		}
		var writes []capacityWrite
		var imageErrors []error
		if mutation {
			writes = make([]capacityWrite, len(group.statements))
			imageErrors = make([]error, len(writes))
			allKeys := true
			for i, statement := range group.statements {
				var ok bool
				writes[i], ok = statementCapacityWrite(statement)
				if !ok {
					imageErrors[i] = errors.New("native PartiQL batch key was not available for capacity measurement")
				}
				allKeys = allKeys && ok
			}
			if !allKeys || s.collectCapacityImages(ctx, &group.plan, writes, false) != nil {
				for i := range writes {
					if imageErrors[i] == nil {
						imageErrors[i] = s.collectCapacityImages(ctx, &group.plan, writes[i:i+1], false)
					}
				}
			}
		}
		out.Responses = make(api.PartiQLBatchResponse, len(group.statements))
		// Local has no prepare/cost hook for UPDATE. Under configured pressure,
		// native singleton batches preserve per-statement errors while actual
		// postimages charge each completion before admitting the next sibling.
		step := len(group.statements)
		if group.plan.limited(mutation) {
			step = 1
		}
		failedUnits := make(map[string]api.ConsumedCapacityUnits)
		for start := 0; start < len(group.statements); start += step {
			end := min(start+step, len(group.statements))
			if step == 1 {
				statement := group.statements[start]
				if indexes := s.admission.check(statement.table, statement.parsed.Index(), mutation); len(indexes) != 0 {
					rejected := s.throttle(ctx, statement.table, indexes, mutation, 1)
					code := api.BatchStatementErrorCodeEnumProvisionedThroughputExceeded
					if rejected.Code == "ThrottlingException" {
						code = api.BatchStatementErrorCodeEnumThrottlingError
					}
					out.Responses[start] = api.BatchStatementResponse{
						TableName: new(api.TableName(statement.table.PhysicalName)),
						Error:     &api.BatchStatementError{Code: &code, Message: new(api.String(rejected.Message))},
					}
					continue
				}
			}
			native := group.input
			native.Statements = group.input.Statements[start:end]
			native.ReturnConsumedCapacity = nil
			if !mutation {
				native.ReturnConsumedCapacity = s.capacityRequest(group.input.ReturnConsumedCapacity, group.plan.table, group.plan.additional...)
			}
			var pendingCapture *MutationCapture
			if mutation {
				var err error
				if start != 0 {
					// Earlier singleton statements may have changed the same key.
					for i := start; i < end; i++ {
						writes[i].beforeObserved = false
					}
				}
				pendingCapture, err = s.beginMutationWrite(ctx, writes[start:end], nil)
				if err != nil {
					return err
				}
			}
			var part api.BatchExecuteStatementOutput
			if err := s.callEngine(ctx, group.plan.table, "BatchExecuteStatement", &native, &part); err != nil {
				return err
			}
			if len(part.Responses) != end-start {
				return errors.New("native PartiQL batch returned incomplete responses")
			}
			copy(out.Responses[start:end], part.Responses)
			if !mutation {
				if len(part.ConsumedCapacity) == 0 {
					for i := start; i < end; i++ {
						if out.Responses[i].Error != nil {
							continue
						}
						request := group.input.Statements[i]
						capacity, err := s.statementReadCapacity(ctx, group.statements[i], &api.ExecuteStatementInput{Statement: request.Statement, Parameters: request.Parameters, ConsistentRead: request.ConsistentRead}, false)
						if err != nil {
							return err
						}
						mergeStatementCapacity(&part.ConsumedCapacity, capacity)
					}
				}
				s.chargeCapacities(&group.plan, part.ConsumedCapacity, false)
				for i := range part.ConsumedCapacity {
					mergeStatementCapacity(&out.ConsumedCapacity, &part.ConsumedCapacity[i])
				}
				continue
			}
			var accepted []capacityWrite
			for i := start; i < end; i++ {
				response := out.Responses[i]
				if response.Error == nil {
					if imageErrors[i] != nil {
						return imageErrors[i]
					}
					accepted = append(accepted, writes[i])
					continue
				}
				code := value(response.Error.Code)
				if (code != "ConditionalCheckFailed" && code != "DuplicateItem") || imageErrors[i] != nil {
					continue
				}
				units := writeUnits(itemSize(writes[i].before))
				failedUnits[writes[i].table.PhysicalName] += api.ConsumedCapacityUnits(units)
				var failures float64
				if code == "ConditionalCheckFailed" {
					failures = 1
				}
				s.observeWriteFailure(ctx, writes[i].table, units, failures)
			}
			if err := s.collectCapacityImages(ctx, &group.plan, accepted, true); err != nil {
				return err
			}
			if err := s.finishMutationWrite(ctx, pendingCapture, accepted, nil); err != nil {
				return err
			}
			for _, charge := range aggregateWrites(accepted, false, nil) {
				capacity := charge.capacity(charge.table.PhysicalName, false)
				s.admission.charge(charge.table, &capacity, true)
				mergeStatementCapacity(&out.ConsumedCapacity, &capacity)
			}
		}
		// Failed writes enter only a successful table's overall aggregate, not
		// the accepted-write Table component. All-failed batches omit capacity.
		for i := range out.ConsumedCapacity {
			capacity := &out.ConsumedCapacity[i]
			if units := failedUnits[value(capacity.TableName)]; units != 0 {
				addCapacityUnits(&capacity.CapacityUnits, &units)
			}
		}
		return nil
	}, group.plan.additional...)
}

func (s *Service) accountStatementTransaction(ctx context.Context, plan *dataPlan, statements []*dataStatement, in *api.ExecuteTransactionInput, out *api.ExecuteTransactionOutput, mutation bool) error {
	operationType := "Read"
	if mutation {
		operationType = "Write"
	}
	observePartiQLMetricOperation(ctx, operationType, "")
	return s.withMutation(ctx, plan.table, func() error {
		if !s.needsCapacity(in.ReturnConsumedCapacity, mutation, plan.table, plan.additional...) && (!mutation || value(in.ClientRequestToken) == "") {
			return s.callEngine(ctx, plan.table, "ExecuteTransaction", in, out)
		}
		if !mutation {
			if err := s.admitPlan(ctx, plan, false); err != nil {
				return err
			}
			native := *in
			native.ReturnConsumedCapacity = s.capacityRequest(in.ReturnConsumedCapacity, plan.table, plan.additional...)
			if err := s.callEngine(ctx, plan.table, "ExecuteTransaction", &native, out); err != nil {
				return err
			}
			if len(out.ConsumedCapacity) != 0 {
				s.chargeCapacities(plan, out.ConsumedCapacity, false)
				return s.completeCapacities(ctx, plan, &out.ConsumedCapacity, in.ReturnConsumedCapacity, false)
			}
			out.ConsumedCapacity = nil
			for _, statement := range statements {
				capacity, err := s.statementReadCapacity(ctx, statement, &api.ExecuteStatementInput{Statement: statement.input, Parameters: statement.parameters, ConsistentRead: new(api.ConsistentRead(true))}, true)
				if err != nil {
					return err
				}
				mergeStatementCapacity(&out.ConsumedCapacity, capacity)
			}
			s.chargeCapacities(plan, out.ConsumedCapacity, false)
			return s.completeCapacities(ctx, plan, &out.ConsumedCapacity, in.ReturnConsumedCapacity, false)
		}
		key := TransactionCapacityKey{Scope: plan.table.Key.Scope, Token: value(in.ClientRequestToken)}
		replay, err := s.transactionReadCapacity(ctx, key, string(value(in.ReturnConsumedCapacity)), "", in)
		if err != nil {
			return err
		}
		if replay != nil && len(replay.Read) != 0 {
			if err := s.admitPlan(ctx, plan, false); err != nil {
				return err
			}
			if err := s.callEngine(ctx, plan.table, "ExecuteTransaction", in, out); err != nil {
				return err
			}
			out.ConsumedCapacity = replay.capacity()
			s.chargeReplay(plan, replay)
			return s.completeCapacities(ctx, plan, &out.ConsumedCapacity, in.ReturnConsumedCapacity, false)
		}
		if err := s.admitPlan(ctx, plan, true); err != nil {
			return err
		}
		writes := make([]capacityWrite, len(statements))
		measurable := true
		for i, statement := range statements {
			var ok bool
			writes[i], ok = statementCapacityWrite(statement)
			measurable = measurable && ok
			if key.Token != "" && (statement.table.RecoveryID != "" || statement.table.Replica.GroupID != "") && statement.action == "PartiQLDelete" {
				// Native token success can leave a subsequently recreated item.
				writes[i].readAfter = true
			}
		}
		var imageErr error
		if measurable {
			imageErr = s.collectCapacityImages(ctx, plan, writes, false)
		}
		for i, statement := range statements {
			if statement.parsed.ConditionCheck() {
				writes[i].after = writes[i].before
				writes[i].conditionOnly = true
			}
		}
		pending, err := s.beginMutationWrite(ctx, writes, nil, true)
		if err != nil {
			return err
		}
		if err := s.callEngine(ctx, plan.table, "ExecuteTransaction", in, out); err != nil {
			if replay == nil {
				err = s.retainCanceledTransaction(ctx, key, string(value(in.ReturnConsumedCapacity)), "", in, err)
			}
			if measurable && imageErr == nil {
				return s.observeTransactionFailure(ctx, writes, err)
			}
			return err
		}
		if imageErr != nil {
			return imageErr
		}
		if !measurable {
			return errors.New("native PartiQL transaction keys were not available for capacity measurement")
		}
		if err := s.collectCapacityImages(ctx, plan, writes, true); err != nil {
			return err
		}
		if err := s.finishMutationWrite(ctx, pending, writes, nil); err != nil {
			return err
		}
		// Preserve DELETE capacity accounting after retaining actual postimages.
		for i, statement := range statements {
			if statement.action == "PartiQLDelete" {
				writes[i].after = nil
			}
		}
		charges := aggregateWrites(writes, true, nil)
		out.ConsumedCapacity = make(api.ConsumedCapacityMultiple, 0, len(charges))
		for _, charge := range charges {
			out.ConsumedCapacity = append(out.ConsumedCapacity, charge.capacity(charge.table.PhysicalName, true))
			s.admission.charge(charge.table, &out.ConsumedCapacity[len(out.ConsumedCapacity)-1], true)
		}
		if err := s.retainTransactionCapacity(ctx, key, charges, string(value(in.ReturnConsumedCapacity)), "", ""); err != nil {
			return err
		}
		return s.completeCapacities(ctx, plan, &out.ConsumedCapacity, in.ReturnConsumedCapacity, true)
	}, plan.additional...)
}

func mergeStatementCapacity(into *api.ConsumedCapacityMultiple, capacity *api.ConsumedCapacity) {
	for i := range *into {
		current := &(*into)[i]
		if value(current.TableName) != value(capacity.TableName) {
			continue
		}
		addCapacityUnits(&current.CapacityUnits, capacity.CapacityUnits)
		addCapacityUnits(&current.ReadCapacityUnits, capacity.ReadCapacityUnits)
		addCapacityUnits(&current.WriteCapacityUnits, capacity.WriteCapacityUnits)
		mergeCapacityPart(&current.Table, capacity.Table)
		mergeCapacityIndexes(&current.LocalSecondaryIndexes, capacity.LocalSecondaryIndexes)
		mergeCapacityIndexes(&current.GlobalSecondaryIndexes, capacity.GlobalSecondaryIndexes)
		return
	}
	*into = append(*into, *capacity)
}

func addCapacityUnits(into **api.ConsumedCapacityUnits, units *api.ConsumedCapacityUnits) {
	if units == nil {
		return
	}
	if *into == nil {
		*into = new(api.ConsumedCapacityUnits)
	}
	**into += *units
}

func mergeCapacityPart(into **api.Capacity, part *api.Capacity) {
	if part == nil {
		return
	}
	if *into == nil {
		*into = new(api.Capacity)
	}
	addCapacityUnits(&(*into).CapacityUnits, part.CapacityUnits)
	addCapacityUnits(&(*into).ReadCapacityUnits, part.ReadCapacityUnits)
	addCapacityUnits(&(*into).WriteCapacityUnits, part.WriteCapacityUnits)
}

func mergeCapacityIndexes(into *api.SecondaryIndexesCapacityMap, indexes api.SecondaryIndexesCapacityMap) {
	if len(indexes) == 0 {
		return
	}
	if *into == nil {
		*into = make(api.SecondaryIndexesCapacityMap, len(indexes))
	}
	for name, part := range indexes {
		current := (*into)[name]
		pointer := &current
		mergeCapacityPart(&pointer, &part)
		(*into)[name] = current
	}
}
