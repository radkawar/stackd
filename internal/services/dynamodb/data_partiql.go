package dynamodb

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awswire"
	"stackd/internal/services/dynamodb/partiql"
)

type dataStatement struct {
	table            *TableRecord
	input            *api.PartiQLStatement
	action, selector string
	parsed           *partiql.Statement
	parameters       api.PreparedStatementParameters
	access           partiql.Access
}

func (s *Service) prepareStatement(ctx context.Context, r Reader, text string, parameters api.PreparedStatementParameters, enclosing string) (*dataStatement, error) {
	statement, err := partiql.Parse(text)
	if err != nil {
		return nil, failure("ValidationException", "Unable to authorize PartiQL statement: "+err.Error())
	}
	prepared := &dataStatement{action: statement.Action(), selector: statement.Table(), parsed: statement, parameters: parameters}
	table, err := s.dataTable(ctx, r, statement.Table())
	if err != nil {
		return prepared, err
	}
	prepared.table = table
	access, err := statement.Analyze(dataKeySchema(table, statement.Index()), parameters)
	if err != nil {
		return nil, failure("ValidationException", err.Error())
	}
	prepared.access = access
	conditions := map[string][]string{}
	if access.LeadingKeys != nil {
		conditions["dynamodb:LeadingKeys"] = access.LeadingKeys
	}
	if len(access.Attributes) > 0 {
		conditions["dynamodb:Attributes"] = access.Attributes
	}
	if access.FullTableScan != nil {
		conditions["dynamodb:FullTableScan"] = []string{strconv.FormatBool(*access.FullTableScan)}
	}
	if enclosing != "" {
		conditions["dynamodb:EnclosingOperation"] = []string{enclosing}
	}
	if err := s.authorizeTable(ctx, r, table.Key, statement.Action(), statement.Index(), conditions); err != nil {
		return prepared, err
	}
	rewritten := api.PartiQLStatement(statement.RewriteTable(table.PhysicalName))
	prepared.input = &rewritten
	return prepared, nil
}
func (s *Service) executeStatement(ctx context.Context, in *api.ExecuteStatementInput) (*api.ExecuteStatementOutput, error) {
	input := *in
	var statement *dataStatement
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		statement, err = s.prepareStatement(r.Context(), r, value(in.Statement), in.Parameters, "")
		return err
	})
	if err != nil {
		return nil, err
	}
	page, err := newStatementPage(statement.table, in)
	if err != nil {
		return nil, err
	}
	input.NextToken = page.native
	input.Statement = statement.input
	out := new(api.ExecuteStatementOutput)
	err = s.accountStatement(ctx, statement, &input, out)
	if err != nil {
		return nil, err
	}
	out.NextToken = page.next(out.NextToken)
	return out, nil
}

type dataStatementBatch struct {
	plan       dataPlan
	input      api.BatchExecuteStatementInput
	positions  []int
	statements []*dataStatement
}

// PartiQL batches report policy denial per statement, while transactions cancel
// atomically with a positional cancellation reason for every statement.
func statementAccessDenied(err error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(err, &wire) && (wire.Code == "AccessDenied" || wire.Code == "AccessDeniedException") {
		return wire
	}
	return nil
}
func (s *Service) batchExecuteStatement(ctx context.Context, in *api.BatchExecuteStatementInput) (*api.BatchExecuteStatementOutput, error) {
	if len(in.Statements) == 0 {
		return nil, failure("ValidationException", "The request must contain at least one statement.")
	}
	if len(in.Statements) > 25 {
		return nil, failure("ValidationException", "A batch cannot contain more than 25 statements.")
	}
	out := &api.BatchExecuteStatementOutput{Responses: make(api.PartiQLBatchResponse, len(in.Statements))}
	var groups []*dataStatementBatch
	var read, write bool
	seen := make(map[capacityItemID]bool, len(in.Statements))
	err := s.repository.View(ctx, func(r Reader) error {
		for i, request := range in.Statements {
			statement, err := s.prepareStatement(r.Context(), r, value(request.Statement), request.Parameters, "BatchExecuteStatement")
			if statement != nil {
				if statement.action == "PartiQLSelect" {
					read = true
				} else {
					write = true
				}
			}
			if err != nil {
				denied := statementAccessDenied(err)
				if denied == nil || statement == nil {
					return err
				}
				code := api.BatchStatementErrorCodeEnumAccessDenied
				message := api.String(denied.Message)
				table := api.TableName(statement.selector)
				out.Responses[i] = api.BatchStatementResponse{Error: &api.BatchStatementError{Code: &code, Message: &message}, TableName: &table}
				continue
			}
			// AWS rejects the whole request without effects. Local checks for
			// duplicates after executing writes, so this belongs before native
			// execution, independently of capacity publication.
			if key, known := statement.parsed.CapacityKey(statement.table.Data.KeySchema, request.Parameters); known {
				for _, attribute := range key {
					if _, valid := dataCanonicalScalar(attribute); !valid {
						known = false
						break
					}
				}
				if known {
					id := capacityKeyID(statement.table.DatabaseID+"/"+statement.table.PhysicalName, statement.table.Data.KeySchema, key)
					if seen[id] {
						return failure("ValidationException", "Provided list of item keys contains duplicates")
					}
					seen[id] = true
				}
			}
			var group *dataStatementBatch
			for _, candidate := range groups {
				if candidate.plan.table.DatabaseID == statement.table.DatabaseID && candidate.plan.table.Key.Scope == statement.table.Key.Scope {
					group = candidate
					break
				}
			}
			if group == nil {
				group = &dataStatementBatch{input: api.BatchExecuteStatementInput{ReturnConsumedCapacity: in.ReturnConsumedCapacity}}
				groups = append(groups, group)
			}
			if err := group.plan.add(&statement.table, statement.selector); err != nil {
				return err
			}
			text, parameters := statement.parsed.SingletonRead(statement.table.PhysicalName, statement.table.Data.KeySchema, request.Parameters)
			request.Statement = new(api.PartiQLStatement(text))
			request.Parameters = parameters
			group.input.Statements = append(group.input.Statements, request)
			group.positions = append(group.positions, i)
			group.statements = append(group.statements, statement)
		}
		if read && write {
			return failure("ValidationException", "Read and write requests together in the same batch is not supported.")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		part := new(api.BatchExecuteStatementOutput)
		err = s.accountStatementBatch(ctx, group, part, write)
		if err != nil {
			return nil, err
		}
		if len(part.Responses) != len(group.positions) {
			return nil, failure("InternalServerError", "The native engine returned an incomplete statement response.", 500)
		}
		if err := s.completeCapacities(ctx, &group.plan, &part.ConsumedCapacity, in.ReturnConsumedCapacity, write); err != nil {
			return nil, err
		}
		out.ConsumedCapacity = append(out.ConsumedCapacity, part.ConsumedCapacity...)
		for i, response := range part.Responses {
			if table, ok := group.plan.tables[value(response.TableName)]; ok {
				public := api.TableName(table.Key.Name)
				response.TableName = &public
			}
			out.Responses[group.positions[i]] = response
		}
	}
	return out, nil
}
func (s *Service) executeTransaction(ctx context.Context, in *api.ExecuteTransactionInput) (*api.ExecuteTransactionOutput, error) {
	input := *in
	input.TransactStatements = make(api.ParameterizedStatements, len(in.TransactStatements))
	plan := dataPlan{}
	var reasons api.CancellationReasonList
	var writes bool
	statements := make([]*dataStatement, len(in.TransactStatements))
	err := s.repository.View(ctx, func(r Reader) error {
		for i, request := range in.TransactStatements {
			statement, err := s.prepareStatement(r.Context(), r, value(request.Statement), request.Parameters, "ExecuteTransaction")
			if err != nil {
				denied := statementAccessDenied(err)
				if denied == nil {
					return err
				}
				if reasons == nil {
					reasons = make(api.CancellationReasonList, len(in.TransactStatements))
					none := api.Code("None")
					for j := range reasons {
						reasons[j].Code = &none
					}
				}
				code := api.Code("AccessDenied")
				message := api.ErrorMessage(denied.Message)
				reasons[i] = api.CancellationReason{Code: &code, Message: &message}
				continue
			}
			writes = writes || statement.action != "PartiQLSelect" || statement.parsed.ConditionCheck()
			statements[i] = statement
			if err := plan.add(&statement.table, statement.selector); err != nil {
				return err
			}
			input.TransactStatements[i] = request
			input.TransactStatements[i].Statement = statement.input
			input.TransactStatements[i].ReturnValuesOnConditionCheckFailure = transactionConditionReturn(request.ReturnValuesOnConditionCheckFailure)
			input.TransactStatements[i].Parameters, _ = transactionValues(request.Parameters)
		}
		if reasons != nil {
			codes := make([]string, len(reasons))
			for i, reason := range reasons {
				codes[i] = string(*reason.Code)
			}
			encoded, err := json.Marshal(reasons)
			if err != nil {
				return err
			}
			rejected := failure("TransactionCanceledException", "Transaction cancelled, please refer cancellation reasons for specific reasons ["+strings.Join(codes, ", ")+"]")
			rejected.Details = map[string]json.RawMessage{"CancellationReasons": encoded}
			return rejected
		}
		return plan.ready()
	})
	if err != nil {
		return nil, err
	}
	out := new(api.ExecuteTransactionOutput)
	err = s.accountStatementTransaction(ctx, &plan, statements, &input, out, writes)
	if err != nil {
		return nil, err
	}
	return out, nil
}
