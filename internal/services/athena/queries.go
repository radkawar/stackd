package athena

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/athena"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func registerQueries(s *Service) {
	registerControl(s, "StartQueryExecution", s.startQueryExecution)
	registerControl(s, "GetQueryExecution", s.getQueryExecution)
	registerControl(s, "ListQueryExecutions", s.listQueryExecutions)
	registerControl(s, "StopQueryExecution", s.stopQueryExecution)
	s.operations["GetQueryResults"] = s.queryResultsCommand
}
func (s *Service) startQueryExecution(ctx context.Context, tx Transaction, in *api.StartQueryExecutionInput) (*api.StartQueryExecutionOutput, error) {
	token := value(in.ClientRequestToken)
	if len(token) < 32 || len(token) > 128 {
		return nil, invalidRequest("ClientRequestToken must contain between 32 and 128 characters.")
	}
	if strings.TrimSpace(value(in.QueryString)) == "" {
		return nil, invalidRequest("QueryString must not be empty.")
	}
	canonical := *in
	canonical.ClientRequestToken = nil
	canonical.WorkGroup = new(api.WorkGroupName(workGroupName(value(in.WorkGroup))))
	hash, err := fingerprint(canonical)
	if err != nil {
		return nil, err
	}
	previous, err := tx.QueryByToken(scopeFor(ctx), token)
	if err == nil {
		if previous.Fingerprint != hash {
			return nil, invalidRequest("ClientRequestToken was already used with different parameters.")
		}
		if _, err := s.loadWorkGroup(ctx, tx, value(previous.Data.WorkGroup), "StartQueryExecution"); err != nil {
			return nil, err
		}
		return &api.StartQueryExecutionOutput{QueryExecutionId: previous.Data.QueryExecutionId}, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	group, err := s.loadWorkGroup(ctx, tx, value(in.WorkGroup), "StartQueryExecution")
	if err != nil {
		return nil, err
	}
	if value(group.Data.State) != "ENABLED" {
		return nil, invalidRequest("The workgroup is disabled.")
	}
	tokens := statementTokens{sql: value(in.QueryString)}
	first, _ := tokens.next()
	if keyword(first, "PREPARE") || keyword(first, "DEALLOCATE") {
		// TODO: Comeback: persist native added/deallocated prepare deltas in
		// the workgroup repository before admitting SQL PREPARE/DEALLOCATE.
		return nil, unsupported("SQL PREPARE and DEALLOCATE are unavailable; use the prepared-statement API.")
	}
	if s.engine == nil || s.results == nil {
		return nil, unsupported("No Athena SQL engine and S3 result adapter are configured.")
	}
	if in.EngineConfiguration != nil {
		return nil, unsupported("Provisioned-capacity engine configuration is unavailable.")
	}
	results := effectiveResults(group.Data.Configuration, in.ResultConfiguration)
	if err := validateResults(&results, true); err != nil {
		return nil, err
	}
	if enabled(group.Data.Configuration.EnableMinimumEncryptionConfiguration) && group.Data.Configuration.ResultConfiguration != nil && group.Data.Configuration.ResultConfiguration.EncryptionConfiguration != nil {
		minimum := group.Data.Configuration.ResultConfiguration.EncryptionConfiguration
		if results.EncryptionConfiguration == nil || encryptionStrength(value(results.EncryptionConfiguration.EncryptionOption)) < encryptionStrength(value(minimum.EncryptionOption)) {
			return nil, invalidRequest("Query encryption does not meet the workgroup minimum configuration.")
		}
	}
	executionContext := &api.QueryExecutionContext{}
	if in.QueryExecutionContext != nil {
		executionContext.Catalog = in.QueryExecutionContext.Catalog
		executionContext.Database = in.QueryExecutionContext.Database
	}
	if strings.EqualFold(value(executionContext.Catalog), "AwsDataCatalog") {
		executionContext.Catalog = new(api.CatalogNameString("awsdatacatalog"))
	} else if value(executionContext.Catalog) != "" {
		if _, err := s.loadCatalog(ctx, tx, value(executionContext.Catalog), "GetDataCatalog"); err != nil {
			return nil, err
		}
	}
	key := resourceFor(ctx, uuid.NewString())
	results.OutputLocation = new(api.ResultOutputLocation(resultObject(value(results.OutputLocation), key.Name)))
	now := s.clock.Now()
	v := QueryRecord{Key: key, Token: token, Fingerprint: hash, Caller: awsctx.FromContext(ctx), ParentEventID: apievents.EventID(ctx), Version: 1, Due: now, PublishMetrics: enabled(group.Data.Configuration.PublishCloudWatchMetricsEnabled), Data: api.QueryExecution{QueryExecutionId: new(api.QueryExecutionId(key.Name)), Query: in.QueryString, WorkGroup: new(api.WorkGroupName(group.Key.Name)), QueryExecutionContext: executionContext, ResultConfiguration: &results, ResultReuseConfiguration: in.ResultReuseConfiguration, ExecutionParameters: in.ExecutionParameters, EngineVersion: group.Data.Configuration.EngineVersion, Status: &api.QueryExecutionStatus{State: new(api.QueryExecutionState("QUEUED")), SubmissionDateTime: &now}}}
	if group.Data.Configuration.BytesScannedCutoffPerQuery != nil {
		v.BytesCutoff = int64(*group.Data.Configuration.BytesScannedCutoffPerQuery)
	}
	v.RequesterPays = enabled(group.Data.Configuration.RequesterPaysEnabled)
	if class := statementClass(first, &tokens); class != "" {
		v.Data.StatementType = new(api.StatementType(class))
	}
	if v.Data.ResultReuseConfiguration == nil {
		v.Data.ResultReuseConfiguration = &api.ResultReuseConfiguration{ResultReuseByAgeConfiguration: &api.ResultReuseByAgeConfiguration{Enabled: new(api.Boolean(false))}}
	}
	// Result reuse is a permission to reuse, not a guarantee; executing the query
	// freshly is valid and must be reported as ReusedPreviousResult=false.
	if err := s.putTransition(tx, v, ""); err != nil {
		return nil, err
	}
	return &api.StartQueryExecutionOutput{QueryExecutionId: v.Data.QueryExecutionId}, nil
}
func encryptionStrength(option string) int {
	switch option {
	case "SSE_S3":
		return 1
	case "SSE_KMS", "CSE_KMS":
		return 2
	}
	return 0
}
func (s *Service) getQueryExecution(ctx context.Context, tx Transaction, in *api.GetQueryExecutionInput) (*api.GetQueryExecutionOutput, error) {
	v, err := s.loadQuery(ctx, tx, value(in.QueryExecutionId), "GetQueryExecution")
	if err != nil {
		return nil, err
	}
	return &api.GetQueryExecutionOutput{QueryExecution: &v.Data}, nil
}
func (s *Service) listQueryExecutions(ctx context.Context, tx Transaction, in *api.ListQueryExecutionsInput) (*api.ListQueryExecutionsOutput, error) {
	group, err := s.loadWorkGroup(ctx, tx, value(in.WorkGroup), "ListQueryExecutions")
	if err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.MaxResults, 50)
	if err != nil {
		return nil, err
	}
	after, err := cursor(group.Key.Scope, "queries", group.Key.Name, in.NextToken)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Queries(ResourceQuery{Scope: group.Key.Scope, WorkGroup: group.Key.Name, After: after, Limit: limit + 1})
	if err != nil {
		return nil, err
	}
	out := &api.ListQueryExecutionsOutput{QueryExecutionIds: api.QueryExecutionIdList{}}
	if len(rows) > limit {
		out.NextToken = nextToken(group.Key.Scope, "queries", group.Key.Name, rows[limit-1].Key.Name)
		rows = rows[:limit]
	}
	for _, v := range rows {
		out.QueryExecutionIds = append(out.QueryExecutionIds, api.QueryExecutionId(v.Key.Name))
	}
	return out, nil
}
func (s *Service) stopQueryExecution(ctx context.Context, tx Transaction, in *api.StopQueryExecutionInput) (*api.StopQueryExecutionOutput, error) {
	v, err := s.loadQuery(ctx, tx, value(in.QueryExecutionId), "StopQueryExecution")
	if err != nil {
		return nil, err
	}
	state := queryState(v)
	if state == "SUCCEEDED" || state == "FAILED" || state == "CANCELLED" {
		return &api.StopQueryExecutionOutput{}, nil
	}
	now := s.clock.Now()
	v.Data.Status.State = new(api.QueryExecutionState("CANCELLED"))
	v.Data.Status.StateChangeReason = new(api.String("Query was cancelled."))
	v.Data.Status.CompletionDateTime = &now
	v.Version++
	v.Due = now
	if err := s.putTransition(tx, v, state); err != nil {
		return nil, err
	}
	return &api.StopQueryExecutionOutput{}, nil
}

func (s *Service) queryResultsCommand(ctx context.Context) (any, *awswire.Error) {
	in, ok := awsapi.Input[api.GetQueryResultsInput](ctx)
	if !ok {
		return nil, failure("InternalServerException", "Missing generated Athena request binding.", 500)
	}
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	var query QueryRecord
	var offset, limit int
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		var err error
		query, err = s.loadQuery(tx.Context(), tx, value(in.QueryExecutionId), "GetQueryResults")
		if err != nil {
			return err
		}
		if queryState(query) != "SUCCEEDED" {
			return invalidRequest("Query has not yet finished. Current state: " + queryState(query))
		}
		kind := value(in.QueryResultType)
		if kind != "" && kind != "DATA_ROWS" {
			if kind != "DATA_MANIFEST" {
				return invalidRequest("Invalid QueryResultType.")
			}
			if query.Data.Statistics == nil || value(query.Data.Statistics.DataManifestLocation) == "" {
				return invalidRequest("This query does not have a data manifest.")
			}
			// TODO: Comeback expose actual native CTAS/INSERT/UNLOAD manifest objects and their result metadata.
			return unsupported("Manifest result retrieval is unavailable.")
		}
		limit, err = pageLimit(in.MaxResults, 1000)
		if err != nil {
			return err
		}
		after, err := cursor(query.Key.Scope, "results", query.Key.Name, in.NextToken)
		if err != nil {
			return err
		}
		if after != "" {
			offset, err = strconv.Atoi(after)
			if err != nil || offset < 0 {
				return invalidRequest("Invalid pagination token.")
			}
		}
		return nil
	})
	var out *api.GetQueryResultsOutput
	if err == nil {
		if s.results == nil {
			err = unsupported("No S3 result adapter is configured.")
		} else {
			data, rejected := s.results.Read(ctx, query)
			if rejected != nil {
				err = rejected
			} else {
				var rows api.RowList
				var more bool
				rows, more, err = resultRows(data, offset, limit)
				if err == nil {
					out = &api.GetQueryResultsOutput{
						ResultSet: &api.ResultSet{
							ResultSetMetadata: &api.ResultSetMetadata{ColumnInfo: query.Columns},
							Rows:              rows,
						},
						UpdateCount: new(api.Long(query.UpdateCount)),
					}
					if more || len(rows) == limit {
						out.NextToken = nextToken(query.Key.Scope, "results", query.Key.Name, strconv.Itoa(offset+len(rows)))
					}
				}
			}
		}
	}
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	if err := s.recordCall(completion, "GetQueryResults", in, out, rejected); err != nil {
		return nil, wireError(err)
	}
	if rejected != nil {
		return nil, rejected
	}
	return out, nil
}
