package dynamodb

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// The request retains the authoritative records resolved before engine execution.
// Re-reading after an external call could observe a deleted/recreated table with
// a different key schema, and consequently expose a formerly non-key attribute.
type auditTablesKey struct{}
type auditTables map[TableKey]*TableRecord

func withAuditTables(ctx context.Context) context.Context {
	return context.WithValue(ctx, auditTablesKey{}, make(auditTables))
}

func rememberAuditTable(ctx context.Context, table *TableRecord) {
	if tables, ok := ctx.Value(auditTablesKey{}).(auditTables); ok && table != nil {
		tables[table.Key] = table
	}
}

var auditManagementRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"ExportTime": {TimeLayout: time.RFC3339},
	"IncrementalExportSpecification.ExportFromTime": {TimeLayout: time.RFC3339},
	"IncrementalExportSpecification.ExportToTime":   {TimeLayout: time.RFC3339},
	"RestoreDateTime":     {TimeLayout: time.RFC3339},
	"TimeRangeLowerBound": {TimeLayout: time.RFC3339},
	"TimeRangeUpperBound": {TimeLayout: time.RFC3339},
}}

var auditTableResponse = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"TableDescription.CreationDateTime":                                                  {TimeLayout: time.RFC3339},
	"TableDescription.BillingModeSummary.LastUpdateToPayPerRequestDateTime":              {TimeLayout: time.RFC3339},
	"TableDescription.ProvisionedThroughput.LastIncreaseDateTime":                        {TimeLayout: time.RFC3339},
	"TableDescription.ProvisionedThroughput.LastDecreaseDateTime":                        {TimeLayout: time.RFC3339},
	"TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.LastIncreaseDateTime": {TimeLayout: time.RFC3339},
	"TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.LastDecreaseDateTime": {TimeLayout: time.RFC3339},
	"TableDescription.TableClassSummary.LastUpdateDateTime":                              {TimeLayout: time.RFC3339},
	"TableDescription.RestoreSummary.RestoreDateTime":                                    {TimeLayout: time.RFC3339},
	"TableDescription.ArchivalSummary.ArchivalDateTime":                                  {TimeLayout: time.RFC3339},
	"TableDescription.SSEDescription.InaccessibleEncryptionDateTime":                     {TimeLayout: time.RFC3339},
	"TableDescription.Replicas.ReplicaInaccessibleDateTime":                              {TimeLayout: time.RFC3339},
	"TableDescription.Replicas.ReplicaTableClassSummary.LastUpdateDateTime":              {TimeLayout: time.RFC3339},
}}

var auditReplicaScalingResponse awsapi.DocumentProjection

func auditProjection(action string) apievents.Projection {
	p := apievents.Projection{Category: journal.CategoryManagement, Request: auditManagementRequest}
	p.ReadOnly = strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "List") || action == "GetResourcePolicy"
	// logging-using-cloudtrail.html documents Query, Scan and SearchVectors;
	// audit_data.json independently captures the other eleven data operations.
	switch action {
	case "GetItem", "BatchGetItem", "TransactGetItems", "Query", "Scan", "SearchVectors":
		p.Category, p.ReadOnly, p.Request = journal.CategoryData, true, auditDataRequest
	case "PutItem", "UpdateItem", "DeleteItem", "BatchWriteItem", "TransactWriteItems", "ExecuteStatement", "BatchExecuteStatement", "ExecuteTransaction":
		// PartiQL SELECT is also readOnly=false in native events.
		p.Category, p.ReadOnly, p.Request = journal.CategoryData, false, auditDataRequest
	}
	if action == "ExecuteStatement" {
		// Both native SELECT waves supplied ConsistentRead=true; their events
		// retain only statement, just like the nested PartiQL batch members.
		p.Request = auditBatchStatementRequest
	}
	switch action {
	case "CreateTable", "UpdateTable", "DeleteTable":
		p.Response = &auditTableResponse
	case "UpdateTableReplicaAutoScaling":
		p.Response = &auditReplicaScalingResponse
	}
	return p
}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, ok := awscatalog.LookupService("dynamodb")
	if !ok {
		return errors.New("DynamoDB audit service metadata is missing")
	}
	op, ok := model.Operation(action)
	if !ok {
		return nil // Unknown operations do not have an authenticated API binding.
	}
	projection := auditProjection(action)
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	switch action {
	case "CreateGlobalTable", "DescribeGlobalTable", "ListGlobalTables", "UpdateGlobalTable":
		if rejected != nil && rejected.Code == "AccessDeniedException" {
			call.ErrorCode = "AccessDenied"
			call.RequestParameters = json.RawMessage("null")
		}
	}
	// Native prebinding throttles omit the API version as well as request fields.
	if in != nil || rejected == nil || rejected.Code != "ThrottlingException" {
		call.APIVersion = "2012-08-10"
	}
	call.EventID = apievents.EventID(ctx)
	tables, _ := ctx.Value(auditTablesKey{}).(auditTables)
	if tables == nil {
		tables = make(auditTables)
	}
	a := auditCall{service: s, ctx: ctx, model: model, tables: tables}
	var request map[string]any
	if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
		return err
	}
	if projection.Category == journal.CategoryData && in != nil {
		if request == nil {
			request = make(map[string]any)
		}
		if err := a.dataRequest(request, in); err != nil {
			return err
		}
		call.RequestParameters, err = json.Marshal(request)
		if err != nil {
			return err
		}
	}
	if a.unparsedStatement && rejected != nil {
		// Parser diagnostics may quote the offending literal. Preserve the
		// actual failure code without leaking it through a second audit field.
		call.ErrorMessage = "***(Redacted)"
	}
	switch action {
	case "DescribeBackup", "DeleteBackup", "RestoreTableFromBackup":
		// Native backup management events omit document resources, including
		// restore's target. HTTP response metadata is not a CloudTrail resource.
	case "UpdateContinuousBackups":
		if rejected == nil || rejected.Code != "ValidationException" {
			a.requestResources(request)
		}
	case "RestoreTableToPointInTime":
		for _, field := range []string{"targetTableName", "sourceTableName", "sourceTableArn"} {
			selector, _ := request[field].(string)
			a.resource(selector, "")
		}
	default:
		a.requestResources(request)
	}
	call.EventResources = a.resources
	switch action {
	case "CreateBackup", "DescribeBackup", "ListBackups", "DeleteBackup", "DescribeContinuousBackups", "RestoreTableToPointInTime":
		// Native LookupEvents has no aliases for these operations.
	case "CreateGlobalTable", "DescribeGlobalTable", "ListGlobalTables", "UpdateGlobalTable":
		// Legacy global APIs have regional detail resources but no lookup aliases.
	case "RestoreTableFromBackup":
		for _, field := range []string{"backupArn", "targetTableName"} {
			if name, ok := request[field].(string); ok {
				call.Resources = append(call.Resources, journal.APIResource{Type: "AWS::DynamoDB::Table", Name: name})
			}
		}
	case "UpdateContinuousBackups":
		if name, ok := request["tableName"].(string); ok {
			call.Resources = append(call.Resources, journal.APIResource{Type: "AWS::DynamoDB::Table", Name: name})
		}
	default:
		for _, resource := range a.resources {
			call.Resources = append(call.Resources, journal.APIResource{Type: resource.Type, Name: resource.ARN})
		}
	}
	if len(call.ResponseElements) != 0 {
		// Native adds this unmodeled summary alongside billingModeSummary.
		// Only these two evidenced fields are copied; public DTOs stay unchanged.
		var response struct {
			TableDescription map[string]json.RawMessage `json:"tableDescription"`
		}
		if err := json.Unmarshal(call.ResponseElements, &response); err != nil {
			return err
		}
		if billing := response.TableDescription["billingModeSummary"]; len(billing) != 0 {
			var summary struct {
				Mode    json.RawMessage `json:"billingMode"`
				Updated json.RawMessage `json:"lastUpdateToPayPerRequestDateTime"`
			}
			if err := json.Unmarshal(billing, &summary); err != nil {
				return err
			}
			throughput := struct {
				Mode    json.RawMessage `json:"tableThroughputMode,omitempty"`
				Updated json.RawMessage `json:"lastUpdateToPayPerRequestDateTime,omitempty"`
			}{summary.Mode, summary.Updated}
			body, err := json.Marshal(throughput)
			if err != nil {
				return err
			}
			response.TableDescription["tableThroughputModeSummary"] = body
			call.ResponseElements, err = json.Marshal(response)
			if err != nil {
				return err
			}
		}
	}
	scope := scopeFor(ctx)
	// One-owner requests use the resource recipient, not the signing account.
	// Mixed-owner rejected/batch calls retain caller scope and each resource's
	// explicit account rather than choosing an arbitrary map iteration winner.
	if len(a.resources) > 0 {
		owner, mixed := a.resourceScopes[0], false
		for _, candidate := range a.resourceScopes[1:] {
			if candidate != owner {
				mixed = true
				break
			}
		}
		if !mixed {
			scope = owner
		}
	}
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}

type auditCall struct {
	service           *Service
	ctx               context.Context
	model             awscatalog.Service
	tables            auditTables
	resources         []journal.APIEventResource
	resourceScopes    []Scope
	unparsedStatement bool
}

func (a *auditCall) table(selector string) (*TableRecord, error) {
	key, err := parseTableKey(a.ctx, selector)
	if err != nil || selector == "" {
		return nil, nil // An invalid selector is already the recorded API rejection.
	}
	if table, ok := a.tables[key]; ok {
		return table, nil
	}
	var table *TableRecord
	err = a.service.repository.View(a.ctx, func(reader Reader) error {
		found, err := reader.Table(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		table = &found
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.tables[key] = table
	return table, nil
}

func (a *auditCall) resource(selector, index string) {
	if selector == "" {
		return
	}
	key := TableKey{Scope: scopeFor(a.ctx), Name: selector}
	var suffix string
	if strings.HasPrefix(selector, "arn:") {
		parsed, err := arn.Parse(selector)
		if err != nil || parsed.Service != "dynamodb" || parsed.AccountID == "" || parsed.Region == "" || !strings.HasPrefix(parsed.Resource, "table/") {
			return
		}
		name, rest, _ := strings.Cut(strings.TrimPrefix(parsed.Resource, "table/"), "/")
		if name == "" {
			return
		}
		key = TableKey{Scope: Scope{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}, Name: name}
		suffix = rest
	}
	a.addResource(key.Scope, "AWS::DynamoDB::Table", key.ARN())
	if index != "" {
		suffix = "index/" + index
	}
	if suffix != "" {
		kind, _, _ := strings.Cut(suffix, "/")
		var resourceType string
		switch kind {
		case "index":
			resourceType = "AWS::DynamoDB::Index"
		case "stream":
			resourceType = "AWS::DynamoDB::Stream"
		case "backup":
			resourceType = "AWS::DynamoDB::Backup"
		case "export":
			resourceType = "AWS::DynamoDB::Export"
		case "import":
			resourceType = "AWS::DynamoDB::Import"
		}
		if resourceType != "" {
			a.addResource(key.Scope, resourceType, key.ARN()+"/"+suffix)
		}
	}
}

func (a *auditCall) addResource(scope Scope, resourceType, resourceARN string) {
	for _, resource := range a.resources {
		if resource.ARN == resourceARN {
			return
		}
	}
	a.resources = append(a.resources, journal.APIEventResource{AccountID: scope.AccountID, Type: resourceType, ARN: resourceARN})
	a.resourceScopes = append(a.resourceScopes, scope)
}

func (a *auditCall) requestResources(request map[string]any) {
	index, _ := request["indexName"].(string)
	for _, field := range []string{"tableName", "tableArn", "globalTableName", "resourceArn", "sourceTableName", "sourceTableArn", "targetTableName", "backupArn", "exportArn", "importArn"} {
		if selector, ok := request[field].(string); ok {
			a.resource(selector, index)
		}
	}
	if creation, ok := request["tableCreationParameters"].(map[string]any); ok {
		a.requestResources(creation)
	}
}
