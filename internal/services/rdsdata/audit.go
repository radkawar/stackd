package rdsdata

import (
	"context"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/rdsdata"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// AWS's documented provisioned/serverless Aurora Data API sample masks SQL,
// database and schema, excludes result data, and identifies DBCluster data events:
// https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/logging-using-cloudtrail-data-api.html
// Parameter payloads are omitted here rather than guessing undocumented native
// shapes for populated parameter arrays. Driver errors may contain SQL literals,
// so only their modeled code crosses the audit boundary.
var auditRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"sql":           {Mode: awsapi.RedactValueField, Redaction: "**********"},
	"sqlStatements": {Mode: awsapi.RedactValueField, Redaction: "**********"},
	"database":      {Mode: awsapi.RedactValueField, Redaction: "**********"},
	"schema":        {Mode: awsapi.RedactValueField, Redaction: "**********"},
	"parameters":    {Mode: awsapi.OmitField},
	"parameterSets": {Mode: awsapi.OmitField},
}}

func (s *Service) recordCall(ctx context.Context, action string, in any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("rdsdata")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	// Do not infer readOnly from SQL text: ExecuteStatement can execute arbitrary
	// native functions. All five Data API operations are data-plane writes.
	p := apievents.Projection{Category: journal.CategoryData, Request: auditRequest}
	var sanitized *awswire.Error
	if rejected != nil {
		sanitized = failure(rejected.Code, "The RDS Data API request failed.", rejected.StatusCode)
	}
	call, err := p.Call(model, op, in, nil, sanitized)
	if err != nil {
		return err
	}
	call.EventType = journal.EventTypeRDSData
	call.EventID = apievents.EventID(ctx)
	resource := ""
	switch v := in.(type) {
	case *api.ExecuteStatementRequest:
		resource = value(v.ResourceArn)
	case *api.BatchExecuteStatementRequest:
		resource = value(v.ResourceArn)
	case *api.BeginTransactionRequest:
		resource = value(v.ResourceArn)
	case *api.CommitTransactionRequest:
		resource = value(v.ResourceArn)
	case *api.RollbackTransactionRequest:
		resource = value(v.ResourceArn)
	case *api.ExecuteSqlRequest:
		resource = value(v.DbClusterOrInstanceArn)
	}
	m := awsctx.FromContext(ctx)
	if resource != "" {
		call.EventResources = []journal.APIEventResource{{Type: "AWS::RDS::DBCluster", ARN: resource, AccountID: m.AccountID}}
	}
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, call)
}
