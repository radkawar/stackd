package cloudwatch

import (
	"context"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

var metricPublicationProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"MetricData.Counts":            {Mode: awsapi.OmitField},
	"MetricData.StatisticValues":   {Mode: awsapi.OmitField},
	"MetricData.StorageResolution": {Mode: awsapi.OmitField},
	"MetricData.Timestamp":         {Mode: awsapi.OmitField},
	"MetricData.Unit":              {Mode: awsapi.OmitField},
	"MetricData.Value":             {Mode: awsapi.OmitField},
	"MetricData.Values":            {Mode: awsapi.OmitField},
	// TODO: Comeback capture entity metric audit identities alongside real entity associations.
	"EntityMetricData": {Mode: awsapi.OmitField},
}}

var metricQueryProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"StartTime": {TimeLayout: time.RFC3339},
	"EndTime":   {TimeLayout: time.RFC3339},
}}

var dashboardWriteProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"DashboardBody": {Mode: awsapi.RedactValueField},
}}

func (s *Service) record(ctx context.Context, decoded awsapi.DecodedRequest, output any, wire *awswire.Error) error {
	if s.apiEvents == nil {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryData, ReadOnly: true}
	input := decoded.Input
	dashboard := false
	switch decoded.Operation.Name {
	case "PutMetricData":
		projection.ReadOnly = false
		projection.Request = metricPublicationProjection
	case "GetMetricStatistics", "GetMetricData":
		projection.Request = metricQueryProjection
	case "ListMetrics":
		if in, ok := input.(*api.ListMetricsInput); ok {
			copy := *in
			if copy.IncludeLinkedAccounts == nil {
				copy.IncludeLinkedAccounts = new(api.IncludeLinkedAccounts(false))
			}
			input = &copy
		}
	case "GetDashboard", "ListDashboards":
		dashboard = true
		projection.Category = journal.CategoryManagement
	case "PutDashboard", "DeleteDashboards":
		dashboard = true
		projection.Category = journal.CategoryManagement
		projection.ReadOnly = false
		if decoded.Operation.Name == "PutDashboard" {
			projection.Request = dashboardWriteProjection
			projection.Response = &awsapi.DocumentProjection{}
		}
	case "DescribeAlarms", "DescribeAlarmsForMetric", "DescribeAlarmHistory", "ListTagsForResource":
		projection.Category = journal.CategoryManagement
	case "PutMetricAlarm", "PutCompositeAlarm", "DeleteAlarms", "SetAlarmState",
		"EnableAlarmActions", "DisableAlarmActions", "TagResource", "UntagResource":
		projection.Category = journal.CategoryManagement
		projection.ReadOnly = false
	default:
		return nil
	}
	model, _ := awscatalog.LookupService("cloudwatch")
	call, err := projection.Call(model, decoded.Operation, input, output, wire)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	denied := wire != nil && (wire.Code == "AccessDenied" || wire.Code == "AccessDeniedException")
	if projection.Category == journal.CategoryData || dashboard && !denied {
		call.EventResources = []journal.APIEventResource{{Type: "AWS::CloudWatch::Metric"}}
	} else if wire != nil {
		// Native reserved-key TagResource denials omit the entire request.
		// Other authorization failures keep their observed public parameters.
		if decoded.Operation.Name == "TagResource" && wire.Code == "AccessDenied" {
			if in, ok := input.(*api.TagResourceInput); ok {
				for _, tag := range in.Tags {
					if strings.HasPrefix(strings.ToLower(value(tag.Key)), "aws:") {
						call.RequestParameters = nil
						break
					}
				}
			}
		}
		// CloudWatch's query validation code is not modeled as an operation
		// error, but native management audit records use ValidationException.
		if wire.Code == "ValidationError" {
			call.ErrorCode = "ValidationException"
		}
		// These native alarm failures omit errorMessage, rather than redact
		// otherwise public request fields or other failures' explanations.
		switch decoded.Operation.Name {
		case "SetAlarmState":
			if wire.Code == "ResourceNotFound" || wire.Code == "InvalidFormat" {
				call.ErrorMessage = ""
			}
		case "TagResource", "UntagResource", "ListTagsForResource":
			if wire.Code == "ResourceNotFoundException" {
				call.ErrorMessage = ""
			}
		}
	}
	if dashboard && wire != nil {
		switch wire.Code {
		case "AccessDenied", "AccessDeniedException":
			call.ErrorCode = "AccessDenied"
			call.RequestParameters = nil
		case "InvalidParameterValue":
			call.ErrorCode = "InvalidParameterValueException"
		case "ValidationError":
			call.ErrorCode = "ValidationException"
		}
	}
	m := awsctx.FromContext(ctx)
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, call)
}

func (s *Service) RecordRequestError(ctx context.Context, decoded awsapi.DecodedRequest, wire *awswire.Error) error {
	return s.record(ctx, decoded, nil, wire)
}
