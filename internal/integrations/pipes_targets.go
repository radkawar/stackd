package integrations

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	eventsapi "stackd/internal/awsapi/eventbridge"
	lambdaapi "stackd/internal/awsapi/lambda"
	pipesapi "stackd/internal/awsapi/pipes"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/pipes"
)

// PipesTargets calls the same destination-owned command boundary as signed
// clients. It does not trust admission-time permissions for an execution.
type PipesTargets struct {
	Roles           ServiceRoles
	Commands        StepFunctionsCommands
	Functions       FirehoseLambdaCommands
	APIDestinations APIDestinationInvoker
	sessions        serviceRoleSessions
}

func (a *PipesTargets) context(ctx context.Context, p pipes.PipeRecord, target string) (context.Context, *awswire.Error) {
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = p.Key.Partition, p.Key.AccountID, p.Key.Region
	if parsed, e := arn.Parse(target); e == nil && parsed.Region != "" {
		m.Region = parsed.Region
	}
	ctx = awsctx.WithMetadata(ctx, m)
	out, e := a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{
		Name: "pipes.amazonaws.com", SourceARN: p.Key.ARN(), Type: "AWSService",
	}, p.RoleARN, p.Key.Name, "")
	if e != nil {
		return ctx, &awswire.Error{Code: "AccessDeniedException", Message: e.Error(), StatusCode: 403}
	}
	return out, nil
}

func (a *PipesTargets) Validate(_ context.Context, p pipes.PipeRecord) *awswire.Error {
	target, e := arn.Parse(p.TargetARN)
	if e != nil || target.AccountID == "" || target.Region == "" {
		return pipesInvalid("Target must be a complete resource ARN.")
	}
	if target.Partition != p.Key.Partition {
		return pipesInvalid("Target partition must match the pipe partition.")
	}
	apiDestination := target.Service == "events" && strings.HasPrefix(target.Resource, "api-destination/")
	if apiDestination {
		resource := strings.Split(target.Resource, "/")
		if len(resource) != 3 || resource[1] == "" || resource[2] == "" || target.AccountID != p.Key.AccountID || target.Region != p.Key.Region {
			return pipesInvalid("API destination targets must identify a resource in the pipe account and Region.")
		}
		if a.APIDestinations == nil {
			return pipesDependency("API destination execution")
		}
		if p.Target.EventBridgeEventBusParameters != nil {
			return pipesInvalid("EventBridgeEventBusParameters require an event bus target.")
		}
	}
	service, operation, maxBatch := "", "", int32(1)
	switch target.Service {
	case "sqs":
		service, operation, maxBatch = "sqs", "SendMessageBatch", 10
	case "sns":
		service, operation, maxBatch = "sns", "PublishBatch", 10
	case "kinesis":
		service, operation, maxBatch = "kinesis", "PutRecords", 500
		if p.Target.KinesisStreamParameters == nil || pipesValue(p.Target.KinesisStreamParameters.PartitionKey) == "" {
			return pipesInvalid("Kinesis target requires PartitionKey.")
		}
	case "firehose":
		service, operation, maxBatch = "firehose", "PutRecordBatch", 500
	case "events":
		if !apiDestination {
			service, operation, maxBatch = "events", "PutEvents", 10
		}
	case "lambda":
		if a.Functions == nil {
			return pipesDependency("Lambda execution")
		}
		maxBatch = 10000
	case "states":
		service, operation, maxBatch = "stepfunctions", "StartExecution", 10000
	case "logs":
		service, operation, maxBatch = "logs", "PutLogEvents", 10000
		if p.Target.CloudWatchLogsParameters == nil || pipesValue(p.Target.CloudWatchLogsParameters.LogStreamName) == "" {
			return pipesInvalid("CloudWatch Logs target requires LogStreamName.")
		}
	case "ecs":
		service, operation = "ecs", "RunTask"
		if p.Target.EcsTaskParameters == nil {
			return pipesInvalid("ECS target requires EcsTaskParameters.")
		}
	default:
		// TODO: Comeback: API Gateway HTTP, Batch, Redshift Data,
		// SageMaker and Timestream need their destination-specific execution adapters.
		return pipesDependency("Pipes target " + target.Service)
	}
	if p.Source.BatchSize > maxBatch {
		return pipesInvalid(fmt.Sprintf("Target supports at most %d records per batch.", maxBatch))
	}
	if service != "" {
		if _, _, e := a.Commands.resolve(service, operation); e != nil {
			return e
		}
	}
	checks := []struct {
		present bool
		service string
	}{
		{p.Target.SqsQueueParameters != nil, "sqs"},
		{p.Target.KinesisStreamParameters != nil, "kinesis"},
		{p.Target.LambdaFunctionParameters != nil, "lambda"},
		{p.Target.StepFunctionStateMachineParameters != nil, "states"},
		{p.Target.CloudWatchLogsParameters != nil, "logs"},
		{p.Target.EventBridgeEventBusParameters != nil, "events"},
		{p.Target.EcsTaskParameters != nil, "ecs"},
		{p.Target.BatchJobParameters != nil, "batch"},
		{p.Target.RedshiftDataParameters != nil, "redshift-data"},
		{p.Target.SageMakerPipelineParameters != nil, "sagemaker"},
		{p.Target.TimestreamParameters != nil, "timestream"},
	}
	for _, check := range checks {
		if check.present && check.service != target.Service {
			return pipesInvalid("TargetParameters do not match Target.")
		}
	}
	if p.Target.HttpParameters != nil && !apiDestination {
		return pipesInvalid("HttpParameters require an API destination target.")
	}
	httpEnrichment := false
	if p.EnrichmentARN != "" {
		enrichment, e := arn.Parse(p.EnrichmentARN)
		if e != nil {
			return pipesInvalid("Invalid enrichment ARN.")
		}
		switch enrichment.Service {
		case "events":
			httpEnrichment = true
			resource := strings.Split(enrichment.Resource, "/")
			if enrichment.Partition != p.Key.Partition || enrichment.AccountID != p.Key.AccountID || enrichment.Region != p.Key.Region || len(resource) != 3 || resource[0] != "api-destination" || resource[1] == "" || resource[2] == "" {
				return pipesInvalid("API destination enrichment must identify a resource in the pipe account and Region.")
			}
			if a.APIDestinations == nil {
				return pipesDependency("API destination enrichment")
			}
			if p.Source.BatchSize > 1 {
				return pipesInvalid("API destination enrichment supports at most one source record per invocation.")
			}
		case "lambda":
			if a.Functions == nil {
				return pipesDependency("Lambda enrichment")
			}
		case "states":
			if _, _, e := a.Commands.resolve("stepfunctions", "StartSyncExecution"); e != nil {
				return e
			}
		default:
			return pipesDependency("Pipes enrichment " + enrichment.Service)
		}
	}
	if p.EnrichmentHTTP != nil && !httpEnrichment {
		return pipesInvalid("Enrichment HttpParameters require an API destination.")
	}
	return nil
}

func (a *PipesTargets) Enrich(ctx context.Context, p pipes.PipeRecord, events []pipes.TargetEvent) ([]byte, *awswire.Error) {
	ctx, e := a.context(ctx, p, p.EnrichmentARN)
	if e != nil {
		return nil, e
	}
	target, err := arn.Parse(p.EnrichmentARN)
	if err != nil {
		return nil, pipesInvalid("Invalid enrichment ARN.")
	}
	if target.Service == "events" {
		if a.APIDestinations == nil {
			return nil, pipesDependency("API destination enrichment")
		}
		if len(events) != 1 {
			return nil, pipesExecutionError("API destination enrichment requires one event per invocation.")
		}
		parameters, rejected := pipesHTTPParameters((*pipesapi.PipeTargetHttpParameters)(p.EnrichmentHTTP), events[0].Input, true)
		if rejected != nil {
			return nil, rejected
		}
		var response bytes.Buffer
		if rejected := a.APIDestinations.InvokeAPIDestination(ctx, p.EnrichmentARN, parameters, string(events[0].Payload), &response); rejected != nil {
			return nil, rejected
		}
		return response.Bytes(), nil
	}
	raw := make([]json.RawMessage, len(events))
	for i, event := range events {
		if json.Valid(event.Payload) {
			raw[i] = event.Payload
		} else {
			raw[i], _ = json.Marshal(string(event.Payload))
		}
	}
	payload, err := json.Marshal(raw)
	if err != nil {
		return nil, pipesInvalid(err.Error())
	}
	if target.Service == "lambda" {
		out, _, e := a.Functions.Invoke(ctx, &lambdaapi.InvokeInput{
			FunctionName:   new(lambdaapi.NamespacedFunctionName(p.EnrichmentARN)),
			InvocationType: new(lambdaapi.InvocationType("RequestResponse")),
			Payload:        payload,
		})
		if e != nil {
			return nil, e
		}
		if out.FunctionError != nil {
			return nil, pipesExecutionError("Lambda enrichment returned " + pipesValue(out.FunctionError))
		}
		return out.Payload, nil
	}
	out, e := a.call(ctx, "stepfunctions", "StartSyncExecution", map[string]any{"StateMachineArn": p.EnrichmentARN, "Input": string(payload)})
	if e != nil {
		return nil, e
	}
	if status, ok := out["status"].(string); ok && status != "SUCCEEDED" {
		return nil, pipesExecutionError("State machine enrichment failed: " + status)
	}
	result, _ := out["output"].(string)
	return []byte(result), nil
}

func (a *PipesTargets) Deliver(ctx context.Context, p pipes.PipeRecord, work []pipes.Work, events []pipes.TargetEvent, dlq bool) (pipes.DeliveryResult, *awswire.Error) {
	destination := p.TargetARN
	if dlq {
		destination = p.Source.DLQ
	}
	result := pipes.DeliveryResult{}
	ctx, rejected := a.context(ctx, p, destination)
	if rejected != nil {
		return result, rejected
	}
	target, e := arn.Parse(destination)
	if e != nil {
		return result, pipesInvalid("Invalid target ARN.")
	}
	if target.Service == "events" && strings.HasPrefix(target.Resource, "api-destination/") {
		if a.APIDestinations == nil {
			return result, pipesDependency("API destination execution")
		}
		if len(events) != 1 {
			return result, pipesExecutionError("API destination targets require one event per invocation.")
		}
		parameters, rejected := pipesHTTPParameters(p.Target.HttpParameters, events[0].Input, false)
		if rejected != nil {
			return result, rejected
		}
		return result, a.APIDestinations.InvokeAPIDestination(ctx, destination, parameters, string(events[0].Payload), nil)
	}
	if target.Service == "lambda" || target.Service == "states" {
		raw := make([]json.RawMessage, len(events))
		for i, event := range events {
			if json.Valid(event.Payload) {
				raw[i] = event.Payload
			} else {
				raw[i], _ = json.Marshal(string(event.Payload))
			}
		}
		body, e := json.Marshal(raw)
		if e != nil {
			return result, pipesExecutionError(e.Error())
		}
		if target.Service == "lambda" {
			invocation := "RequestResponse"
			if p.Target.LambdaFunctionParameters != nil && pipesValue(p.Target.LambdaFunctionParameters.InvocationType) == "FIRE_AND_FORGET" {
				invocation = "Event"
			}
			out, _, e := a.Functions.Invoke(ctx, &lambdaapi.InvokeInput{
				FunctionName:   new(lambdaapi.NamespacedFunctionName(destination)),
				InvocationType: new(lambdaapi.InvocationType(invocation)),
				Payload:        body,
			})
			if e != nil {
				return result, e
			}
			if out.FunctionError != nil {
				return result, pipesExecutionError("Lambda target returned " + pipesValue(out.FunctionError))
			}
			if invocation == "RequestResponse" {
				return pipesPartialFailures(out.Payload, work)
			}
			return result, nil
		}
		operation := "StartSyncExecution"
		if p.Target.StepFunctionStateMachineParameters != nil && pipesValue(p.Target.StepFunctionStateMachineParameters.InvocationType) == "FIRE_AND_FORGET" {
			operation = "StartExecution"
		}
		out, rejected := a.call(ctx, "stepfunctions", operation, map[string]any{"StateMachineArn": destination, "Input": string(body)})
		if rejected != nil {
			return result, rejected
		}
		if operation == "StartSyncExecution" {
			if status, ok := out["status"].(string); ok && status != "SUCCEEDED" {
				return result, pipesExecutionError("State machine target failed: " + status)
			}
			text, _ := out["output"].(string)
			return pipesPartialFailures([]byte(text), work)
		}
		return result, nil
	}
	maxBatch := 10000
	switch target.Service {
	case "sqs", "sns", "events":
		maxBatch = 10
	case "kinesis", "firehose":
		maxBatch = 500
	case "ecs":
		maxBatch = 1
	}
	if len(events) > maxBatch {
		return result, pipesExecutionError("Enrichment result exceeds the target batch limit.")
	}
	entries := make([]map[string]any, 0, len(events))
	for i, event := range events {
		original, payload := event.Input, event.Payload
		dynamic := func(v string) string {
			resolved, err := pipes.ResolveParameter(v, original)
			if err != nil {
				rejected = pipesInvalid(err.Error())
			}
			return resolved
		}
		id := strconv.Itoa(i)
		var entry map[string]any
		switch target.Service {
		case "sqs":
			entry = map[string]any{"Id": id, "MessageBody": string(payload)}
			if !dlq && p.Target.SqsQueueParameters != nil {
				q := p.Target.SqsQueueParameters
				if q.MessageGroupId != nil {
					entry["MessageGroupId"] = dynamic(pipesValue(q.MessageGroupId))
				}
				if q.MessageDeduplicationId != nil {
					entry["MessageDeduplicationId"] = dynamic(pipesValue(q.MessageDeduplicationId))
				}
			}
		case "sns":
			entry = map[string]any{"Id": id, "Message": string(payload)}
		case "kinesis":
			entry = map[string]any{
				"PartitionKey": dynamic(pipesValue(p.Target.KinesisStreamParameters.PartitionKey)),
				"Data":         base64.StdEncoding.EncodeToString(payload),
			}
		case "firehose":
			entry = map[string]any{"Data": base64.StdEncoding.EncodeToString(payload)}
		case "events":
			entry = map[string]any{"EventBusName": destination, "Detail": string(payload), "Source": "aws.pipes", "DetailType": "Event from " + p.Key.Name}
			if q := p.Target.EventBridgeEventBusParameters; q != nil {
				if q.Source != nil {
					entry["Source"] = dynamic(pipesValue(q.Source))
				}
				if q.DetailType != nil {
					entry["DetailType"] = dynamic(pipesValue(q.DetailType))
				}
				if q.Resources != nil {
					resources := make([]string, len(q.Resources))
					for i, v := range q.Resources {
						resources[i] = dynamic(string(v))
					}
					entry["Resources"] = resources
				}
				if q.Time != nil {
					v := dynamic(pipesValue(q.Time))
					parsed, err := time.Parse(time.RFC3339Nano, v)
					if err != nil {
						return result, pipesInvalid("EventBridge Time must resolve to an ISO 8601 timestamp.")
					}
					entry["Time"] = float64(parsed.UnixMilli()) / 1000
				}
			}
		case "logs":
			timestamp := int64(0)
			if i < len(work) {
				timestamp = work[i].Created.UnixMilli()
			}
			if q := p.Target.CloudWatchLogsParameters; q.Timestamp != nil {
				text := dynamic(pipesValue(q.Timestamp))
				n, e := strconv.ParseInt(text, 10, 64)
				if e != nil {
					return result, pipesInvalid("Logs Timestamp must resolve to epoch milliseconds.")
				}
				timestamp = n
			}
			entry = map[string]any{"Message": string(payload), "Timestamp": timestamp}
		case "ecs":
			return a.ecs(ctx, p, original)
		default:
			return result, pipesDependency("Pipes target " + target.Service)
		}
		if rejected != nil {
			return result, rejected
		}
		entries = append(entries, entry)
	}
	parameters := map[string]any{}
	service, operation := "", ""
	switch target.Service {
	case "sqs":
		service, operation = "sqs", "SendMessageBatch"
		domain := "amazonaws.com"
		if target.Partition == "aws-cn" {
			domain = "amazonaws.com.cn"
		}
		parameters["QueueUrl"] = "https://sqs." + target.Region + "." + domain + "/" + target.AccountID + "/" + target.Resource
		parameters["Entries"] = entries
	case "sns":
		service, operation = "sns", "PublishBatch"
		parameters["TopicArn"] = destination
		parameters["PublishBatchRequestEntries"] = entries
	case "kinesis":
		service, operation = "kinesis", "PutRecords"
		parameters["StreamARN"] = destination
		parameters["Records"] = entries
	case "firehose":
		service, operation = "firehose", "PutRecordBatch"
		parameters["DeliveryStreamName"] = strings.TrimPrefix(target.Resource, "deliverystream/")
		parameters["Records"] = entries
	case "events":
		service, operation = "events", "PutEvents"
		parameters["Entries"] = entries
		if q := p.Target.EventBridgeEventBusParameters; q != nil && q.EndpointId != nil {
			parameters["EndpointId"] = pipesValue(q.EndpointId)
		}
	case "logs":
		service, operation = "logs", "PutLogEvents"
		group := strings.TrimSuffix(strings.TrimPrefix(target.Resource, "log-group:"), ":*")
		parameters["logGroupName"] = group
		stream, e := pipes.ResolveParameter(pipesValue(p.Target.CloudWatchLogsParameters.LogStreamName), events[0].Input)
		if e != nil {
			return result, pipesInvalid(e.Error())
		}
		parameters["logStreamName"] = stream
		slices.SortStableFunc(entries, func(a, b map[string]any) int {
			x, y := a["Timestamp"].(int64), b["Timestamp"].(int64)
			if x < y {
				return -1
			}
			if x > y {
				return 1
			}
			return 0
		})
		parameters["logEvents"] = entries
	}
	out, rejected := a.call(ctx, service, operation, parameters)
	if rejected != nil {
		return result, rejected
	}
	if target.Service == "logs" {
		if rejected, ok := out["rejectedLogEventsInfo"]; ok && rejected != nil {
			return result, pipesExecutionError("CloudWatch Logs rejected target events.")
		}
	}
	failedIndexes := map[int]bool{}
	if list, ok := out["Failed"].([]any); ok {
		for _, raw := range list {
			v, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			text, _ := v["Id"].(string)
			i, e := strconv.Atoi(text)
			if e == nil {
				failedIndexes[i] = true
			}
		}
	}
	for _, field := range []string{"Records", "Entries", "RequestResponses"} {
		if list, ok := out[field].([]any); ok {
			for i, raw := range list {
				v, ok := raw.(map[string]any)
				if ok && v["ErrorCode"] != nil {
					failedIndexes[i] = true
				}
			}
		}
	}
	for index := range failedIndexes {
		id := ""
		if index >= 0 && index < len(events) {
			if dlq || p.EnrichmentARN == "" {
				if index < len(work) {
					id = work[index].RecordID
				}
			} else {
				// Enrichments may reorder or replace their batch. Only an original source
				// identifier can safely associate an enriched target failure with a receipt.
				var event struct {
					MessageID string `json:"messageId"`
					EventID   string `json:"eventID"`
				}
				if json.Unmarshal(events[index].Input, &event) == nil {
					if p.Source.Kind == "sqs" {
						id = event.MessageID
					} else {
						id = event.EventID
					}
				}
			}
		}
		known := false
		for _, record := range work {
			if record.RecordID == id {
				known = true
				break
			}
		}
		if !known {
			result.FailedIDs = result.FailedIDs[:0]
			for _, record := range work {
				result.FailedIDs = append(result.FailedIDs, record.RecordID)
			}
			break
		}
		result.FailedIDs = append(result.FailedIDs, id)
	}
	return result, nil
}

func (a *PipesTargets) call(ctx context.Context, service, operation string, parameters map[string]any) (map[string]any, *awswire.Error) {
	raw, e := json.Marshal(parameters)
	if e != nil {
		return nil, pipesExecutionError(e.Error())
	}
	result, rejected := a.Commands.Call(ctx, service, operation, raw)
	if rejected != nil {
		return nil, rejected
	}
	raw, e = json.Marshal(result.Output)
	if e != nil {
		return nil, pipesExecutionError(e.Error())
	}
	var out map[string]any
	if e = json.Unmarshal(raw, &out); e != nil {
		return nil, pipesExecutionError(e.Error())
	}
	return out, nil
}

func (a *PipesTargets) ecs(ctx context.Context, p pipes.PipeRecord, event []byte) (pipes.DeliveryResult, *awswire.Error) {
	result := pipes.DeliveryResult{}
	raw, e := json.Marshal(p.Target.EcsTaskParameters)
	if e != nil {
		return result, pipesExecutionError(e.Error())
	}
	var in map[string]any
	if e = json.Unmarshal(raw, &in); e != nil {
		return result, pipesExecutionError(e.Error())
	}
	in["Cluster"] = p.TargetARN
	in["TaskDefinition"] = in["TaskDefinitionArn"]
	delete(in, "TaskDefinitionArn")
	if v, ok := in["TaskCount"]; ok {
		in["Count"] = v
		delete(in, "TaskCount")
	}
	if v, ok := in["ReferenceId"]; ok {
		in["StartedBy"] = v
		delete(in, "ReferenceId")
	}
	var resolve func(any) (any, error)
	resolve = func(v any) (any, error) {
		switch v := v.(type) {
		case string:
			return pipes.ResolveParameter(v, event)
		case map[string]any:
			for k, x := range v {
				r, e := resolve(x)
				if e != nil {
					return nil, e
				}
				v[k] = r
			}
		case []any:
			for i, x := range v {
				r, e := resolve(x)
				if e != nil {
					return nil, e
				}
				v[i] = r
			}
		}
		return v, nil
	}
	if _, e = resolve(in); e != nil {
		return result, pipesInvalid(e.Error())
	}
	out, rejected := a.call(ctx, "ecs", "RunTask", in)
	if rejected != nil {
		return result, rejected
	}
	if failures, ok := out["failures"].([]any); ok && len(failures) > 0 {
		return result, pipesExecutionError("ECS target rejected task admission.")
	}
	return result, nil
}

func pipesPartialFailures(payload []byte, work []pipes.Work) (pipes.DeliveryResult, *awswire.Error) {
	result := pipes.DeliveryResult{}
	if len(payload) == 0 || string(payload) == "null" {
		return result, nil
	}
	var root map[string]json.RawMessage
	// A normal Lambda return value need not be a partial-batch response.
	if json.Unmarshal(payload, &root) != nil {
		return result, nil
	}
	raw, ok := root["batchItemFailures"]
	if !ok || string(raw) == "null" {
		return result, nil
	}
	var failures []struct {
		ID *string `json:"itemIdentifier"`
	}
	if json.Unmarshal(raw, &failures) != nil {
		return result, pipesExecutionError("Invalid batchItemFailures response.")
	}
	for _, failure := range failures {
		if failure.ID == nil || *failure.ID == "" {
			return result, pipesExecutionError("Invalid batch failure itemIdentifier.")
		}
		found := false
		for _, w := range work {
			if w.RecordID == *failure.ID {
				found = true
				break
			}
		}
		if !found {
			return result, pipesExecutionError("Unknown batch failure itemIdentifier.")
		}
		result.FailedIDs = append(result.FailedIDs, *failure.ID)
	}
	return result, nil
}
func pipesHTTPParameters(in *pipesapi.PipeTargetHttpParameters, event []byte, enrichment bool) (*eventsapi.HttpParameters, *awswire.Error) {
	if in == nil {
		return nil, nil
	}
	out := &eventsapi.HttpParameters{}
	if in.HeaderParameters != nil {
		out.HeaderParameters = make(eventsapi.HeaderParametersMap, len(in.HeaderParameters))
		for key, value := range in.HeaderParameters {
			// Retained native enrichment captures resolve header values despite
			// their documented exclusion. Target headers retain their own contract.
			resolved := string(value)
			if enrichment {
				var err error
				resolved, err = pipes.ResolveParameter(resolved, event)
				if err != nil {
					return nil, pipesInvalid(err.Error())
				}
			}
			out.HeaderParameters[eventsapi.HeaderKey(key)] = eventsapi.HeaderValue(resolved)
		}
	}
	if in.PathParameterValues != nil {
		out.PathParameterValues = make(eventsapi.PathParameterList, len(in.PathParameterValues))
		for i, value := range in.PathParameterValues {
			resolved, err := pipes.ResolveParameter(string(value), event)
			if err != nil {
				return nil, pipesInvalid(err.Error())
			}
			out.PathParameterValues[i] = eventsapi.PathParameter(resolved)
		}
	}
	if in.QueryStringParameters != nil {
		out.QueryStringParameters = make(eventsapi.QueryStringParametersMap, len(in.QueryStringParameters))
		for key, value := range in.QueryStringParameters {
			resolved, err := pipes.ResolveParameter(string(value), event)
			if err != nil {
				return nil, pipesInvalid(err.Error())
			}
			out.QueryStringParameters[eventsapi.QueryStringKey(key)] = eventsapi.QueryStringValue(resolved)
		}
	}
	return out, nil
}

func pipesValue[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func pipesInvalid(message string) *awswire.Error {
	return &awswire.Error{Code: "ValidationException", Message: message, StatusCode: 400}
}
func pipesExecutionError(message string) *awswire.Error {
	return &awswire.Error{Code: "PipeExecutionException", Message: message, StatusCode: 400}
}

var _ pipes.Targets = (*PipesTargets)(nil)
