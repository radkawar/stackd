package integrations

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"stackd/internal/awsapi"
	appsyncapi "stackd/internal/awsapi/appsync"
	ddb "stackd/internal/awsapi/dynamodb"
	lambdaapi "stackd/internal/awsapi/lambda"
	rds "stackd/internal/awsapi/rdsdata"
	"stackd/internal/awscatalog"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/appsync"
	"stackd/internal/services/dynamodb"
)

// AppSyncLambdaCommands leaves invocation authorization and real execution in Lambda.
type AppSyncLambdaCommands interface {
	Invoke(context.Context, *lambdaapi.InvokeInput) (*lambdaapi.InvokeOutput, string, *awswire.Error)
}

// AppSyncSources has no engine access or ambient AWS credentials. Every AWS effect
// uses an ordinary destination command under the data source's current role.
type AppSyncSources struct {
	Roles      ServiceRoles
	Lambda     AppSyncLambdaCommands
	DynamoDB   awscommands.CommandExecutor
	RDSData    awscommands.CommandExecutor
	HTTPClient *http.Client
	sessions   serviceRoleSessions
}

var _ appsync.DataSources = (*AppSyncSources)(nil)

// HTTP has no proxy-from-environment, cookie jar or redirect credential forwarding.
var appSyncHTTPClient = http.Client{
	Transport:     &http.Transport{Proxy: nil, MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (a *AppSyncSources) Execute(ctx context.Context, api appsync.APIRecord, source appsyncapi.DataSource, request map[string]any) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch appSyncString(source.Type) {
	case "NONE":
		return request["payload"], nil
	case "HTTP":
		return a.http(ctx, source, request)
	case "AWS_LAMBDA", "AMAZON_DYNAMODB", "RELATIONAL_DATABASE":
		region := api.Key.Region
		if source.DynamodbConfig != nil {
			region = appSyncString(source.DynamodbConfig.AwsRegion)
		}
		if source.RelationalDatabaseConfig != nil && source.RelationalDatabaseConfig.RdsHttpEndpointConfig != nil {
			region = appSyncString(source.RelationalDatabaseConfig.RdsHttpEndpointConfig.AwsRegion)
		}
		if source.LambdaConfig != nil {
			parts := strings.Split(appSyncString(source.LambdaConfig.LambdaFunctionArn), ":")
			if len(parts) >= 6 {
				region = parts[3]
			}
		}
		metadata := awsctx.FromContext(ctx)
		metadata.AccountID, metadata.Partition, metadata.Region = api.Key.AccountID, api.Key.Partition, region
		ctx = awsctx.WithMetadata(ctx, metadata)
		role := appSyncString(source.ServiceRoleArn)
		if role == "" {
			return nil, appSyncError("AccessDeniedException", "Data source serviceRoleArn is required")
		}
		var err error
		ctx, err = a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: "appsync.amazonaws.com", SourceARN: api.Key.ARN(), Type: "AWSService"}, role, "AppSync", "")
		if err != nil {
			return nil, err
		}
		switch appSyncString(source.Type) {
		case "AWS_LAMBDA":
			return a.lambda(ctx, source, request)
		case "AMAZON_DYNAMODB":
			return a.dynamodb(ctx, api, source, request)
		default:
			return a.rds(ctx, source, request)
		}
	default:
		return nil, appSyncUnsupported("Data source " + appSyncString(source.Type))
	}
}

func (a *AppSyncSources) lambda(ctx context.Context, source appsyncapi.DataSource, request map[string]any) (any, error) {
	if a.Lambda == nil {
		return nil, appSyncUnsupported("Lambda is not configured")
	}
	if source.LambdaConfig == nil {
		return nil, appSyncError("MappingTemplate", "Missing Lambda data source configuration")
	}
	operation := appSyncText(request["operation"])
	if operation != "Invoke" && operation != "BatchInvoke" {
		return nil, appSyncUnsupported("Lambda operation " + operation)
	}
	invocation := appSyncText(request["invocationType"])
	if invocation == "" {
		invocation = "RequestResponse"
	}
	if invocation != "RequestResponse" && invocation != "Event" {
		return nil, appSyncError("MappingTemplate", "Invalid Lambda invocationType")
	}
	payload := request["payload"]
	// A single field is a valid one-element batch; the GraphQL executor owns any
	// cross-field batching. Never pass a scalar where BatchInvoke expects a list.
	if operation == "BatchInvoke" {
		payload = []any{payload}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	out, _, rejected := a.Lambda.Invoke(ctx, &lambdaapi.InvokeInput{
		FunctionName:   new(lambdaapi.NamespacedFunctionName(appSyncString(source.LambdaConfig.LambdaFunctionArn))),
		InvocationType: new(lambdaapi.InvocationType(invocation)), Payload: lambdaapi.Blob(encoded),
	})
	if rejected != nil {
		return nil, &appsync.MappingError{Message: rejected.Message, Type: "Lambda:" + rejected.Code}
	}
	if out == nil {
		return nil, appSyncError("Lambda:InternalFailure", "Lambda returned no invocation result")
	}
	if invocation == "Event" {
		return nil, nil
	}
	var result any
	if err := json.Unmarshal(out.Payload, &result); err != nil {
		return nil, appSyncError("Lambda:MappingTemplate", "Lambda returned invalid JSON: "+err.Error())
	}
	if appSyncString(out.FunctionError) != "" {
		detail, _ := result.(map[string]any)
		message, kind := appSyncText(detail["errorMessage"]), appSyncText(detail["errorType"])
		if message == "" {
			message = string(out.Payload)
		}
		if kind == "" {
			kind = "Lambda:Unhandled"
		}
		return nil, &appsync.MappingError{Message: message, Type: kind, Data: result}
	}
	if operation == "BatchInvoke" {
		batch, ok := result.([]any)
		if !ok || len(batch) != 1 {
			return nil, appSyncError("Lambda:MappingTemplate", "BatchInvoke response must contain one result for each request")
		}
		return batch[0], nil
	}
	return result, nil
}

func (a *AppSyncSources) http(ctx context.Context, source appsyncapi.DataSource, request map[string]any) (any, error) {
	if source.HttpConfig == nil {
		return nil, appSyncError("MappingTemplate", "Missing HTTP data source configuration")
	}
	if source.HttpConfig.AuthorizationConfig != nil {
		return nil, appSyncUnsupported("HTTP AWS_IAM signing")
	}
	endpoint, err := url.Parse(appSyncString(source.HttpConfig.Endpoint))
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.Fragment != "" {
		return nil, appSyncError("MappingTemplate", "HTTP data source requires an explicit http(s) endpoint without credentials or fragment")
	}
	resource, err := url.Parse(appSyncText(request["resourcePath"]))
	if err != nil || resource.IsAbs() || resource.Host != "" || resource.User != nil || resource.Fragment != "" {
		return nil, appSyncError("MappingTemplate", "HTTP resourcePath must be a relative endpoint path")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/" + strings.TrimLeft(resource.Path, "/")
	endpoint.RawPath = ""
	query := endpoint.Query()
	for k, v := range resource.Query() {
		query[k] = v
	}
	params, err := appSyncObject(request["params"], "params", false)
	if err != nil {
		return nil, err
	}
	queries, err := appSyncObject(params["query"], "params.query", false)
	if err != nil {
		return nil, err
	}
	for k, v := range queries {
		s, ok := v.(string)
		if !ok {
			return nil, appSyncError("MappingTemplate", "HTTP query values must be strings")
		}
		query.Set(k, s)
	}
	endpoint.RawQuery = query.Encode()
	method := appSyncText(request["method"])
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		return nil, appSyncError("MappingTemplate", "Invalid HTTP method")
	}
	var body []byte
	if value, ok := params["body"]; ok {
		if text, ok := value.(string); ok {
			body = []byte(text)
		} else {
			body, err = json.Marshal(value)
			if err != nil {
				return nil, err
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	headers, err := appSyncObject(params["headers"], "params.headers", false)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		s, ok := v.(string)
		if !ok {
			return nil, appSyncError("MappingTemplate", "HTTP header values must be strings")
		}
		switch strings.ToLower(strings.ReplaceAll(k, "_", "-")) {
		case "host", "connection", "user-agent", "expectation", "expect", "transfer-encoding", "content-length":
			return nil, appSyncError("MappingTemplate", "Reserved HTTP header: "+k)
		}
		req.Header.Set(k, s)
	}
	client := appSyncHTTPClient
	if a.HTTPClient != nil {
		client = *a.HTTPClient
		client.Jar = nil
		if client.Transport == nil {
			client.Transport = appSyncHTTPClient.Transport
		}
		client.CheckRedirect = appSyncHTTPClient.CheckRedirect
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, appSyncError("HTTP", err.Error())
	}
	defer response.Body.Close()
	const maxResponse = 5 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return nil, appSyncError("HTTP", err.Error())
	}
	if len(data) > maxResponse {
		return nil, appSyncError("HTTP", "HTTP response exceeds 5 MiB")
	}
	responseHeaders := make(map[string]any, len(response.Header))
	for k, v := range response.Header {
		responseHeaders[k] = strings.Join(v, ",")
	}
	// Non-2xx status is visible to the response handler, not hidden or retried.
	return map[string]any{"statusCode": response.StatusCode, "headers": responseHeaders, "body": string(data)}, nil
}

func (a *AppSyncSources) dynamodb(ctx context.Context, api appsync.APIRecord, source appsyncapi.DataSource, request map[string]any) (any, error) {
	if a.DynamoDB == nil {
		return nil, appSyncUnsupported("DynamoDB is not configured")
	}
	config := source.DynamodbConfig
	if config == nil {
		return nil, appSyncError("MappingTemplate", "Missing DynamoDB data source configuration")
	}
	if config.DeltaSyncConfig != nil || (config.Versioned != nil && bool(*config.Versioned)) || (config.UseCallerCredentials != nil && bool(*config.UseCallerCredentials)) {
		return nil, appSyncUnsupported("DynamoDB versioning or caller credentials")
	}
	for _, field := range []string{"_version", "customPartitionKey", "populateIndexFields"} {
		if _, ok := request[field]; ok {
			return nil, appSyncUnsupported("DynamoDB " + field)
		}
	}
	operation := appSyncText(request["operation"])
	switch operation {
	case "GetItem", "PutItem", "UpdateItem", "DeleteItem", "Query", "Scan":
	default:
		return nil, appSyncUnsupported("DynamoDB operation " + operation)
	}
	input := map[string]any{"TableName": appSyncString(config.TableName)}
	for from, to := range map[string]string{"key": "Key", "consistentRead": "ConsistentRead", "index": "IndexName", "limit": "Limit", "scanIndexForward": "ScanIndexForward", "select": "Select", "segment": "Segment", "totalSegments": "TotalSegments"} {
		if v, ok := request[from]; ok && v != nil {
			input[to] = v
		}
	}
	for from, to := range map[string]string{"query": "KeyConditionExpression", "filter": "FilterExpression", "condition": "ConditionExpression", "update": "UpdateExpression", "projection": "ProjectionExpression"} {
		if v, ok := request[from]; ok && v != nil {
			if err := appSyncExpression(input, v, to); err != nil {
				return nil, err
			}
		}
	}
	if operation == "PutItem" {
		attributes, err := appSyncObject(request["attributeValues"], "attributeValues", false)
		if err != nil {
			return nil, err
		}
		key, err := appSyncObject(request["key"], "key", true)
		if err != nil {
			return nil, err
		}
		item := maps.Clone(attributes)
		if item == nil {
			item = make(map[string]any, len(key))
		}
		maps.Copy(item, key)
		input["Item"] = item
		delete(input, "Key")
	}
	if operation == "UpdateItem" {
		input["ReturnValues"] = "ALL_NEW"
	}
	if operation == "DeleteItem" {
		input["ReturnValues"] = "ALL_OLD"
	}
	condition, err := appSyncObject(request["condition"], "condition", false)
	if err != nil {
		return nil, err
	}
	if handler, ok := condition["conditionalCheckFailedHandler"]; ok {
		config, err := appSyncObject(handler, "conditionalCheckFailedHandler", true)
		if err != nil {
			return nil, err
		}
		if appSyncText(config["strategy"]) != "Reject" {
			return nil, appSyncUnsupported("DynamoDB custom conditional failure handler")
		}
	}
	cursorScope := api.Key.ARN() + "/" + appSyncString(source.Name) + "/" + operation + "/" + appSyncText(request["index"])
	if token := appSyncText(request["nextToken"]); token != "" {
		data, err := base64.RawURLEncoding.DecodeString(token)
		var cursor struct {
			Scope string
			Key   map[string]any
		}
		if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Scope != cursorScope {
			return nil, appSyncError("MappingTemplate", "Invalid DynamoDB nextToken")
		}
		input["ExclusiveStartKey"] = cursor.Key
	}
	out, rejected := appSyncCommand(ctx, a.DynamoDB, "dynamodb", operation, input)
	if rejected != nil {
		if rejected.Code == "ConditionalCheckFailedException" {
			return a.dynamodbCondition(ctx, source, request, input, rejected)
		}
		return nil, &appsync.MappingError{Message: rejected.Message, Type: "DynamoDB:" + rejected.Code}
	}
	switch result := out.(type) {
	case *ddb.GetItemOutput:
		return appSyncDynamoItem(result.Item), nil
	case *ddb.PutItemOutput:
		var item ddb.AttributeMap
		encoded, err := json.Marshal(input["Item"])
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(encoded, &item); err != nil {
			return nil, err
		}
		return appSyncDynamoItem(item), nil
	case *ddb.UpdateItemOutput:
		return appSyncDynamoItem(result.Attributes), nil
	case *ddb.DeleteItemOutput:
		return appSyncDynamoItem(result.Attributes), nil
	case *ddb.QueryOutput:
		return appSyncDynamoPage(result.Items, result.LastEvaluatedKey, result.ScannedCount, cursorScope)
	case *ddb.ScanOutput:
		return appSyncDynamoPage(result.Items, result.LastEvaluatedKey, result.ScannedCount, cursorScope)
	default:
		return nil, appSyncError("DynamoDB:InternalFailure", "Unexpected DynamoDB command result")
	}
}

func (a *AppSyncSources) dynamodbCondition(ctx context.Context, source appsyncapi.DataSource, request, attempted map[string]any, original *awswire.Error) (any, error) {
	condition, _ := request["condition"].(map[string]any)
	consistent := true
	if value, ok := condition["consistentRead"].(bool); ok {
		consistent = value
	}
	out, rejected := appSyncCommand(ctx, a.DynamoDB, "dynamodb", "GetItem", map[string]any{"TableName": attempted["TableName"], "Key": request["key"], "ConsistentRead": consistent})
	if rejected != nil {
		return nil, &appsync.MappingError{Message: rejected.Message, Type: "DynamoDB:" + rejected.Code}
	}
	result, ok := out.(*ddb.GetItemOutput)
	if !ok {
		return nil, appSyncError("DynamoDB:InternalFailure", "Unexpected DynamoDB condition read result")
	}
	current := appSyncDynamoItem(result.Item)
	switch appSyncText(request["operation"]) {
	case "DeleteItem":
		if len(result.Item) == 0 {
			return nil, nil
		}
	case "PutItem":
		var desired ddb.AttributeMap
		encoded, err := json.Marshal(attempted["Item"])
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(encoded, &desired); err != nil {
			return nil, err
		}
		actual := maps.Clone(result.Item)
		ignored, ok := condition["equalsIgnore"].([]any)
		if condition["equalsIgnore"] != nil && !ok {
			return nil, appSyncError("MappingTemplate", "equalsIgnore must be a list")
		}
		for _, name := range ignored {
			delete(actual, ddb.AttributeName(appSyncText(name)))
			delete(desired, ddb.AttributeName(appSyncText(name)))
		}
		if maps.EqualFunc(actual, desired, dynamodb.AttributeValuesEqual) {
			return current, nil
		}
	}
	return current, &appsync.MappingError{Message: original.Message, Type: "DynamoDB:" + original.Code, Data: current}
}

func appSyncExpression(input map[string]any, value any, target string) error {
	expression, err := appSyncObject(value, target, true)
	if err != nil {
		return err
	}
	text := appSyncText(expression["expression"])
	if text == "" {
		return appSyncError("MappingTemplate", target+" requires expression")
	}
	input[target] = text
	for from, to := range map[string]string{"expressionNames": "ExpressionAttributeNames", "expressionValues": "ExpressionAttributeValues"} {
		values, err := appSyncObject(expression[from], from, false)
		if err != nil {
			return err
		}
		if len(values) == 0 {
			continue
		}
		existing, _ := input[to].(map[string]any)
		if existing == nil {
			existing = map[string]any{}
			input[to] = existing
		}
		for k, v := range values {
			if old, ok := existing[k]; ok && !reflect.DeepEqual(old, v) {
				return appSyncError("MappingTemplate", "Conflicting DynamoDB expression placeholder "+k)
			}
			existing[k] = v
		}
	}
	return nil
}

func appSyncDynamoItem(item ddb.AttributeMap) any {
	if len(item) == 0 {
		return nil
	}
	result := make(map[string]any, len(item))
	for k, v := range item {
		result[string(k)] = appSyncDynamoValue(v)
	}
	return result
}

func appSyncDynamoValue(v ddb.AttributeValue) any {
	switch {
	case v.S != nil:
		return string(*v.S)
	case v.N != nil:
		return json.Number(*v.N)
	case v.BOOL != nil:
		return bool(*v.BOOL)
	case v.NULL != nil:
		return nil
	case v.B != nil:
		return base64.StdEncoding.EncodeToString(v.B)
	case v.M != nil:
		result := make(map[string]any, len(v.M))
		for k, value := range v.M {
			result[string(k)] = appSyncDynamoValue(value)
		}
		return result
	case v.L != nil:
		result := make([]any, len(v.L))
		for i, value := range v.L {
			result[i] = appSyncDynamoValue(value)
		}
		return result
	case v.SS != nil:
		result := make([]string, len(v.SS))
		for i, value := range v.SS {
			result[i] = string(value)
		}
		return result
	case v.NS != nil:
		result := make([]json.Number, len(v.NS))
		for i, value := range v.NS {
			result[i] = json.Number(value)
		}
		return result
	case v.BS != nil:
		result := make([]string, len(v.BS))
		for i, value := range v.BS {
			result[i] = base64.StdEncoding.EncodeToString(value)
		}
		return result
	default:
		return nil
	}
}

func appSyncDynamoPage(items ddb.ItemList, key ddb.Key, scanned *ddb.Integer, scope string) (any, error) {
	result := make([]any, len(items))
	for i, item := range items {
		result[i] = appSyncDynamoItem(item)
	}
	var token any
	if len(key) != 0 {
		data, err := json.Marshal(struct {
			Scope string
			Key   ddb.Key
		}{scope, key})
		if err != nil {
			return nil, err
		}
		token = base64.RawURLEncoding.EncodeToString(data)
	}
	count := int32(0)
	if scanned != nil {
		count = int32(*scanned)
	}
	return map[string]any{"items": result, "nextToken": token, "scannedCount": count}, nil
}

func (a *AppSyncSources) rds(ctx context.Context, source appsyncapi.DataSource, request map[string]any) (any, error) {
	if a.RDSData == nil {
		return nil, appSyncUnsupported("RDS Data is not configured")
	}
	config := source.RelationalDatabaseConfig
	if config == nil || config.RdsHttpEndpointConfig == nil || appSyncString(config.RelationalDatabaseSourceType) != "RDS_HTTP_ENDPOINT" {
		return nil, appSyncUnsupported("RDS data source type")
	}
	endpoint := config.RdsHttpEndpointConfig
	if appSyncString(endpoint.Schema) != "" {
		return nil, appSyncUnsupported("RDS Data schema")
	}
	statements, ok := request["statements"].([]any)
	if !ok || len(statements) == 0 || len(statements) > 2 {
		return nil, appSyncError("MappingTemplate", "RDS requires one or two statements")
	}
	variables, err := appSyncObject(request["variableMap"], "variableMap", false)
	if err != nil {
		return nil, err
	}
	hints, err := appSyncObject(request["variableTypeHintMap"], "variableTypeHintMap", false)
	if err != nil {
		return nil, err
	}
	parameters := make(rds.SqlParametersList, 0, len(variables))
	for _, name := range slices.Sorted(maps.Keys(variables)) {
		field, err := appSyncSQLField(variables[name])
		if err != nil {
			return nil, err
		}
		parameter := rds.SqlParameter{Name: new(rds.ParameterName(strings.TrimPrefix(name, ":"))), Value: &field}
		if hint, ok := hints[name]; ok {
			text, ok := hint.(string)
			if !ok {
				return nil, appSyncError("MappingTemplate", "SQL type hints must be strings")
			}
			parameter.TypeHint = new(rds.TypeHint(text))
		}
		parameters = append(parameters, parameter)
	}
	// Validate the entire request before issuing its first (possibly mutating) statement.
	for _, statement := range statements {
		if text, ok := statement.(string); !ok || strings.TrimSpace(text) == "" {
			return nil, appSyncError("MappingTemplate", "RDS statements must be nonempty strings")
		}
	}
	results := make([]*rds.ExecuteStatementResponse, 0, len(statements))
	for _, statement := range statements {
		input := &rds.ExecuteStatementRequest{
			ResourceArn: new(rds.Arn(appSyncString(endpoint.DbClusterIdentifier))), SecretArn: new(rds.Arn(appSyncString(endpoint.AwsSecretStoreArn))),
			Database: new(rds.DbName(appSyncString(endpoint.DatabaseName))), Sql: new(rds.SqlStatement(statement.(string))),
			Parameters: parameters, IncludeResultMetadata: new(rds.Boolean(true)),
		}
		out, rejected := appSyncTypedCommand(ctx, a.RDSData, "rdsdata", "ExecuteStatement", input)
		if rejected != nil {
			return nil, &appsync.MappingError{Message: rejected.Message, Type: "RDS:" + rejected.Code}
		}
		result, ok := out.(*rds.ExecuteStatementResponse)
		if !ok {
			return nil, appSyncError("RDS:InternalFailure", "Unexpected RDS Data command result")
		}
		results = append(results, result)
	}
	encoded, err := json.Marshal(map[string]any{"sqlStatementResults": results})
	if err != nil {
		return nil, err
	}
	return string(encoded), nil
}

func appSyncSQLField(value any) (rds.Field, error) {
	switch v := value.(type) {
	case nil:
		return rds.Field{IsNull: new(rds.BoxedBoolean(true))}, nil
	case string:
		return rds.Field{StringValue: new(rds.String(v))}, nil
	case bool:
		return rds.Field{BooleanValue: new(rds.BoxedBoolean(v))}, nil
	case float64:
		if math.Trunc(v) == v && v >= -9007199254740991 && v <= 9007199254740991 {
			return rds.Field{LongValue: new(rds.BoxedLong(v))}, nil
		}
		return rds.Field{DoubleValue: new(rds.BoxedDouble(v))}, nil
	case int64:
		return rds.Field{LongValue: new(rds.BoxedLong(v))}, nil
	case int:
		return rds.Field{LongValue: new(rds.BoxedLong(v))}, nil
	case json.Number:
		if integer, err := strconv.ParseInt(string(v), 10, 64); err == nil {
			return rds.Field{LongValue: new(rds.BoxedLong(integer))}, nil
		}
		f, err := v.Float64()
		if err != nil {
			return rds.Field{}, err
		}
		return rds.Field{DoubleValue: new(rds.BoxedDouble(f))}, nil
	default:
		return rds.Field{}, appSyncError("MappingTemplate", "SQL variables must be strings, numbers, booleans or null")
	}
}

func appSyncCommand(ctx context.Context, owner awscommands.CommandExecutor, service, operation string, fields map[string]any) (any, *awswire.Error) {
	model, ok := awscatalog.LookupService(service)
	if !ok {
		return nil, &awswire.Error{Code: "NotImplemented", Message: "Unknown source service", StatusCode: 501}
	}
	op, ok := model.Operation(operation)
	if !ok {
		return nil, &awswire.Error{Code: "NotImplemented", Message: "Unknown source operation", StatusCode: 501}
	}
	input, err := awscommands.NewInput(service, operation)
	if err != nil {
		return nil, &awswire.Error{Code: "NotImplemented", Message: err.Error(), StatusCode: 501}
	}
	encoded, err := json.Marshal(fields)
	if err == nil {
		err = awsapi.DecodeSDKInput(model, op, encoded, input)
	}
	if err != nil {
		return nil, &awswire.Error{Code: "MappingTemplate", Message: err.Error(), StatusCode: 400}
	}
	return appSyncTypedCommand(ctx, owner, service, operation, input)
}

func appSyncTypedCommand(ctx context.Context, owner awscommands.CommandExecutor, service, operation string, input any) (any, *awswire.Error) {
	model, ok := awscatalog.LookupService(service)
	if !ok {
		return nil, &awswire.Error{Code: "NotImplemented", Message: "Unknown source service", StatusCode: 501}
	}
	op, ok := model.Operation(operation)
	if !ok {
		return nil, &awswire.Error{Code: "NotImplemented", Message: "Unknown source operation", StatusCode: 501}
	}
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID = uuid.NewString()
	ctx = awsctx.WithMetadata(ctx, metadata)
	return owner.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
}

func appSyncObject(value any, field string, required bool) (map[string]any, error) {
	if value == nil && !required {
		return nil, nil
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, appSyncError("MappingTemplate", field+" must be an object")
	}
	return result, nil
}
func appSyncText(value any) string { text, _ := value.(string); return text }
func appSyncString[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
func appSyncError(kind, message string) error {
	return &appsync.MappingError{Message: message, Type: kind}
}
func appSyncUnsupported(message string) error {
	return appSyncError("UnsupportedOperation", message+" is not supported")
}

// TODO: Comeback: DynamoDB batch/transaction/sync mappings, custom conditional
// Lambda handlers and signed HTTP sources must use their actual owner commands.
