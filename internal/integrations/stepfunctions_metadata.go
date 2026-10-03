package integrations

import (
	"context"
	"encoding/json"
	"strconv"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

// Lambda retains invocation-specific transport information outside its modeled
// DTO. Its response encoder owns those headers, not the workflow adapter.
type stepFunctionsResponseExecutor interface {
	ExecuteCommandResponse(context.Context, awsapi.DecodedRequest) (any, awsapi.HTTPResponse, *awswire.Error)
}

func stepFunctionsCommandResponse(result StepFunctionsCommandResult) (awsapi.HTTPResponse, error) {
	response, err := awsapi.EncodeHTTPResponse(result.Service, result.Operation, result.Output)
	if err != nil {
		return response, err
	}
	if result.Service.Protocol == awscatalog.AWSQuery {
		response.Body, err = awswire.EncodeQueryResponse(result.Service.XMLNamespace, string(result.Operation.Name), result.RequestID, struct {
			Fields []byte `xml:",innerxml"`
		}{Fields: response.Body})
		if err != nil {
			return awsapi.HTTPResponse{}, err
		}
		response.Header.Set("Content-Type", "text/xml; charset=utf-8")
	}
	response.Header.Set("X-Amzn-Requestid", result.RequestID)
	return response, nil
}

// Only optimized task results carry the Java SDK metadata envelope. Preserve
// actual service headers and response identity; internal calls have no proxy,
// connection, or HTTP-server Date headers to report.
func stepFunctionsAddMetadata(document map[string]json.RawMessage, result StepFunctionsCommandResult) error {
	allHeaders := result.Response.Header.Clone()
	allHeaders.Set("Content-Length", strconv.Itoa(len(result.Response.Body)))
	headers := make(map[string]string, len(allHeaders))
	for name, values := range allHeaders {
		if len(values) != 0 {
			// SdkHttpMetadata.getHttpHeaders retains the last seen value.
			headers[name] = values[len(values)-1]
		}
	}
	metadata, err := json.Marshal(struct {
		AllHttpHeaders map[string][]string
		HttpHeaders    map[string]string
		HttpStatusCode int
	}{AllHttpHeaders: allHeaders, HttpHeaders: headers, HttpStatusCode: result.Response.StatusCode})
	if err != nil {
		return err
	}
	document["SdkHttpMetadata"] = metadata
	metadata, err = json.Marshal(struct{ RequestId string }{RequestId: result.RequestID})
	if err != nil {
		return err
	}
	document["SdkResponseMetadata"] = metadata
	return nil
}

func stepFunctionsOptimizedOutput(result StepFunctionsCommandResult, output []byte) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(output, &document); err != nil {
		return nil, err
	}
	if err := stepFunctionsAddMetadata(document, result); err != nil {
		return nil, err
	}
	return json.Marshal(document)
}
