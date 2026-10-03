package gateway

import (
	"bytes"
	"compress/gzip"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

func (p Protocol) modelProtocol() awscatalog.Protocol {
	switch p {
	case Query:
		return awscatalog.AWSQuery
	case JSON10:
		return awscatalog.AWSJSON10
	case JSON11:
		return awscatalog.AWSJSON11
	default:
		return awscatalog.Protocol(p)
	}
}

// selectProtocol chooses only protocols advertised by this service's model.
// The signing service still owns routing; a target cannot change that identity.
func selectProtocol(r *http.Request, service *Service) (*Service, *awswire.Error) {
	protocol := service.Protocol
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Header.Get("Smithy-Protocol") != "" || contentType == "application/cbor" {
		protocol = RPCV2CBOR
	} else if service.Model != nil && len(service.Model.Protocols) > 1 {
		protocol = Query
		if r.Header.Get("X-Amz-Target") != "" {
			protocol = JSON10
			if contentType == "application/x-amz-json-1.1" {
				protocol = JSON11
			}
		}
	}
	if protocol != service.Protocol {
		if service.Model == nil || !slices.Contains(service.Model.Protocols, protocol.modelProtocol()) {
			return service, protocolError("The request protocol is not supported by the signing service.")
		}
		selected := *service
		selected.Protocol = protocol
		service = &selected
	}
	if protocol == RPCV2CBOR {
		if r.Header.Get("Smithy-Protocol") != "rpc-v2-cbor" {
			return service, protocolError("Smithy-Protocol must be rpc-v2-cbor.")
		}
		if r.Header.Get("X-Amz-Target") != "" || r.Header.Get("X-Amzn-Target") != "" {
			return service, protocolError("RPCv2 requests must not include a target header.")
		}
	}
	return service, nil
}

func protocolError(message string) *awswire.Error {
	return &awswire.Error{Code: "InvalidAction", Message: message, StatusCode: http.StatusBadRequest}
}

func rpcOperation(r *http.Request, service *Service) (string, *awswire.Error) {
	if r.Method != http.MethodPost {
		return "", protocolError("RPCv2 APIs require POST.")
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		return "", protocolError("Invalid RPCv2 operation path.")
	}
	parts = parts[len(parts)-4:]
	if parts[0] != "service" || parts[2] != "operation" || parts[3] == "" || strings.ContainsAny(parts[3], ".#") {
		return "", protocolError("Invalid RPCv2 operation path.")
	}
	absolute := strings.Replace(string(service.Model.ID), "#", ".", 1)
	if parts[1] != service.TargetPrefix && parts[1] != absolute {
		return "", protocolError("RPCv2 service name does not match the signing service.")
	}
	return parts[3], nil
}

func (g *Gateway) operationInput(r *http.Request, service *Service) (string, awsapi.Request, *awswire.Error) {
	input := awsapi.Request{Protocol: service.Protocol.modelProtocol(), Header: r.Header, Host: r.Host}
	if service.Name == "s3control" {
		if account, ok := s3ControlAccount(r.Host); ok {
			// Authentication has verified the original host and headers. Native
			// account endpoints take precedence only in the decoded input.
			input.Header = r.Header.Clone()
			input.Header.Set("X-Amz-Account-Id", account)
		}
	}
	if service.Protocol != RestJSON && service.Protocol != RestXML && service.Protocol != RPCV2CBOR && r.URL.Path != "/" {
		return "", input, protocolError("No operation at this path")
	}
	encoding := r.Header.Get("Content-Encoding")
	compressedRequest := encoding != "" && (service.Protocol == Query || service.Protocol == EC2Query || service.Protocol == JSON10 || service.Protocol == JSON11 || service.Protocol == RPCV2CBOR)
	if compressedRequest {
		if encoding != "gzip" {
			return "", input, protocolError("Unsupported request content encoding.")
		}
		// Query carries its action inside the compressed body. Signature
		// verification has already consumed the original signed bytes.
		compressed, err := gzip.NewReader(r.Body)
		if err != nil {
			return "", input, protocolError("Invalid compressed request body.")
		}
		defer compressed.Close()
		r.Body = http.MaxBytesReader(nil, compressed, g.config.MaxBodyBytes)
	}
	var action string
	switch service.Protocol {
	case Query, EC2Query:
		params, err := awswire.ParseQuery(r, service.Protocol.modelProtocol())
		if err != nil {
			return "", input, &awswire.Error{Code: "InvalidParameterValue", Message: err.Error(), StatusCode: 400}
		}
		if params.Get("Version") != service.QueryVersion {
			return "", input, &awswire.Error{Code: "InvalidParameterValue", Message: "Unsupported API version", StatusCode: 400}
		}
		input.Query = params
		action = params.Get("Action")
	case RPCV2CBOR:
		var failure *awswire.Error
		action, failure = rpcOperation(r, service)
		if failure != nil {
			return "", input, failure
		}
		operation, known := service.Model.Operation(action)
		contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if known && operation.Input == "smithy.api#Unit" {
			if r.Header.Get("Content-Type") != "" {
				return "", input, protocolError("Unit input must not declare a content type.")
			}
		} else if err != nil || contentType != "application/cbor" {
			return "", input, protocolError("RPCv2 input requires application/cbor.")
		}
	case RestJSON, RestXML:
		input.Query = r.URL.Query()
		path := r.URL.EscapedPath()
		if service.Name == "s3" {
			path = S3RequestPath(r)
		}
		operation, labels, ok := service.Model.MatchHTTPOperation(r.Method, path, input.Query, r.Header)
		if !ok {
			return "", input, &awswire.Error{Code: "UnknownOperationException", Message: "No operation at this HTTP method and path", StatusCode: http.StatusNotFound}
		}
		action, input.Labels = string(operation.Name), labels
	case JSON10, JSON11:
		if r.Method != http.MethodPost {
			return "", input, protocolError("JSON APIs require POST")
		}
		_, action, _ = awswire.JSONTarget(r.Header.Get("X-Amz-Target"))
	}
	if compressedRequest {
		var supported bool
		if service.Model != nil {
			operation, _ := service.Model.Operation(action)
			supported = slices.Contains(operation.RequestCompression, encoding)
		}
		if !supported {
			return "", input, protocolError("Unsupported request content encoding.")
		}
	}
	if service.Protocol == Query || service.Protocol == EC2Query || service.Decode == nil {
		return action, input, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", input, protocolError("Unable to read request body.")
	}
	input.Body = body
	if service.Protocol == JSON10 || service.Protocol == JSON11 {
		input.JSON = body
	}
	if service.Name == "s3" {
		operation, _ := service.Model.Operation(action)
		if failure := ValidateS3DocumentChecksum(service.Model, operation, r.Header, body); failure != nil {
			if resolver, ok := service.Provider.(requestErrorResolver); ok {
				failure = resolver.ResolveRequestError(r.Context(), action, input, failure)
			}
			return action, input, failure
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return action, input, nil
}
