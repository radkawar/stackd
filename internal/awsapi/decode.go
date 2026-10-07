// Package awsapi binds AWS wire requests to generated Go DTOs using the
// corresponding Smithy contracts. It does not implement service behavior.
package awsapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"

	"stackd/internal/awscatalog"
)

var (
	ErrUnknownOperation    = errors.New("unknown AWS operation")
	ErrUnsupportedProtocol = errors.New("unsupported AWS frontend protocol")
	ErrUnsupportedBinding  = errors.New("unsupported AWS HTTP binding")
)

type Request struct {
	// Protocol is selected from the service model by the transport boundary.
	// An empty value uses the model's preferred protocol for direct callers.
	Protocol awscatalog.Protocol
	JSON     []byte
	Query    url.Values
	// Body is the unmodified payload; JSON aliases it for AWS JSON protocols.
	Body   []byte
	Header http.Header
	// Host is the HTTP authority, which net/http keeps outside Header.
	Host string
	// Labels are decoded exactly once by the generated-model route matcher.
	Labels map[string]string
}

// DecodedRequest contains operation metadata and a generated *Input DTO for
// admitted requests. Rejection observers may attach service-owned projections;
// those observations are never dispatched as commands.
type DecodedRequest struct {
	Operation awscatalog.Operation
	Protocol  awscatalog.Protocol
	Input     any
	// Body borrows the bounded wire payload for source-owned observations.
	// Field presence, length and XML attributes must not be reconstructed
	// from the normalized DTO.
	Body []byte
}

// ValidationError describes invalid wire input without echoing sensitive values.
type ValidationError struct {
	Path   string
	Reason string
	// Constraint identifies a violated modeled bound (range.min, range.max,
	// length.min or length.max), missing required member (required), string
	// pattern mismatch (pattern), forbidden null value (nonnull), or malformed
	// Query primitive (query). Other validation failures leave it empty.
	// Services can map the failure without parsing the diagnostic text.
	Constraint string
	// EnumValue lets a service distinguish rejected enum tokens without echoing
	// them in the validation diagnostic. It is set only for string enums.
	EnumValue string
	// HTTPValue retains a rejected query/header value for service-specific
	// wire errors. It is never included in the validation diagnostic.
	HTTPValue string
	// TypeMismatch distinguishes an incompatible JSON value from a value
	// outside its modeled constraints, which can produce different service errors.
	TypeMismatch bool
}

func (e *ValidationError) Error() string {
	if e.Path == "" {
		return e.Reason
	}
	return e.Path + ": " + e.Reason
}

// Decode is called by generated operation adapters. It validates before
// unmarshalling, retaining null/presence distinctions that normal JSON binding
// would discard for scalar values, collection elements, and required members.
func Decode(service awscatalog.Service, operation awscatalog.Operation, request Request, out any) error {
	value := reflect.ValueOf(out)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return errors.New("AWS frontend destination must be a nonnil pointer")
	}
	var data []byte
	switch service.Protocol {
	case awscatalog.RPCV2CBOR:
		return decodeCBOR(service, operation, request.Body, out)
	case awscatalog.AWSQuery, awscatalog.EC2Query:
		for key, values := range request.Query {
			if len(values) != 1 {
				return &ValidationError{Path: key, Reason: "query parameter must occur exactly once"}
			}
		}
		if service.Protocol == awscatalog.EC2Query {
			if err := checkEC2QueryParameters(service, operation.Input, request.Query); err != nil {
				return err
			}
		}
		var err error
		data, _, err = queryValue(service, operation.Input, "", request.Query, false)
		if err != nil {
			return err
		}
	case awscatalog.RestJSON, awscatalog.RestXML:
		return decodeHTTPInput(service, operation, request, out, true)
	case awscatalog.AWSJSON10, awscatalog.AWSJSON11:
		data = request.JSON
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedProtocol, service.Protocol)
	}
	if len(data) == 0 {
		data = []byte("{}")
	}
	wireJSON := service.Protocol == awscatalog.AWSJSON10 || service.Protocol == awscatalog.AWSJSON11
	normalized, err := normalizeValue(service, operation.Input, data, "", awscatalog.Constraints{}, "", documentInput{wireJSON: wireJSON, validate: true})
	if err != nil {
		return err
	}
	if err := json.Unmarshal(normalized, out); err != nil {
		return fmt.Errorf("bind generated %s input: %w", operation.Name, err)
	}
	return nil
}

// DecodeCloudFormationInput binds service commands originating in resource
// handlers using their established SDK-style document contract. Numeric shapes
// additionally accept Number parameter Ref strings without changing the public
// AWS decoder or ordinary Step Functions SDK input normalization.
func DecodeCloudFormationInput(service awscatalog.Service, operation awscatalog.Operation, payload []byte, input any) error {
	value := reflect.ValueOf(input)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return errors.New("CloudFormation destination must be a nonnil pointer")
	}
	normalized, err := normalizeValue(service, operation.Input, payload, "", awscatalog.Constraints{}, "", documentInput{sdk: true, cloudFormation: true, validate: true, sdkInvokePayload: service.Name == "lambda" && operation.Name == "Invoke"})
	if err != nil {
		return err
	}
	if err := json.Unmarshal(normalized, input); err != nil {
		return fmt.Errorf("bind generated %s CloudFormation input: %w", operation.Name, err)
	}
	return nil
}

// BindJSON binds modeled JSON wire types without admitting the command or
// enforcing Smithy constraints. Rejected-request observers use it to measure
// typed inputs such as an over-limit collection; ordinary dispatch uses Decode.
// Malformed JSON and values that cannot bind to the modeled Go types still fail.
func BindJSON(service awscatalog.Service, shape awscatalog.ShapeID, data []byte, out any) error {
	normalized, err := normalizeValue(service, shape, data, "", awscatalog.Constraints{}, "", documentInput{wireJSON: true})
	if err != nil {
		return err
	}
	return json.Unmarshal(normalized, out)
}

// ValidateSDKMockResult applies modeled field and constraint validation to an
// explicit TestState mock. Mocked blob fields are strings, not transport base64
// or streamed SDK input documents. PRESENT mode permits absent required fields.
func ValidateSDKMockResult(service awscatalog.Service, shape awscatalog.ShapeID, data []byte, requireMembers bool) error {
	_, err := normalizeValue(service, shape, data, "", awscatalog.Constraints{}, "", documentInput{sdk: true, validate: true, allowMissingRequired: !requireMembers, mockResponse: true})
	return err
}

// BindHTTP binds modeled REST input without admitting the command or enforcing
// Smithy constraints. Rejected-request observers use it for source-owned
// projections; malformed payloads and unbindable wire types still fail.
func BindHTTP(service awscatalog.Service, operation awscatalog.Operation, request Request, out any) error {
	return decodeHTTPInput(service, operation, request, out, false)
}
