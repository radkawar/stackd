// Package awswire implements shared AWS protocol envelopes, not service models.
package awswire

import (
	"encoding/json"
	"encoding/xml"
	"net/http"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

// Error is an AWS API error with an explicit HTTP status.
type Error struct {
	Code       string
	Message    string
	StatusCode int
	// ResponseHeader contains source-owned headers retained on a protocol error.
	ResponseHeader http.Header
	Reason         string
	Type           string
	Fields         []ValidationField
	ResourceIDs    []string
	// Details contains additional modeled JSON error members, such as DynamoDB
	// cancellation reasons and condition-failure items. The protocol serializer
	// admits only members declared by the service error shape.
	Details map[string]json.RawMessage
	S3ErrorDetails
	// Cause preserves source failures for in-process adapters, never on the wire.
	Cause error `json:"-"`
	// Request-owned serialized XML, shared by pre-emission audit and the writer.
	restXMLBody []byte
}

// S3ErrorDetails contains native REST XML error members not modeled in Smithy.
// Other protocols never serialize these fields.
type S3ErrorDetails struct {
	Header                string  `xml:"Header,omitempty"`
	MissingHeaderName     string  `xml:"MissingHeaderName,omitempty"`
	AccountID             string  `xml:"AccountId,omitempty"`
	BucketName            string  `xml:"BucketName,omitempty"`
	Bucket                string  `xml:"Bucket,omitempty"`
	Region                string  `xml:"Region,omitempty"`
	Endpoint              string  `xml:"Endpoint,omitempty"`
	Key                   string  `xml:"Key,omitempty"`
	URI                   string  `xml:"URI,omitempty"`
	TagKey                string  `xml:"TagKey,omitempty"`
	TargetBucket          string  `xml:"TargetBucket,omitempty"`
	TargetBucketLocation  string  `xml:"TargetBucketLocation,omitempty"`
	MaxMessageLengthBytes int64   `xml:"MaxMessageLengthBytes,omitempty"`
	ContentMD5            string  `xml:"Content-MD5,omitempty"`
	ExpectedDigest        string  `xml:"ExpectedDigest,omitempty"`
	CalculatedDigest      string  `xml:"CalculatedDigest,omitempty"`
	AdditionalMessage     string  `xml:"additionalMessage,omitempty"`
	Method                string  `xml:"Method,omitempty"`
	ResourceType          string  `xml:"ResourceType,omitempty"`
	Condition             string  `xml:"Condition,omitempty"`
	ArgumentName          string  `xml:"ArgumentName,omitempty"`
	ArgumentValue         *string `xml:"ArgumentValue,omitempty"`
	UploadID              string  `xml:"UploadId,omitempty"`
	ETag                  string  `xml:"ETag,omitempty"`
	PartNumber            *int32  `xml:"PartNumber,omitempty"`
	PartSize              *int64  `xml:"PartSize,omitempty"`
	MinSizeAllowed        *int64  `xml:"MinSizeAllowed,omitempty"`
	PartNumberRequested   *int32  `xml:"PartNumberRequested,omitempty"`
	ActualPartCount       *int32  `xml:"ActualPartCount,omitempty"`
	StorageClass          string  `xml:"StorageClass,omitempty"`
	AccessTier            string  `xml:"AccessTier,omitempty"`
	StorageClassRequested *string `xml:"StorageClassRequested,omitempty"`
	VersionID             string  `xml:"VersionId,omitempty"`
}

// ValidationField identifies a rejected external request member.
type ValidationField struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }
func (e *Error) Unwrap() error { return e.Cause }

func errorStatus(err *Error) int {
	if err.StatusCode < 400 || err.StatusCode > 599 {
		return http.StatusBadRequest
	}
	return err.StatusCode
}

func setHeaders(w http.ResponseWriter, r *http.Request, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
}

func JSONError(w http.ResponseWriter, r *http.Request, err *Error) {
	body, errorType := jsonErrorEnvelope(w, r, err)
	writeJSONError(w, r, err, jsonContentType(r), errorType, body)
}

// RESTJSONError uses the generated error member names for REST JSON documents.
func RESTJSONError(w http.ResponseWriter, r *http.Request, service *awscatalog.Service, err *Error) {
	writeJSONError(w, r, err, "application/json", err.Code, jsonErrorBody(service, err, "reason"))
}

func writeJSONError(w http.ResponseWriter, r *http.Request, err *Error, contentType, errorType string, body any) {
	setHeaders(w, r, contentType)
	if errorType != "" {
		w.Header().Set("X-Amzn-Errortype", errorType)
	}
	w.WriteHeader(errorStatus(err))
	_ = json.NewEncoder(w).Encode(body)
}

func QueryError(w http.ResponseWriter, r *http.Request, namespace string, err *Error) {
	setHeaders(w, r, "text/xml; charset=utf-8")
	w.WriteHeader(errorStatus(err))
	kind := "Sender"
	if errorStatus(err) >= 500 {
		kind = "Receiver"
	}
	_ = xml.NewEncoder(w).Encode(struct {
		XMLName   xml.Name `xml:"ErrorResponse"`
		Namespace string   `xml:"xmlns,attr"`
		Type      string   `xml:"Error>Type"`
		Code      string   `xml:"Error>Code"`
		Message   string   `xml:"Error>Message"`
		RequestID string   `xml:"RequestId"`
	}{Namespace: namespace, Type: kind, Code: err.Code, Message: err.Message, RequestID: awsctx.FromContext(r.Context()).RequestID})
}

// EC2QueryError writes EC2's distinct error envelope without AWS Query metadata.
func EC2QueryError(w http.ResponseWriter, r *http.Request, err *Error) {
	setHeaders(w, r, "text/xml;charset=UTF-8")
	w.WriteHeader(errorStatus(err))
	_ = xml.NewEncoder(w).Encode(struct {
		XMLName   xml.Name `xml:"Response"`
		Code      string   `xml:"Errors>Error>Code"`
		Message   string   `xml:"Errors>Error>Message"`
		RequestID string   `xml:"RequestID"`
	}{Code: err.Code, Message: err.Message, RequestID: awsctx.FromContext(r.Context()).RequestID})
}
