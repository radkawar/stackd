package s3

import (
	"net/http"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

// preparedResponse commits the actual generated response length with its audit
// event, then returns those same bytes without serializing again after commit.
// The original modeled output remains available to typed command callers.
type preparedResponse struct {
	response          awsapi.HTTPResponse
	output            any
	encryptionContext string
	storageClass      string
	statusCode        int
}

func (r *preparedResponse) encodedResponse() awsapi.HTTPResponse { return r.response }

func (r *preparedResponse) modeledOutput() any { return r.output }

func (r *preparedResponse) responseWithHeaders(headers http.Header) any {
	setEncryptionContextHeader(headers, r.encryptionContext)
	setStorageClassHeader(headers, r.storageClass)
	return r
}

// ObjectResponse retains generated SDK fields and the authoritative bucket
// region, plus native headers absent from the Smithy output shapes.
type ObjectResponse[O any] struct {
	Output O
	Region string
	// BucketAccountID is available to in-process consumers after an authorized
	// HeadObject or GetObject. It is not part of the AWS wire response.
	BucketAccountID   string
	encryptionContext string
	storageClass      string
}

func (r *ObjectResponse[O]) responseWithHeaders(headers http.Header) any {
	setEncryptionContextHeader(headers, r.encryptionContext)
	setStorageClassHeader(headers, r.storageClass)
	return &r.Output
}

func (r *ObjectResponse[O]) modeledOutput() any { return &r.Output }

func setEncryptionContextHeader(headers http.Header, value string) {
	if value != "" {
		headers.Set("x-amz-server-side-encryption-context", value)
	}
}

func setStorageClassHeader(headers http.Header, class string) {
	if class != "" {
		headers.Set("x-amz-storage-class", class)
	}
}

func (r *preparedResponse) prepare(c *apiCall, out any) error {
	model, _ := awscatalog.LookupService(c.service)
	operation, _ := model.Operation(c.name)
	response, err := awsapi.EncodeHTTPResponse(model, operation, out)
	if err != nil {
		return err
	}
	if r.statusCode != 0 {
		response.StatusCode = r.statusCode
	}
	r.response = response
	r.output = out
	if c.additional == nil {
		c.additional = map[string]any{}
	}
	c.additional["bytesTransferredOut"] = len(response.Body)
	c.additional["httpStatusCode"] = response.StatusCode
	return nil
}

func prepareErrorResponse(c *apiCall, requestID string, wire *awswire.Error) error {
	model, _ := awscatalog.LookupService(c.service)
	size, err := awswire.PrepareRESTXMLError(&model, requestID, wire)
	if err != nil {
		return err
	}
	c.additional["bytesTransferredOut"] = size
	return nil
}
