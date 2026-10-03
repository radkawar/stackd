package awswire

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

// S3HostID is the opaque extended request ID shared by S3 wire and audit output.
func S3HostID(requestID string) string {
	return base64.StdEncoding.EncodeToString([]byte(requestID))
}

// RESTXMLError follows the service's modeled XML error wrapping. HEAD failures
// carry status and request identity, but never an XML response body.
func RESTXMLError(w http.ResponseWriter, r *http.Request, service *awscatalog.Service, err *Error) {
	requestID := awsctx.FromContext(r.Context()).RequestID
	hostID := ""
	for name, values := range err.ResponseHeader {
		w.Header()[name] = values
	}
	w.Header().Set("Content-Type", "application/xml")
	if service.SigningName == "s3" {
		if observer, ok := w.(interface{ ObserveS3Error(string) }); ok {
			observer.ObserveS3Error(err.Code)
		}
		hostID = S3HostID(requestID)
		w.Header().Set("X-Amz-Request-Id", requestID)
		w.Header().Set("X-Amz-Id-2", hostID)
	} else {
		w.Header().Set("X-Amzn-Requestid", requestID)
	}
	status := errorStatus(err)
	// S3 redirects retain their XML error envelope; streaming operations can
	// report failure inside an HTTP 200 response.
	if service.SigningName == "s3" && (err.StatusCode == http.StatusOK || err.StatusCode == http.StatusMovedPermanently) {
		status = err.StatusCode
	}
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	if err.restXMLBody != nil {
		_, _ = w.Write(err.restXMLBody)
		return
	}
	_ = encodeRESTXMLError(w, service, requestID, hostID, err)
}

// PrepareRESTXMLError serializes a request-owned error and returns its wire size.
// RESTXMLError emits those same bytes. The error must not be reused for another
// request; ordinary errors that need no pre-emission size remain streaming.
func PrepareRESTXMLError(service *awscatalog.Service, requestID string, err *Error) (int, error) {
	if err.restXMLBody == nil {
		hostID := ""
		if service.SigningName == "s3" {
			hostID = S3HostID(requestID)
		}
		var body bytes.Buffer
		if encodeErr := encodeRESTXMLError(&body, service, requestID, hostID, err); encodeErr != nil {
			return 0, encodeErr
		}
		err.restXMLBody = body.Bytes()
	}
	return len(err.restXMLBody), nil
}

func encodeRESTXMLError(w io.Writer, service *awscatalog.Service, requestID, hostID string, err *Error) error {
	var s3Details S3ErrorDetails
	if service.SigningName == "s3" {
		s3Details = err.S3ErrorDetails
	}
	detail := struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
		S3ErrorDetails
	}{Code: err.Code, Message: err.Message, S3ErrorDetails: s3Details}
	if !service.XMLNoErrorWrapping {
		return xml.NewEncoder(w).Encode(struct {
			XMLName   xml.Name `xml:"ErrorResponse"`
			Error     any      `xml:"Error"`
			RequestID string   `xml:"RequestId"`
			HostID    string   `xml:"HostId,omitempty"`
		}{Error: detail, RequestID: requestID, HostID: hostID})
	}
	return xml.NewEncoder(w).Encode(struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string   `xml:"Code"`
		Message   string   `xml:"Message"`
		RequestID string   `xml:"RequestId"`
		HostID    string   `xml:"HostId,omitempty"`
		S3ErrorDetails
	}{Code: detail.Code, Message: detail.Message, RequestID: requestID, HostID: hostID, S3ErrorDetails: s3Details})
}
