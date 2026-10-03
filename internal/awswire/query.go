package awswire

import (
	"bytes"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

func ParseQuery(r *http.Request, protocol awscatalog.Protocol) (url.Values, error) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		return nil, errors.New("AWS Query requires GET or POST")
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	for key, values := range r.Form {
		if protocol == awscatalog.EC2Query && len(values) > 1 {
			if r.Method == http.MethodPost {
				r.Form[key] = values[len(values)-1:]
			} else {
				r.Form[key] = values[:1]
			}
			continue
		}
		if len(values) != 1 {
			return nil, errors.New("duplicate query parameter: " + key)
		}
	}
	return r.Form, nil
}

// WriteQuery wraps the typed result using the operation-specific AWS Query
// element names. It serializes before writing headers so encoding errors cannot
// become successful, truncated responses.
func WriteQuery(w http.ResponseWriter, r *http.Request, namespace, action string, result any) {
	body, err := EncodeQueryResponse(namespace, action, awsctx.FromContext(r.Context()).RequestID, result)
	if err != nil {
		QueryError(w, r, namespace, &Error{Code: "InternalFailure", Message: "Unable to serialize response", StatusCode: http.StatusInternalServerError})
		return
	}
	setHeaders(w, r, "text/xml; charset=utf-8")
	_, _ = w.Write(body)
}

// EncodeQueryResponse owns the AWS Query result and request-identity envelope
// for both HTTP delivery and internal consumers of that actual response.
func EncodeQueryResponse(namespace, action, requestID string, result any) ([]byte, error) {
	var body bytes.Buffer
	encoder := xml.NewEncoder(&body)
	root := xml.StartElement{Name: xml.Name{Local: action + "Response"}, Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: namespace}}}
	err := encoder.EncodeToken(root)
	if err == nil && result != nil {
		err = encoder.EncodeElement(result, xml.StartElement{Name: xml.Name{Local: action + "Result"}})
	}
	if err == nil {
		err = encoder.Encode(struct {
			XMLName   xml.Name `xml:"ResponseMetadata"`
			RequestID string   `xml:"RequestId"`
		}{RequestID: requestID})
	}
	if err == nil {
		err = encoder.EncodeToken(root.End())
	}
	if err == nil {
		err = encoder.Flush()
	}
	return body.Bytes(), err
}

// WriteQueryBytes wraps XML fields already serialized by the generated model
// binding. Only pass output from that serializer, never raw request content.
func WriteQueryBytes(w http.ResponseWriter, r *http.Request, namespace, action string, fields []byte) {
	WriteQuery(w, r, namespace, action, struct {
		Fields string `xml:",innerxml"`
	}{Fields: string(fields)})
}

// WriteEC2QueryBytes places generated fields directly inside the response,
// without AWS Query's operation Result and ResponseMetadata wrappers.
func WriteEC2QueryBytes(w http.ResponseWriter, r *http.Request, namespace, action string, fields []byte) {
	body, err := xml.Marshal(struct {
		XMLName   xml.Name
		Namespace string `xml:"xmlns,attr"`
		RequestID string `xml:"requestId"`
		Fields    []byte `xml:",innerxml"`
	}{
		XMLName: xml.Name{Local: action + "Response"}, Namespace: namespace,
		RequestID: awsctx.FromContext(r.Context()).RequestID, Fields: fields,
	})
	if err != nil {
		EC2QueryError(w, r, &Error{Code: "InternalFailure", Message: "Unable to serialize response", StatusCode: http.StatusInternalServerError})
		return
	}
	setHeaders(w, r, "text/xml;charset=UTF-8")
	_, _ = w.Write(body)
}
