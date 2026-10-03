package awswire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

// DecodeJSON accepts exactly one JSON object. Unknown fields are tolerated, as
// required for forward-compatible AWS clients; malformed or trailing data is not.
func DecodeJSON(r *http.Request, input any) error {
	decoder := json.NewDecoder(r.Body)
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("request must be a JSON object")
	}
	if err := json.Unmarshal(raw, input); err != nil {
		return err
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("unexpected data after JSON object")
	}
	return nil
}

func WriteJSON(w http.ResponseWriter, r *http.Request, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		JSONError(w, r, &Error{Code: "InternalFailure", Message: "Unable to serialize response", StatusCode: http.StatusInternalServerError})
		return
	}
	WriteJSONBytes(w, r, body)
}

// WriteJSONBytes writes an already encoded AWS JSON response.
func WriteJSONBytes(w http.ResponseWriter, r *http.Request, body []byte) {
	setHeaders(w, r, jsonContentType(r))
	_, _ = w.Write(body)
}

func jsonContentType(r *http.Request) string {
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if contentType == "application/x-amz-json-1.0" {
		return contentType
	}
	return "application/x-amz-json-1.1"
}
