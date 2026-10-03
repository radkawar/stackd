package lambda

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const functionURLIntegrationContentType = "application/vnd.awslambda.http-integration-response"

var functionURLMetadataDelimiter = []byte{0, 0, 0, 0, 0, 0, 0, 0}

type functionURLResponse struct {
	status int
	header http.Header
	body   []byte
}

func functionURLDefaultResponse(payload []byte, contentType string) functionURLResponse {
	header := make(http.Header)
	header.Set("Content-Type", contentType)
	return functionURLResponse{status: http.StatusOK, header: header, body: payload}
}

// These views borrow the immutable invocation payload for the duration of the
// parse; in particular an ordinary streamed handler must not copy its body.
type functionURLJSONValue []byte

func (value *functionURLJSONValue) UnmarshalJSON(data []byte) error {
	*value = data
	return nil
}

// Parse only proxy metadata here. Both transports share its status, header and
// cookie coercions; their body delivery is deliberately different.
func parseFunctionURLResponse(payload []byte, metadata, buffered bool) (functionURLResponse, error) {
	out := functionURLDefaultResponse(payload, "application/json")
	var fields struct {
		StatusCode      functionURLJSONValue `json:"statusCode"`
		Headers         functionURLJSONValue `json:"headers"`
		Cookies         functionURLJSONValue `json:"cookies"`
		Body            functionURLJSONValue `json:"body"`
		IsBase64Encoded bool                 `json:"isBase64Encoded"`
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		if metadata {
			return out, err
		}
		var text string
		if buffered && json.Unmarshal(payload, &text) == nil {
			out.body = []byte(text)
		}
		return out, nil
	}
	status, proxy := fields.StatusCode, len(fields.StatusCode) != 0
	if !proxy && !metadata {
		return out, nil
	}
	out.body = nil
	if proxy {
		value := strings.Trim(string(status), "\"")
		code, err := strconv.Atoi(value)
		if err != nil || code < 100 || code > 599 {
			return out, errors.New("invalid function URL response status")
		}
		out.status = code
	}
	if raw := fields.Headers; len(raw) != 0 && !bytes.Equal(raw, []byte("null")) {
		var headers map[string]json.RawMessage
		if err := json.Unmarshal(raw, &headers); err != nil {
			return out, err
		}
		for key, value := range headers {
			text, err := functionURLHeaderValue(value)
			if err != nil {
				return out, err
			}
			// HTTP framing belongs to this transport, never to the function.
			switch strings.ToLower(key) {
			case "content-length", "transfer-encoding", "connection", "trailer", "upgrade", "keep-alive":
				continue
			}
			out.header.Add(key, text)
		}
		if values := out.header.Values("Content-Type"); len(values) > 1 {
			out.header["Content-Type"] = values[1:]
		}
	}
	if raw := fields.Cookies; len(raw) != 0 && !bytes.Equal(raw, []byte("null")) {
		var cookies []json.RawMessage
		if err := json.Unmarshal(raw, &cookies); err != nil {
			return out, err
		}
		for _, cookie := range cookies {
			text, err := functionURLHeaderValue(cookie)
			if err != nil {
				return out, err
			}
			out.header.Add("Set-Cookie", text)
		}
	}
	if metadata || !buffered {
		return out, nil
	}
	if raw := fields.Body; len(raw) != 0 {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			out.body = []byte(text)
		} else {
			var compact bytes.Buffer
			if err := json.Compact(&compact, raw); err != nil {
				return out, err
			}
			out.body = compact.Bytes()
		}
	}
	if fields.IsBase64Encoded {
		out.body = functionURLDecodeBase64(out.body)
	}
	return out, nil
}

// The native integration stringifies header objects with map/list notation,
// unlike body objects, which remain JSON.
func functionURLHeaderValue(raw json.RawMessage) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	return functionURLHeaderString(value), nil
}

func functionURLHeaderString(value any) string {
	switch value := value.(type) {
	case nil:
		return "null"
	case string:
		return value
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, key+"="+functionURLHeaderString(value[key]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case []any:
		parts := make([]string, len(value))
		for i, element := range value {
			parts[i] = functionURLHeaderString(element)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprint(value)
	}
}

// Native decoding accepts URL-safe alphabet, omitted padding and nonalphabet
// characters (for example !!!not-base64!!!), rather than rejecting the response.
func functionURLDecodeBase64(body []byte) []byte {
	filtered := make([]byte, 0, len(body))
	for _, char := range body {
		switch {
		case char >= 'A' && char <= 'Z', char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '+', char == '/':
			filtered = append(filtered, char)
		case char == '-':
			filtered = append(filtered, '+')
		case char == '_':
			filtered = append(filtered, '/')
		case char == '=':
			goto decode
		}
	}
decode:
	if len(filtered)%4 == 1 {
		filtered = filtered[:len(filtered)-1]
	}
	decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(filtered)))
	n, _ := base64.RawStdEncoding.Decode(decoded, filtered)
	return decoded[:n]
}

func writeBufferedFunctionURLResponse(w http.ResponseWriter, r *http.Request, out *invocationOutput, cors *FunctionURLCORS) error {
	response := functionURLDefaultResponse(nil, "application/json")
	var err error
	switch {
	case out == nil:
		return writeFunctionURLBadGateway(w, r, cors)
	case out.streamed:
		if len(out.Payload) != 0 {
			if out.runtimeContentType == functionURLIntegrationContentType {
				boundary := bytes.Index(out.Payload, functionURLMetadataDelimiter)
				if boundary < 0 {
					return writeFunctionURLBadGateway(w, r, cors)
				}
				response, err = parseFunctionURLResponse(out.Payload[:boundary], true, false)
			} else {
				response = functionURLDefaultResponse(out.Payload, "application/octet-stream")
			}
		}
	case out.FunctionError != nil:
		return writeFunctionURLBadGateway(w, r, cors)
	default:
		response, err = parseFunctionURLResponse(out.Payload, false, true)
	}
	if err != nil {
		return writeFunctionURLBadGateway(w, r, cors)
	}
	return writeFunctionURLBuffered(w, r, response, cors)
}

func writeFunctionURLBadGateway(w http.ResponseWriter, r *http.Request, cors *FunctionURLCORS) error {
	response := functionURLDefaultResponse([]byte("Internal Server Error"), "application/json")
	response.status = http.StatusBadGateway
	return writeFunctionURLBuffered(w, r, response, cors)
}

func writeFunctionURLBuffered(w http.ResponseWriter, r *http.Request, response functionURLResponse, cors *FunctionURLCORS) error {
	if r.Method == http.MethodHead || response.status == http.StatusNoContent || response.status == http.StatusNotModified {
		response.body = nil
	}
	functionURLResponseHeaders(w.Header(), r, response, cors)
	w.Header().Set("Content-Length", strconv.Itoa(len(response.body)))
	w.WriteHeader(response.status)
	if len(response.body) == 0 {
		return nil
	}
	_, err := w.Write(response.body)
	return err
}

func functionURLResponseHeaders(header http.Header, r *http.Request, response functionURLResponse, cors *FunctionURLCORS) {
	for key, values := range response.header {
		header[key] = values
	}
	functionURLCORSHeaders(header, r, cors, false)
}

func writeStreamingFunctionURLResponse(ctx context.Context, w http.ResponseWriter, r *http.Request, stream *invocationStream, cors *FunctionURLCORS) error {
	response := functionURLDefaultResponse(nil, stream.contentType)
	if response.header.Get("Content-Type") == "" {
		response.header.Set("Content-Type", "application/octet-stream")
	}
	metadata := stream.streamed && stream.contentType == functionURLIntegrationContentType
	if !stream.streamed {
		var err error
		response, err = parseFunctionURLResponse(stream.bufferedPayload, false, false)
		if err != nil {
			return writeFunctionURLBadGateway(w, r, cors)
		}
		// Ordinary handlers keep their original response bytes in this mode.
		response.body = nil
	}
	var prefix bytes.Buffer
	zeros := 0
	started := false
	start := func() {
		functionURLResponseHeaders(w.Header(), r, response, cors)
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", "0")
		}
		w.WriteHeader(response.status)
		started = true
		if r.Method != http.MethodHead {
			_ = http.NewResponseController(w).Flush()
		}
	}
	if !metadata {
		start()
	}
	received := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, open := <-stream.events:
			if !open {
				if !started {
					if prefix.Len() != 0 {
						return writeFunctionURLBadGateway(w, r, cors)
					}
					response = functionURLDefaultResponse(nil, "application/octet-stream")
					start()
				}
				if stream.streamed && !received && r.Method != http.MethodHead {
					// Native empty streams remained open beyond the bounded
					// 90-second probe. Await delivery cancellation, not a made-up
					// timer; the completed execution owns no runtime lease here.
					<-ctx.Done()
					return ctx.Err()
				}
				return nil
			}
			// Completion errors cannot replace already emitted bytes and native
			// function URLs do not project InvokeComplete into HTTP trailers.
			if event.PayloadChunk == nil {
				continue
			}
			payload := []byte(event.PayloadChunk.Payload)
			received = received || len(payload) != 0
			if metadata && !started {
				consumed := 0
				for consumed < len(payload) {
					char := payload[consumed]
					consumed++
					prefix.WriteByte(char)
					if char == 0 {
						zeros++
					} else {
						zeros = 0
					}
					if zeros == len(functionURLMetadataDelimiter) {
						break
					}
				}
				payload = payload[consumed:]
				if zeros != len(functionURLMetadataDelimiter) {
					continue
				}
				var err error
				response, err = parseFunctionURLResponse(prefix.Bytes()[:prefix.Len()-zeros], true, false)
				if err != nil {
					return writeFunctionURLBadGateway(w, r, cors)
				}
				prefix = bytes.Buffer{}
				start()
			}
			if len(payload) == 0 || r.Method == http.MethodHead || response.status == http.StatusNoContent || response.status == http.StatusNotModified {
				continue
			}
			if n, err := w.Write(payload); err != nil {
				return err
			} else if n != len(payload) {
				return io.ErrShortWrite
			}
			if err := http.NewResponseController(w).Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
				return err
			}
		}
	}
}
