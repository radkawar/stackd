package awstest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// CallSDK replays a fixture through the named operation of an AWS SDK for Go v2
// client, using its SDK method name or AWS CLI spelling. The client owns endpoint,
// credentials, retries and middleware. CLI names resolve against the actual SDK
// methods, preserving initialisms rather than maintaining a parallel name table.
// Input uses SDK field names and native union envelopes, with RFC3339 or epoch timestamps.
// The returned value is the actual decoded SDK output, with its result metadata.
// Prepare functions attach values JSON cannot represent, such as streaming
// readers, to the decoded typed input before invocation.
func CallSDK(ctx context.Context, client any, operation string, input json.RawMessage, prepare ...func(any)) (any, error) {
	receiver := reflect.ValueOf(client)
	method := receiver.MethodByName(operation)
	if !method.IsValid() {
		name := strings.ReplaceAll(operation, "-", "")
		for i := range receiver.NumMethod() {
			if strings.EqualFold(receiver.Type().Method(i).Name, name) {
				method = receiver.Method(i)
				break
			}
		}
	}
	if !method.IsValid() {
		return nil, fmt.Errorf("SDK client %T has no operation %q", client, operation)
	}
	parameter := reflect.New(method.Type().In(1).Elem())
	if err := DecodeSDK(input, parameter.Interface()); err != nil {
		return nil, fmt.Errorf("decode %s input: %w", operation, err)
	}
	for _, apply := range prepare {
		apply(parameter.Interface())
	}
	result := method.Call([]reflect.Value{reflect.ValueOf(ctx), parameter})
	if !result[1].IsNil() {
		return result[0].Interface(), result[1].Interface().(error)
	}
	return result[0].Interface(), nil
}

// WireClient retains the last response while the SDK still decodes it. Native
// fixture comparisons use the wire body to preserve absent/null/empty fields.
// A replay owns one client and invokes it sequentially.
type WireClient struct {
	Client aws.HTTPClient
	Body   []byte
	Status int
}

func (w *WireClient) Do(request *http.Request) (*http.Response, error) {
	response, err := w.Client.Do(request)
	if err != nil {
		return response, err
	}
	w.Status = response.StatusCode
	w.Body, err = io.ReadAll(response.Body)
	response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(w.Body))
	return response, err
}
