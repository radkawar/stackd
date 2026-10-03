package awsapi_test

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"

	"stackd/internal/awsapi"
	lambdaapi "stackd/internal/awsapi/lambda"
	"stackd/internal/awscatalog"
)

func TestRESTBindingLocationsCannotOverrideEachOther(t *testing.T) {
	service, _ := awscatalog.LookupService("lambda")
	for _, fixture := range []struct {
		uri, body string
		method    string
		check     func(*testing.T, any)
	}{
		{
			uri:    "/2015-03-31/functions/arn%3Aaws%3Alambda%3Aus-east-1%3A123456789012%3Afunction%3Ademo/configuration?Timeout=99",
			method: "PUT",
			body:   `{"FunctionName":"body-spoof","Timeout":4}`,
			check: func(t *testing.T, input any) {
				value := input.(*lambdaapi.UpdateFunctionConfigurationInput)
				if value.FunctionName == nil || string(*value.FunctionName) != "arn:aws:lambda:us-east-1:123456789012:function:demo" || value.Timeout == nil || int32(*value.Timeout) != 4 {
					t.Fatalf("HTTP label/body precedence violated: %+v", value)
				}
			},
		},
		{
			uri:    "/2015-03-31/functions?MaxItems=2&MaxItems=3",
			method: "GET",
			check: func(t *testing.T, input any) {
				value := input.(*lambdaapi.ListFunctionsInput)
				if value.MaxItems == nil || int32(*value.MaxItems) != 2 {
					t.Fatalf("query-only request did not select first value: %+v", value)
				}
			},
		},
		{
			uri:    "/2015-03-31/functions/demo?Qualifier=3",
			method: "DELETE",
			check: func(t *testing.T, input any) {
				value := input.(*lambdaapi.DeleteFunctionInput)
				if value.FunctionName == nil || string(*value.FunctionName) != "demo" || value.Qualifier == nil || string(*value.Qualifier) != "3" {
					t.Fatalf("empty DELETE body lost HTTP bindings: %+v", value)
				}
			},
		},
	} {
		t.Run(fixture.method+fixture.uri, func(t *testing.T) {
			uri, err := url.Parse(fixture.uri)
			if err != nil {
				t.Fatal(err)
			}
			op, labels, ok := service.MatchHTTPOperation(fixture.method, uri.EscapedPath(), uri.Query(), nil)
			if !ok {
				t.Fatal("no generated route")
			}
			decoded, err := lambdaapi.DecodeRequest(string(op.Name), awsapi.Request{Labels: labels, Query: uri.Query(), Body: []byte(fixture.body)})
			if err != nil {
				t.Fatal(err)
			}
			fixture.check(t, decoded.Input)
		})
	}
}

func TestRESTRawPayloadAndModeledResponseBindings(t *testing.T) {
	payload := []byte{0, 255, '"', '\n', 128}
	decoded, err := lambdaapi.DecodeRequest("Invoke", awsapi.Request{
		Labels: map[string]string{"FunctionName": "demo"}, Body: payload,
		Header: http.Header{"X-Amz-Invocation-Type": {"RequestResponse"}},
		Query:  url.Values{"InvocationType": {"Event"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := decoded.Input.(*lambdaapi.InvokeInput)
	if !bytes.Equal(input.Payload, payload) || input.InvocationType == nil || string(*input.InvocationType) != "RequestResponse" {
		t.Fatalf("raw payload or header binding changed: %+v", input)
	}
	service, _ := awscatalog.LookupService("lambda")
	operation, _ := service.Operation("Invoke")
	status := lambdaapi.Integer(202)
	functionError := lambdaapi.String("Unhandled")
	response, err := awsapi.EncodeHTTPResponse(service, operation, &lambdaapi.InvokeOutput{Payload: payload, StatusCode: &status, FunctionError: &functionError})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 202 || response.Header.Get("X-Amz-Function-Error") != "Unhandled" || !bytes.Equal(response.Body, payload) {
		t.Fatalf("modeled response bindings changed: %+v", response)
	}
}
