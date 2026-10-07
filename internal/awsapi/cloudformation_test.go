package awsapi_test

import (
	"errors"
	"testing"

	"stackd/internal/awsapi"
	gatewayapi "stackd/internal/awsapi/apigateway"
	lambdaapi "stackd/internal/awsapi/lambda"
	"stackd/internal/awscatalog"
)

func TestCloudFormationModeledNumericStringsAndPublicStrictness(t *testing.T) {
	service, _ := awscatalog.LookupService("lambda")
	operation, _ := service.Operation("CreateEventSourceMapping")
	body := []byte(`{"FunctionName":"configured","MaximumBatchingWindowInSeconds":"3","ScalingConfig":{"MaximumConcurrency":"2"},"Enabled":false}`)
	var input lambdaapi.CreateEventSourceMappingRequest
	if err := awsapi.DecodeCloudFormationInput(service, operation, body, &input); err != nil {
		t.Fatal(err)
	}
	if input.MaximumBatchingWindowInSeconds == nil || *input.MaximumBatchingWindowInSeconds != 3 || input.ScalingConfig == nil || input.ScalingConfig.MaximumConcurrency == nil || *input.ScalingConfig.MaximumConcurrency != 2 || input.Enabled == nil || bool(*input.Enabled) {
		t.Fatalf("CFN modeled scalar conversion: %+v", input)
	}
	if _, err := lambdaapi.DecodeRequest("CreateEventSourceMapping", awsapi.Request{Body: body}); err == nil {
		t.Fatal("native public API accepted a numeric string")
	}
	if err := awsapi.DecodeSDKInput(service, operation, body, &input); err == nil {
		t.Fatal("CFN numeric conversion leaked into Step Functions SDK mode")
	}
}

func TestCloudFormationScalarValidationPaths(t *testing.T) {
	service, _ := awscatalog.LookupService("lambda")
	operation, _ := service.Operation("CreateEventSourceMapping")
	for _, tt := range []struct {
		name, field, value, path string
	}{
		{"invalid", "MaximumBatchingWindowInSeconds", `"nope"`, "MaximumBatchingWindowInSeconds"},
		{"empty", "MaximumBatchingWindowInSeconds", `""`, "MaximumBatchingWindowInSeconds"},
		{"fraction string", "MaximumBatchingWindowInSeconds", `"1.5"`, "MaximumBatchingWindowInSeconds"},
		{"fraction number", "MaximumBatchingWindowInSeconds", `1.5`, "MaximumBatchingWindowInSeconds"},
		{"integer exponent", "MaximumBatchingWindowInSeconds", `"1e0"`, "MaximumBatchingWindowInSeconds"},
		{"overflow", "MaximumBatchingWindowInSeconds", `"2147483648"`, "MaximumBatchingWindowInSeconds"},
		{"below minimum", "MaximumBatchingWindowInSeconds", `"-1"`, "MaximumBatchingWindowInSeconds"},
		{"above maximum", "MaximumBatchingWindowInSeconds", `"301"`, "MaximumBatchingWindowInSeconds"},
		{"nan", "MaximumBatchingWindowInSeconds", `"NaN"`, "MaximumBatchingWindowInSeconds"},
		{"infinity", "MaximumBatchingWindowInSeconds", `"Infinity"`, "MaximumBatchingWindowInSeconds"},
		{"hexadecimal", "MaximumBatchingWindowInSeconds", `"0x10"`, "MaximumBatchingWindowInSeconds"},
		{"quoted number", "MaximumBatchingWindowInSeconds", `"\"3\""`, "MaximumBatchingWindowInSeconds"},
		{"whitespace", "MaximumBatchingWindowInSeconds", `" 3 "`, "MaximumBatchingWindowInSeconds"},
		{"boolean number", "MaximumBatchingWindowInSeconds", `true`, "MaximumBatchingWindowInSeconds"},
		{"object number", "MaximumBatchingWindowInSeconds", `{}`, "MaximumBatchingWindowInSeconds"},
		{"list number", "MaximumBatchingWindowInSeconds", `[]`, "MaximumBatchingWindowInSeconds"},
		{"nested bound", "ScalingConfig", `{"MaximumConcurrency":"1"}`, "ScalingConfig.MaximumConcurrency"},
		{"nested wrong type", "ScalingConfig", `{"MaximumConcurrency":[]}`, "ScalingConfig.MaximumConcurrency"},
		{"list scalar", "Topics", `[1]`, "Topics[0]"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(`{"FunctionName":"configured","` + tt.field + `":` + tt.value + `}`)
			var input lambdaapi.CreateEventSourceMappingRequest
			err := awsapi.DecodeCloudFormationInput(service, operation, body, &input)
			var validation *awsapi.ValidationError
			if !errors.As(err, &validation) || validation.Path != tt.path {
				t.Fatalf("error=%v; want ValidationError at %s", err, tt.path)
			}
		})
	}
	for _, value := range []string{`"false"`, `0`} {
		body := []byte(`{"FunctionName":"configured","Enabled":` + value + `}`)
		if _, err := lambdaapi.DecodeRequest("CreateEventSourceMapping", awsapi.Request{Body: body}); err == nil {
			t.Fatalf("native public API accepted boolean %s", value)
		}
	}
}

func TestCloudFormationRetainsAdapterScalarContract(t *testing.T) {
	service, _ := awscatalog.LookupService("lambda")
	operation, _ := service.Operation("CreateEventSourceMapping")
	for _, value := range []string{`"false"`, `0`, `null`} {
		var input lambdaapi.CreateEventSourceMappingRequest
		body := []byte(`{"FunctionName":"configured","Enabled":` + value + `,"Tags":null,"MaximumBatchingWindowInSeconds":null}`)
		if err := awsapi.DecodeCloudFormationInput(service, operation, body, &input); err != nil {
			t.Fatalf("existing adapter scalar contract rejected %s: %v", value, err)
		}
		if input.Enabled != nil && bool(*input.Enabled) {
			t.Fatalf("false scalar became true: %s", value)
		}
		if input.Tags != nil || input.MaximumBatchingWindowInSeconds != nil {
			t.Fatal("optional null fields were not omitted")
		}
	}
	operation, _ = service.Operation("PublishLayerVersion")
	var input lambdaapi.PublishLayerVersionRequest
	body := []byte(`{"LayerName":"layer","Content":{"ZipFile":"native text bytes"}}`)
	if err := awsapi.DecodeCloudFormationInput(service, operation, body, &input); err != nil {
		t.Fatal(err)
	}
	if input.Content == nil || string(input.Content.ZipFile) != "native text bytes" {
		t.Fatalf("CFN adapter blob bytes changed: %+v", input.Content)
	}
}

func TestCloudFormationRetainsSmithyNamesOverWireAliases(t *testing.T) {
	service, _ := awscatalog.LookupService("apigateway")
	operation, _ := service.Operation("PutIntegration")
	var input gatewayapi.PutIntegrationRequest
	body := []byte(`{"restApiId":"api","resourceId":"resource","httpMethod":"GET","integrationHttpMethod":"POST","type":"HTTP","uri":"https://example.com","timeoutInMillis":"5000"}`)
	if err := awsapi.DecodeCloudFormationInput(service, operation, body, &input); err != nil {
		t.Fatal(err)
	}
	if input.HttpMethod == nil || *input.HttpMethod != "GET" || input.IntegrationHttpMethod == nil || *input.IntegrationHttpMethod != "POST" || input.TimeoutInMillis == nil || *input.TimeoutInMillis != 5000 {
		t.Fatalf("CFN confused SDK document member names with wire aliases: %+v", input)
	}
}
