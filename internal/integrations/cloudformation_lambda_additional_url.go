package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

type cfnLambdaURL struct{ commands StepFunctionsCommands }

type cfnLambdaURLProperties struct {
	TargetFunctionArn string
	Qualifier         *api.FunctionUrlQualifier
	AuthType          *api.FunctionUrlAuthType
	InvokeMode        *api.InvokeMode
	Cors              *cfnLambdaURLCors
}

type cfnLambdaURLCors struct {
	AllowCredentials *cfnMessagingBool
	AllowHeaders     api.HeadersList
	AllowMethods     api.AllowMethodsList
	AllowOrigins     api.AllowOriginsList
	ExposeHeaders    api.HeadersList
	MaxAge           *cfnMessagingInt
}

func cfnLambdaURLStrings[T ~string](name string, values []T, maxItems, maxLength int) error {
	if values == nil {
		return nil
	}
	if len(values) < 1 || len(values) > maxItems {
		return fmt.Errorf("%s requires between 1 and %d entries", name, maxItems)
	}
	for _, value := range values {
		if len(value) < 1 || len(value) > maxLength {
			return fmt.Errorf("%s entries must be between 1 and %d characters", name, maxLength)
		}
	}
	return nil
}

func (c *cfnLambdaURLCors) input() (*api.Cors, error) {
	if c == nil {
		return nil, nil
	}
	if err := cfnLambdaURLStrings("AllowHeaders", c.AllowHeaders, 100, 1024); err != nil {
		return nil, err
	}
	if err := cfnLambdaURLStrings("AllowOrigins", c.AllowOrigins, 100, 253); err != nil {
		return nil, err
	}
	if err := cfnLambdaURLStrings("ExposeHeaders", c.ExposeHeaders, 100, 1024); err != nil {
		return nil, err
	}
	if err := cfnLambdaURLStrings("AllowMethods", c.AllowMethods, 6, 6); err != nil {
		return nil, err
	}
	for _, method := range c.AllowMethods {
		switch method {
		case "GET", "PUT", "HEAD", "POST", "PATCH", "DELETE", "*":
		default:
			return nil, fmt.Errorf("invalid CORS AllowMethods entry %s", method)
		}
	}
	out := &api.Cors{AllowHeaders: c.AllowHeaders, AllowMethods: c.AllowMethods, AllowOrigins: c.AllowOrigins, ExposeHeaders: c.ExposeHeaders}
	if c.AllowCredentials != nil {
		out.AllowCredentials = new(api.AllowCredentials(*c.AllowCredentials))
	}
	if c.MaxAge != nil {
		if *c.MaxAge < 0 || *c.MaxAge > 86400 {
			return nil, fmt.Errorf("Cors.MaxAge must be between 0 and 86400")
		}
		out.MaxAge = new(api.MaxAge(*c.MaxAge))
	}
	return out, nil
}

func cfnLambdaURLInput(p cloudformation.Properties) (*api.CreateFunctionUrlConfigInput, error) {
	var properties cfnLambdaURLProperties
	if err := cfnMessagingDecode(p, &properties); err != nil {
		return nil, err
	}
	if properties.TargetFunctionArn == "" || properties.AuthType == nil {
		return nil, fmt.Errorf("TargetFunctionArn and AuthType are required")
	}
	if value := cfnComputeValue(properties.AuthType); value != "NONE" && value != "AWS_IAM" {
		return nil, fmt.Errorf("AuthType must be NONE or AWS_IAM")
	}
	if properties.InvokeMode != nil && *properties.InvokeMode != "BUFFERED" && *properties.InvokeMode != "RESPONSE_STREAM" {
		return nil, fmt.Errorf("InvokeMode must be BUFFERED or RESPONSE_STREAM")
	}
	if properties.InvokeMode == nil {
		properties.InvokeMode = new(api.InvokeMode("BUFFERED"))
	}
	cors, err := properties.Cors.input()
	if err != nil {
		return nil, err
	}
	return &api.CreateFunctionUrlConfigInput{FunctionName: new(api.FunctionUrlFunctionName(properties.TargetFunctionArn)), Qualifier: properties.Qualifier, AuthType: properties.AuthType, InvokeMode: properties.InvokeMode, Cors: cors}, nil
}
func (h cfnLambdaURL) Validate(p cloudformation.Properties) error {
	_, err := cfnLambdaURLInput(p)
	return err
}
func (h cfnLambdaURL) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "TargetFunctionArn", "Qualifier"), h.Validate(b)
}
func cfnLambdaURLResult(function, url string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: function, Ref: function, Attributes: map[string]any{"FunctionArn": function, "FunctionUrl": url}}
}
func (h cfnLambdaURL) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	in, err := cfnLambdaURLInput(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	function, qualifier, err := cfnLambdaAdditionalIdentity(r, "TargetFunctionArn")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in.FunctionName = new(api.FunctionUrlFunctionName(function))
	if qualifier != "" {
		in.Qualifier = new(api.FunctionUrlQualifier(qualifier))
	}
	out, err := cfnMessagingCall[api.CreateFunctionUrlConfigOutput](cfnLambdaAdditionalContext(ctx, r, true), h.commands, "lambda", "CreateFunctionUrlConfig", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaURLResult(cfnComputeValue(out.FunctionArn), cfnComputeValue(out.FunctionUrl)), nil
}
func (h cfnLambdaURL) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	properties, err := cfnLambdaURLInput(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	function, qualifier, err := cfnLambdaAdditionalIdentity(r, "TargetFunctionArn")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in := &api.UpdateFunctionUrlConfigInput{FunctionName: new(api.FunctionUrlFunctionName(function)), AuthType: properties.AuthType, InvokeMode: properties.InvokeMode, Cors: properties.Cors}
	if qualifier != "" {
		in.Qualifier = new(api.FunctionUrlQualifier(qualifier))
	}
	if in.Cors == nil {
		in.Cors = &api.Cors{}
	}
	out, err := cfnMessagingCall[api.UpdateFunctionUrlConfigOutput](cfnLambdaAdditionalContext(ctx, r, false), h.commands, "lambda", "UpdateFunctionUrlConfig", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaURLResult(cfnComputeValue(out.FunctionArn), cfnComputeValue(out.FunctionUrl)), nil
}
func (h cfnLambdaURL) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	function, qualifier, err := cfnLambdaAdditionalIdentity(r, "TargetFunctionArn")
	if err != nil {
		return err
	}
	in := &api.DeleteFunctionUrlConfigInput{FunctionName: new(api.FunctionUrlFunctionName(function))}
	if qualifier != "" {
		in.Qualifier = new(api.FunctionUrlQualifier(qualifier))
	}
	return cfnComputeAbsent(cfnMessagingExec(cfnLambdaAdditionalContext(ctx, r, false), h.commands, "lambda", "DeleteFunctionUrlConfig", in))
}
func cfnLambdaURLModel(out *api.FunctionUrlConfig) (cloudformation.Properties, error) {
	properties, err := cfnLambdaAdditionalProperties(out)
	if err != nil {
		return nil, err
	}
	function, qualifier, err := cfnLambdaAdditionalIdentity(cloudformation.ResourceRequest{PhysicalID: cfnComputeValue(out.FunctionArn)}, "TargetFunctionArn")
	if err != nil {
		return nil, err
	}
	properties["TargetFunctionArn"] = function
	if qualifier != "" {
		properties["Qualifier"] = qualifier
	}
	delete(properties, "CreationTime")
	delete(properties, "LastModifiedTime")
	return properties, nil
}
func (h cfnLambdaURL) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	function, qualifier, err := cfnLambdaAdditionalIdentity(r, "TargetFunctionArn")
	if err != nil {
		return nil, err
	}
	in := &api.GetFunctionUrlConfigInput{FunctionName: new(api.FunctionUrlFunctionName(function))}
	if qualifier != "" {
		in.Qualifier = new(api.FunctionUrlQualifier(qualifier))
	}
	out, err := cfnMessagingCall[api.GetFunctionUrlConfigOutput](cfnLambdaAdditionalContext(ctx, r, false), h.commands, "lambda", "GetFunctionUrlConfig", in)
	if err != nil {
		return nil, err
	}
	config := api.FunctionUrlConfig(*out)
	return cfnLambdaURLModel(&config)
}
func (h cfnLambdaURL) listFunction(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	function := cfnComputeString(r.Properties, "TargetFunctionArn")
	if function == "" {
		return nil, fmt.Errorf("TargetFunctionArn is required for URL listing")
	}
	in := &api.ListFunctionUrlConfigsInput{FunctionName: new(api.FunctionUrlFunctionName(function))}
	rows := []cloudformation.ResourceDescription{}
	for {
		out, err := cfnMessagingCall[api.ListFunctionUrlConfigsOutput](ctx, h.commands, "lambda", "ListFunctionUrlConfigs", in)
		if err != nil {
			return nil, err
		}
		for _, config := range out.FunctionUrlConfigs {
			properties, err := cfnLambdaURLModel(&config)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: cfnComputeValue(config.FunctionArn), Properties: properties})
		}
		if cfnComputeValue(out.NextMarker) == "" {
			return rows, nil
		}
		in.Marker = out.NextMarker
	}
}

func (h cfnLambdaURL) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	if _, err := cfnLambdaRequiredListFilter(r, "TargetFunctionArn"); err != nil {
		return nil, err
	}
	return h.listFunction(ctx, r)
}
