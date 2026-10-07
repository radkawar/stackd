package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/services/apigateway"
	"strings"
)

func cfnRESTImportValidation(p map[string]any) error {
	if p["Body"] != nil {
		if _, ok := cfnComputeObject(p["Body"]); !ok {
			return fmt.Errorf("body must be a Swagger object")
		}
	}
	if _, err := cfnComputeStringList(p, "BinaryMediaTypes"); err != nil {
		return err
	}
	if err := cfnRESTBools(p, "FailOnWarnings"); err != nil {
		return err
	}
	if mode := p["Mode"]; mode != nil && mode != "merge" && mode != "overwrite" {
		return fmt.Errorf("mode must be merge or overwrite")
	}
	if err := cfnRESTStringMap(p, "Parameters"); err != nil {
		return err
	}
	if parameters, ok := cfnComputeObject(p["Parameters"]); ok {
		for key, value := range parameters {
			if key != "endpointConfigurationTypes" || value != "REGIONAL" {
				return fmt.Errorf("unsupported import parameter %s", key)
			}
		}
	}
	if p["Body"] == nil && (p["Mode"] != nil || p["FailOnWarnings"] != nil || p["Parameters"] != nil) {
		return fmt.Errorf("import options require Body")
	}
	return nil
}
func cfnRESTImportContext(ctx context.Context, input map[string]any, patches []any, p map[string]any) (context.Context, error) {
	configuration := apigateway.ImportConfiguration{}
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return ctx, err
		}
		configuration.Create = &api.CreateRestApiRequest{}
		if err := json.Unmarshal(data, configuration.Create); err != nil {
			return ctx, err
		}
	}
	if patches != nil {
		data, err := json.Marshal(patches)
		if err != nil {
			return ctx, err
		}
		if err := json.Unmarshal(data, &configuration.Patches); err != nil {
			return ctx, err
		}
	}
	types, err := cfnComputeStringList(p, "BinaryMediaTypes")
	if err != nil {
		return ctx, err
	}
	configuration.BinaryMediaTypes = types
	configuration.PreserveBinaryMediaTypes = p["Body"] != nil && p["Mode"] == nil
	if configuration.Create != nil {
		if p["Name"] == nil {
			configuration.Create.Name = nil
		}
		if p["Description"] == nil {
			configuration.Create.Description = nil
		}
		if p["Version"] == nil {
			configuration.Create.Version = nil
		}
	}
	return apigateway.WithImportConfiguration(ctx, configuration), nil
}
func cfnRESTBinaryPatches(current, p map[string]any) []any {
	var patches []any
	previous, _ := cfnComputeStringList(current, "BinaryMediaTypes")
	for _, media := range previous {
		path := strings.ReplaceAll(strings.ReplaceAll(media, "~", "~0"), "/", "~1")
		patches = append(patches, cfnRESTPatch("remove", "/binaryMediaTypes/"+path, nil))
	}
	types, _ := cfnComputeStringList(p, "BinaryMediaTypes")
	if p["Body"] != nil && p["Mode"] != "overwrite" {
		types = append(types, previous...)
	}
	if body, ok := cfnComputeObject(p["Body"]); ok {
		extensions, _ := cfnComputeStringList(body, "x-amazon-apigateway-binary-media-types")
		types = append(types, extensions...)
	}
	for _, media := range types {
		path := strings.ReplaceAll(strings.ReplaceAll(media, "~", "~0"), "/", "~1")
		patches = append(patches, cfnRESTPatch("add", "/binaryMediaTypes/"+path, nil))
	}
	return patches
}
func cfnRESTImportMetadata(p map[string]any, property, field string, fallback any) any {
	if value, ok := p[property]; ok {
		return value
	}
	if body, ok := cfnComputeObject(p["Body"]); ok {
		if info, ok := cfnComputeObject(body["info"]); ok {
			if value, ok := info[field]; ok {
				return value
			}
		}
	}
	return fallback
}
