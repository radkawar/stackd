package cloudwatch

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

//go:embed dashboard_body.schema.json
var dashboardBodySchemaJSON []byte

type dashboardBodyValidator struct {
	schema   *jsonschema.Schema
	warnings []string
}

var dashboardValidator = sync.OnceValues(func() (*dashboardBodyValidator, error) {
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(dashboardBodySchemaJSON))
	if err != nil {
		return nil, err
	}
	const location = "stackd://cloudwatch/dashboard-body"
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(location, document); err != nil {
		return nil, err
	}
	schema, err := compiler.Compile(location)
	if err != nil {
		return nil, err
	}
	validator := &dashboardBodyValidator{schema: schema}
	var visit func(any, string)
	visit = func(value any, path string) {
		switch value := value.(type) {
		case map[string]any:
			if value["x-warning"] == true {
				validator.warnings = append(validator.warnings, path)
			}
			for key, child := range value {
				visit(child, path+"/"+dashboardPointerPart(key))
			}
		case []any:
			for i, child := range value {
				visit(child, fmt.Sprintf("%s/%d", path, i))
			}
		}
	}
	visit(document, "")
	return validator, nil
})

type dashboardDiagnostic struct {
	Path    string `json:"dataPath"`
	Message string `json:"message"`
}

func dashboardPointerPart(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func (v *dashboardBodyValidator) warning(err *jsonschema.ValidationError) bool {
	_, path, _ := strings.Cut(err.SchemaURL, "#")
	for _, prefix := range v.warnings {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func admitDashboardBody(body string) (string, api.DashboardValidationMessages, *awswire.Error) {
	if body == "" {
		return "", nil, invalid("The parameter DashboardBody is required.")
	}
	document, err := jsonschema.UnmarshalJSON(strings.NewReader(body))
	root, object := document.(map[string]any)
	if err != nil || !object {
		return "", nil, failure("InvalidParameterInput", "The field DashboardBody must be a valid JSON object")
	}
	validator, err := dashboardValidator()
	if err != nil {
		return "", nil, storageFailure()
	}
	var failures, warnings []dashboardDiagnostic
	if err := validator.schema.Validate(document); err != nil {
		var validation *jsonschema.ValidationError
		if !errors.As(err, &validation) {
			return "", nil, storageFailure()
		}
		printer := message.NewPrinter(language.English)
		var collect func(*jsonschema.ValidationError)
		collect = func(current *jsonschema.ValidationError) {
			if len(current.Causes) != 0 {
				for _, cause := range current.Causes {
					collect(cause)
				}
				return
			}
			path := ""
			for _, part := range current.InstanceLocation {
				path += "/" + dashboardPointerPart(part)
			}
			switch kind := current.ErrorKind.(type) {
			case *kind.AdditionalProperties:
				for _, property := range kind.Properties {
					text := fmt.Sprintf("The %q property is not expected, will be ignored", property)
					if strings.HasPrefix(path, "/widgets/") {
						text = fmt.Sprintf("The %q property is not expected to be part of a widget definition, will be ignored", property)
					}
					warnings = append(warnings, dashboardDiagnostic{path, text})
				}
			default:
				diagnostic := dashboardDiagnostic{path, current.ErrorKind.LocalizedString(printer)}
				if validator.warning(current) {
					warnings = append(warnings, diagnostic)
				} else {
					failures = append(failures, diagnostic)
				}
			}
		}
		collect(validation)
	}
	failures = append(failures, dashboardBodyRelationships(root)...)
	if len(failures) != 0 {
		encoded, _ := json.MarshalIndent(failures, "", "  ")
		return "", nil, failure("InvalidParameterInput", fmt.Sprintf("The dashboard body is invalid, there are %d validation errors:\n%s", len(failures), encoded))
	}
	// Preserve unknown properties and Unicode, rather than treating an admission
	// warning as permission to discard customer configuration.
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return "", nil, storageFailure()
	}
	slices.SortFunc(warnings, func(a, b dashboardDiagnostic) int {
		if order := strings.Compare(a.Path, b.Path); order != 0 {
			return order
		}
		return strings.Compare(a.Message, b.Message)
	})
	out := make(api.DashboardValidationMessages, 0, len(warnings))
	for _, warning := range warnings {
		out = append(out, api.DashboardValidationMessage{DataPath: new(api.DataPath(warning.Path)), Message: new(api.Message(warning.Message))})
	}
	return strings.TrimSuffix(encoded.String(), "\n"), out, nil
}

// These relationships depend on sibling values rather than independent shape
// constraints. Neither check resolves resources or executes customer queries.
func dashboardBodyRelationships(root map[string]any) []dashboardDiagnostic {
	var failures []dashboardDiagnostic
	variables, _ := root["variables"].([]any)
	properties := make(map[string]bool)
	for i, value := range variables {
		variable, _ := value.(map[string]any)
		if variable["type"] != "property" {
			continue
		}
		property, _ := variable["property"].(string)
		if property == "" {
			continue
		}
		if properties[property] {
			failures = append(failures, dashboardDiagnostic{fmt.Sprintf("/variables/%d/property", i), fmt.Sprintf("Duplicated property in variable: %q", property)})
		}
		properties[property] = true
	}
	widgets, _ := root["widgets"].([]any)
	for widgetIndex, value := range widgets {
		widget, _ := value.(map[string]any)
		if widget["type"] != "metric" {
			continue
		}
		properties, _ := widget["properties"].(map[string]any)
		metrics, _ := properties["metrics"].([]any)
		for metricIndex, value := range metrics {
			row, ok := value.([]any)
			if !ok {
				continue // the shape validator owns non-array rows
			}
			for i, member := range row {
				if _, object := member.(map[string]any); object && i != len(row)-1 {
					failures = append(failures, dashboardDiagnostic{fmt.Sprintf("/widgets/%d/properties/metrics/%d/%d", widgetIndex, metricIndex, i), "Metric rendering properties must be the last element of the metric row"})
				}
			}
		}
	}
	return failures
}
