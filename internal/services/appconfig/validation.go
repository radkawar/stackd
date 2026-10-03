package appconfig

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Customer schemas are self-contained. In particular, validation must never
// resolve a customer $ref through the host filesystem or the network.
type contentSchemaLoader struct{}

func (contentSchemaLoader) Load(string) (any, error) {
	return nil, fmt.Errorf("external schema references are not supported")
}

type contentSchemaRegexp struct{ re *regexp2.Regexp }

func (r contentSchemaRegexp) String() string { return r.re.String() }
func (r contentSchemaRegexp) MatchString(value string) bool {
	matched, err := r.re.MatchString(value)
	return err == nil && matched
}

func compileContentRegexp(pattern string) (jsonschema.Regexp, error) {
	re, err := regexp2.Compile(pattern, regexp2.ECMAScript|regexp2.Unicode)
	if err != nil {
		return nil, err
	}
	return contentSchemaRegexp{re: re}, nil
}

func contentSchema(document any, draft *jsonschema.Draft) (*jsonschema.Schema, error) {
	const location = "urn:stackd:appconfig:content"
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(draft)
	compiler.UseLoader(contentSchemaLoader{})
	compiler.UseRegexpEngine(compileContentRegexp)
	if err := compiler.AddResource(location, document); err != nil {
		return nil, err
	}
	return compiler.Compile(location)
}

func (s *Service) validateContent(ctx context.Context, profile Profile, version string, content []byte) error {
	if profile.Type == "AWS.AppConfig.FeatureFlags" {
		if err := validateFeatureFlags(content); err != nil {
			return err
		}
	}
	var document any
	decoded := false
	for _, validator := range profile.Validators {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch validator.Type {
		case "JSON_SCHEMA":
			schemaDocument, err := jsonschema.UnmarshalJSON(strings.NewReader(validator.Content))
			if err == nil {
				var object map[string]any
				var ok bool
				object, ok = schemaDocument.(map[string]any)
				if !ok {
					err = fmt.Errorf("JSON Schema must be an object")
				} else {
					// Native AppConfig uses draft4 even when a customer declares a
					// later draft: const is ignored and exclusiveMinimum is boolean.
					delete(object, "$schema")
				}
			}
			var schema *jsonschema.Schema
			if err == nil {
				schema, err = contentSchema(schemaDocument, jsonschema.Draft4)
			}
			if err == nil && !decoded {
				document, err = jsonschema.UnmarshalJSON(bytes.NewReader(content))
				decoded = err == nil
			}
			if err == nil {
				err = schema.Validate(document)
			}
			if err != nil {
				return failure("BadRequestException", fmt.Sprintf("Could not build JSON schema from invalid input:\n %s.\n Original error message:\n%s", validator.Content, err))
			}
		case "LAMBDA":
			if s.effects == nil {
				return failure("BadRequestException", "Lambda validator execution is unavailable.")
			}
			if err := s.effects.ValidateLambda(ctx, profile, validator.Content, version, content); err != nil {
				return err
			}
		default:
			return failure("BadRequestException", "Unsupported validator type: "+validator.Type)
		}
	}
	return nil
}
