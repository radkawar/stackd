package appsync

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/formatter"
	api "stackd/internal/awsapi/appsync"
)

var introspectionTypeSelection = "kind name " + strings.Repeat("ofType { kind name ", 7) + strings.Repeat("}", 7)

func registerSchemaExport(s *Service) {
	register(s, "GetIntrospectionSchema", s.getIntrospectionSchema)
}
func (s *Service) getIntrospectionSchema(ctx context.Context, tx Transaction, in *api.GetIntrospectionSchemaInput) (*api.GetIntrospectionSchemaOutput, error) {
	record, err := s.load(ctx, tx, value(in.ApiId), "GetIntrospectionSchema")
	if err != nil {
		return nil, err
	}
	schema, err := s.compiled(record)
	if err != nil {
		return nil, bad("Schema is not available")
	}
	var data []byte
	switch value(in.Format) {
	case "SDL":
		var buffer bytes.Buffer
		options := []formatter.FormatterOption{}
		if boolValue(in.IncludeDirectives) {
			options = append(options, formatter.WithNonIntrospectionBuiltin())
		}
		formatter.NewFormatter(&buffer, options...).FormatSchema(schema)
		data = buffer.Bytes()
	case "JSON":
		input := "name description type {" + introspectionTypeSelection + "} defaultValue"
		fields := "fields(includeDeprecated:true) {name description args {" + input + "} type {" + introspectionTypeSelection + "} isDeprecated deprecationReason}"
		selection := "query { __schema { queryType{name} mutationType{name} subscriptionType{name} types{kind name description " + fields + " inputFields{" + input + "} interfaces{" + introspectionTypeSelection + "} enumValues(includeDeprecated:true){name description isDeprecated deprecationReason} possibleTypes{" + introspectionTypeSelection + "}}"
		if boolValue(in.IncludeDirectives) {
			selection += " directives{name description locations args{" + input + "}}"
		}
		selection += "} }"
		document, errs := gqlparser.LoadQueryWithRules(schema, selection, queryValidationRules)
		if len(errs) > 0 {
			return nil, errs
		}
		prepared := &preparedOperation{Schema: schema, Document: document, Operation: document.Operations[0], Variables: map[string]any{}}
		execution := &execution{prepared: prepared, projectOnly: true, introspecting: true}
		response := GraphQLResponse{Data: map[string]any{}}
		for _, field := range collectFields(prepared, schema.Query, prepared.Operation.SelectionSet) {
			result, _, _ := execution.field(ctx, schema.Query, nil, field, []any{field.Alias})
			response.Data[field.Alias] = result
		}
		response.Errors = execution.errors
		data, err = json.Marshal(response)
		if err != nil {
			return nil, err
		}
	default:
		return nil, bad("format must be SDL or JSON")
	}
	return &api.GetIntrospectionSchemaOutput{Schema: api.Blob(data)}, nil
}
