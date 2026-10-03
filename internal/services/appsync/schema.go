package appsync

import (
	"context"
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"github.com/vektah/gqlparser/v2/validator"
	"github.com/vektah/gqlparser/v2/validator/rules"
)

const serviceSchema = `
scalar AWSDate
scalar AWSTime
scalar AWSDateTime
scalar AWSTimestamp
scalar AWSEmail
scalar AWSJSON
scalar AWSPhone
scalar AWSURL
scalar AWSIPAddress
directive @aws_subscribe(mutations: [String!]!) on FIELD_DEFINITION
directive @aws_auth(cognito_groups: [String!]) on FIELD_DEFINITION
directive @aws_api_key on OBJECT | FIELD_DEFINITION
directive @aws_iam on OBJECT | FIELD_DEFINITION
directive @aws_oidc on OBJECT | FIELD_DEFINITION
directive @aws_cognito_user_pools(cognito_groups: [String!]) on OBJECT | FIELD_DEFINITION
directive @aws_lambda on OBJECT | FIELD_DEFINITION
`

var queryValidationRules = rules.NewDefaultRules()

type compiledSchema struct {
	source string
	schema *ast.Schema
}

func parseSchema(source string) (*ast.Schema, error) {
	schema, err := gqlparser.LoadSchema(&ast.Source{Name: "appsync", Input: serviceSchema, BuiltIn: true}, &ast.Source{Name: "schema", Input: source})
	if err != nil {
		return nil, err
	}
	if schema.Query == nil {
		return nil, fmt.Errorf("a schema must define a query root")
	}
	for name, def := range schema.Types {
		if def.BuiltIn {
			continue
		}
		if strings.HasPrefix(name, "AWS") {
			return nil, fmt.Errorf("the AWS prefix is reserved: %s", name)
		}
		if def.Kind == ast.Scalar {
			return nil, fmt.Errorf("custom scalar %s is not supported by AppSync", name)
		}
	}
	if schema.Subscription != nil {
		for _, field := range schema.Subscription.Fields {
			directive := field.Directives.ForName("aws_subscribe")
			if directive == nil {
				continue
			}
			arguments := directive.Arguments.ForName("mutations")
			if arguments == nil {
				return nil, fmt.Errorf("subscription %s must specify mutations", field.Name)
			}
			names, err := arguments.Value.Value(nil)
			if err != nil {
				return nil, err
			}
			for _, entry := range names.([]any) {
				name, _ := entry.(string)
				if schema.Mutation == nil {
					return nil, fmt.Errorf("subscription %s references missing mutation %s", field.Name, name)
				}
				mutation := schema.Mutation.Fields.ForName(name)
				if mutation == nil {
					return nil, fmt.Errorf("subscription %s references missing mutation %s", field.Name, name)
				}
				// AppSync permits the mutation to be non-null while the subscription is
				// nullable, but the actual named/list return shape must agree.
				if strings.ReplaceAll(mutation.Type.String(), "!", "") != strings.ReplaceAll(field.Type.String(), "!", "") {
					return nil, fmt.Errorf("subscription %s return type does not match mutation %s", field.Name, name)
				}
			}
		}
	}
	return schema, nil
}
func validateSchema(source string) error { _, err := parseSchema(source); return err }
func validateResolverField(source, typeName, fieldName string) error {
	schema, err := parseSchema(source)
	if err != nil {
		return err
	}
	definition := schema.Types[typeName]
	if definition == nil || definition.Fields.ForName(fieldName) == nil {
		return bad("Resolver field does not exist in the schema")
	}
	if definition.Kind != ast.Object && definition.Kind != ast.Interface {
		return bad("Resolvers require an object or interface field")
	}
	return nil
}
func (s *Service) compiled(record APIRecord) (*ast.Schema, error) {
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	cached, ok := s.schemas[record.Key.ID]
	if ok && cached.source == record.Schema {
		return cached.schema, nil
	}
	schema, err := parseSchema(record.Schema)
	if err != nil {
		return nil, err
	}
	s.schemas[record.Key.ID] = compiledSchema{source: record.Schema, schema: schema}
	return schema, nil
}

type preparedOperation struct {
	Schema    *ast.Schema
	Document  *ast.QueryDocument
	Operation *ast.OperationDefinition
	Variables map[string]any
}

func (s *Service) prepare(_ context.Context, snapshot Snapshot, request GraphQLRequest, _ Identity) (*preparedOperation, error) {
	schema, err := s.compiled(snapshot.API)
	if err != nil {
		return nil, &MappingError{Type: "BadRequestException", Message: "The GraphQL schema is unavailable"}
	}
	document, errs := gqlparser.LoadQueryWithRules(schema, request.Query, queryValidationRules)
	if len(errs) > 0 {
		return nil, errs
	}
	operation := document.Operations.ForName(request.OperationName)
	if operation == nil {
		return nil, &MappingError{Type: "ValidationError", Message: "An operation name is required for multiple operations, and must identify an operation in the document"}
	}
	variables, err := validator.VariableValues(schema, operation, request.Variables)
	if err != nil {
		return nil, err
	}
	for _, def := range operation.VariableDefinitions {
		input, ok := variables[def.Variable]
		if !ok {
			continue
		}
		_, e := coerceInput(schema, def.Type, input)
		if e != nil {
			return nil, &MappingError{Type: "ValidationError", Message: "Variable $" + def.Variable + ": " + e.Error()}
		}
	}
	p := &preparedOperation{Schema: schema, Document: document, Operation: operation, Variables: variables}
	if err := validateArguments(p, operation.SelectionSet); err != nil {
		return nil, err
	}
	depth := 0
	if snapshot.API.API.QueryDepthLimit != nil {
		depth = int(*snapshot.API.API.QueryDepthLimit)
	}
	if depth > 0 && selectionDepth(operation.SelectionSet, document, 0) > depth {
		return nil, &MappingError{Type: "QueryDepthLimitReached", Message: "Query depth limit reached"}
	}
	if value(snapshot.API.API.IntrospectionConfig) == "DISABLED" && hasIntrospection(operation.SelectionSet, document) {
		return nil, &MappingError{Type: "ValidationError", Message: "GraphQL introspection is disabled"}
	}
	return p, nil
}
func selectionDepth(selections ast.SelectionSet, document *ast.QueryDocument, current int) int {
	deepest := current
	for _, selection := range selections {
		next := current
		switch node := selection.(type) {
		case *ast.Field:
			next = selectionDepth(node.SelectionSet, document, current+1)
		case *ast.InlineFragment:
			next = selectionDepth(node.SelectionSet, document, current)
		case *ast.FragmentSpread:
			if fragment := document.Fragments.ForName(node.Name); fragment != nil {
				next = selectionDepth(fragment.SelectionSet, document, current)
			}
		}
		if next > deepest {
			deepest = next
		}
	}
	return deepest
}
func hasIntrospection(selections ast.SelectionSet, document *ast.QueryDocument) bool {
	for _, selection := range selections {
		switch node := selection.(type) {
		case *ast.Field:
			if node.Name == "__schema" || node.Name == "__type" || hasIntrospection(node.SelectionSet, document) {
				return true
			}
		case *ast.InlineFragment:
			if hasIntrospection(node.SelectionSet, document) {
				return true
			}
		case *ast.FragmentSpread:
			if fragment := document.Fragments.ForName(node.Name); fragment != nil && hasIntrospection(fragment.SelectionSet, document) {
				return true
			}
		}
	}
	return false
}
func graphQLFailure(err error) GraphQLResponse {
	var errors []GraphQLError
	switch e := err.(type) {
	case gqlerror.List:
		for _, item := range e {
			errors = append(errors, fromQueryError(item))
		}
	case *gqlerror.Error:
		errors = append(errors, fromQueryError(e))
	default:
		errors = append(errors, executionError(err, nil, nil))
	}
	return GraphQLResponse{Errors: errors}
}
func fromQueryError(err *gqlerror.Error) GraphQLError {
	out := GraphQLError{Message: err.Message, ErrorType: "ValidationError"}
	for _, v := range err.Locations {
		out.Locations = append(out.Locations, Location{Line: v.Line, Column: v.Column})
	}
	return out
}

func validateArguments(p *preparedOperation, selections ast.SelectionSet) error {
	for _, selection := range selections {
		switch node := selection.(type) {
		case *ast.Field:
			arguments := node.ArgumentMap(p.Variables)
			for _, argument := range node.Definition.Arguments {
				if value, ok := arguments[argument.Name]; ok {
					if _, err := coerceInput(p.Schema, argument.Type, value); err != nil {
						return &MappingError{Type: "ValidationError", Message: node.Name + "." + argument.Name + ": " + err.Error()}
					}
				}
			}
			if err := validateArguments(p, node.SelectionSet); err != nil {
				return err
			}
		case *ast.InlineFragment:
			if err := validateArguments(p, node.SelectionSet); err != nil {
				return err
			}
		case *ast.FragmentSpread:
			if fragment := p.Document.Fragments.ForName(node.Name); fragment != nil {
				if err := validateArguments(p, fragment.SelectionSet); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func validateSchemaAuthentication(source string, multiAuth bool) error {
	if !multiAuth {
		return nil
	}
	schema, err := parseSchema(source)
	if err != nil {
		return err
	}
	for _, definition := range schema.Types {
		for _, field := range definition.Fields {
			if field.Directives.ForName("aws_auth") != nil {
				return bad("@aws_auth cannot be used with additional authentication providers")
			}
		}
	}
	return nil
}
