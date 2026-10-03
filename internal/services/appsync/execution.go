package appsync

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/awswire"
)

type GraphQLRequest struct {
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables"`
	OperationName string         `json:"operationName"`
}
type Location struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}
type GraphQLError struct {
	Message   string     `json:"message"`
	ErrorType string     `json:"errorType,omitempty"`
	Path      []any      `json:"path,omitempty"`
	Locations []Location `json:"locations,omitempty"`
	Data      any        `json:"data,omitempty"`
}
type GraphQLResponse struct {
	Data   map[string]any `json:"data"`
	Errors []GraphQLError `json:"errors,omitempty"`
}
type MappingError struct {
	Message, Type string
	Data          any
}

func (e *MappingError) Error() string { return e.Message }

type EarlyReturn struct {
	Value  any
	SkipTo string
}

func (e *EarlyReturn) Error() string { return "Resolver returned early" }

type execution struct {
	service       *Service
	snapshot      Snapshot
	prepared      *preparedOperation
	identity      Identity
	errors        []GraphQLError
	calls         int
	projectOnly   bool
	introspecting bool
}

func (s *Service) execute(ctx context.Context, snapshot Snapshot, request GraphQLRequest, identity Identity) GraphQLResponse {
	p, err := s.prepare(ctx, snapshot, request, identity)
	if err != nil {
		return graphQLFailure(err)
	}
	if p.Operation.Operation == ast.Subscription {
		return graphQLFailure(&MappingError{Type: "BadRequestException", Message: "Subscriptions require the real-time WebSocket endpoint"})
	}
	root := p.Schema.Query
	if p.Operation.Operation == ast.Mutation {
		root = p.Schema.Mutation
	}
	if root == nil {
		return graphQLFailure(&MappingError{Type: "ValidationError", Message: "Schema has no root for this operation"})
	}
	e := &execution{service: s, snapshot: snapshot, prepared: p, identity: identity}
	out := make(map[string]any)
	// Mutation root fields run serially. Publication occurs after each completed
	// field, including when a later independent mutation field fails.
	for _, field := range collectFields(p, root, p.Operation.SelectionSet) {
		path := []any{field.Alias}
		result, canonical, bubble := e.field(ctx, root, nil, field, path)
		if bubble {
			out = nil
			break
		}
		out[field.Alias] = result
		if p.Operation.Operation == ast.Mutation && canonical != nil {
			s.realtime.Publish(ctx, snapshot.API.Key.ID, field.Name, canonical)
		}
	}
	return GraphQLResponse{Data: out, Errors: e.errors}
}
func (e *execution) field(ctx context.Context, parent *ast.Definition, source any, field *ast.Field, path []any) (any, any, bool) {
	if err := ctx.Err(); err != nil {
		e.add(err, path, field)
		return nil, nil, field.Definition.Type.NonNull
	}
	if field.Name == "__typename" {
		return parent.Name, parent.Name, false
	}
	if !e.introspecting && !strings.HasPrefix(parent.Name, "__") {
		if err := e.service.checkFieldAuth(ctx, e.identity, e.snapshot.API, parent, field.Definition); err != nil {
			e.add(err, path, field)
			return nil, nil, field.Definition.Type.NonNull
		}
	}
	args := field.ArgumentMap(e.prepared.Variables)
	for _, arg := range field.Definition.Arguments {
		input, ok := args[arg.Name]
		if !ok {
			continue
		}
		v, err := coerceInput(e.prepared.Schema, arg.Type, input)
		if err != nil {
			e.add(&MappingError{Type: "ValidationError", Message: err.Error()}, path, field)
			return nil, nil, field.Definition.Type.NonNull
		}
		args[arg.Name] = v
	}
	var result any
	var err error
	switch {
	case field.Name == "__schema":
		result = introspectionSchema{schema: e.prepared.Schema}
	case field.Name == "__type":
		name, _ := args["name"].(string)
		if def := e.prepared.Schema.Types[name]; def != nil {
			result = introspectionType{schema: e.prepared.Schema, typ: ast.NamedType(def.Name, nil)}
		}
	case strings.HasPrefix(parent.Name, "__"):
		result, err = introspectionField(source, field.Name, args)
	default:
		if resolver, ok := e.snapshot.Resolvers[parent.Name+"."+field.Name]; ok && !e.projectOnly {
			e.calls++
			limit := 10000
			if e.snapshot.API.API.ResolverCountLimit != nil && *e.snapshot.API.API.ResolverCountLimit > 0 {
				limit = int(*e.snapshot.API.API.ResolverCountLimit)
			}
			if e.calls > limit {
				err = &MappingError{Type: "ResolverExecutionLimitReached", Message: "Resolver execution limit reached"}
			} else {
				result, err = e.resolve(ctx, resolver, source, args, parent, field, path)
			}
		} else if fields, ok := source.(map[string]any); ok {
			result = fields[field.Name]
		}
	}
	if err != nil {
		e.add(err, path, field)
		return nil, nil, field.Definition.Type.NonNull
	}
	return e.complete(ctx, field.Definition.Type, result, field.SelectionSet, path, field)
}
func (e *execution) complete(ctx context.Context, typ *ast.Type, result any, selections ast.SelectionSet, path []any, field *ast.Field) (any, any, bool) {
	if result == nil {
		if typ.NonNull {
			e.add(&MappingError{Type: "MappingTemplate", Message: fmt.Sprintf("Cannot return null for non-nullable type: '%s' within parent '%s' (/ %s)", typ.String(), field.ObjectDefinition.Name, field.Name)}, path, field)
		}
		return nil, nil, typ.NonNull
	}
	if typ.Elem != nil {
		list := reflect.ValueOf(result)
		if list.Kind() != reflect.Slice && list.Kind() != reflect.Array {
			e.add(&MappingError{Type: "MappingTemplate", Message: "Expected a list for " + typ.String()}, path, field)
			return nil, nil, typ.NonNull
		}
		out := make([]any, list.Len())
		canonical := make([]any, list.Len())
		for i := range list.Len() {
			itemPath := appendPath(path, i)
			v, c, bubble := e.complete(ctx, typ.Elem, list.Index(i).Interface(), selections, itemPath, field)
			if bubble {
				return nil, nil, typ.NonNull
			}
			out[i], canonical[i] = v, c
		}
		return out, canonical, false
	}
	definition := e.prepared.Schema.Types[typ.NamedType]
	if definition.Kind == ast.Scalar || definition.Kind == ast.Enum {
		v, err := serializeScalar(definition, result)
		if err != nil {
			e.add(&MappingError{Type: "MappingTemplate", Message: err.Error()}, path, field)
			return nil, nil, typ.NonNull
		}
		if definition.Name == "AWSJSON" {
			return v, result, false
		}
		return v, v, false
	}
	if definition.Kind == ast.Interface || definition.Kind == ast.Union {
		values, ok := result.(map[string]any)
		runtimeName, _ := values["__typename"].(string)
		runtimeType := e.prepared.Schema.Types[runtimeName]
		if !ok || runtimeType == nil || !typeMatches(e.prepared.Schema, runtimeName, definition.Name) {
			e.add(&MappingError{Type: "MappingTemplate", Message: "An abstract result must provide a valid __typename"}, path, field)
			return nil, nil, typ.NonNull
		}
		definition = runtimeType
	}
	out := map[string]any{}
	canonical := map[string]any{}
	for _, child := range collectFields(e.prepared, definition, selections) {
		v, c, bubble := e.field(ctx, definition, result, child, appendPath(path, child.Alias))
		if bubble {
			return nil, nil, typ.NonNull
		}
		out[child.Alias] = v
		if before, ok := canonical[child.Name].(map[string]any); ok {
			if after, ok := c.(map[string]any); ok {
				for k, v := range after {
					before[k] = v
				}
				continue
			}
		}
		canonical[child.Name] = c
	}
	return out, canonical, false
}
func (e *execution) resolve(ctx context.Context, resolver api.Resolver, source any, args map[string]any, parent *ast.Definition, field *ast.Field, path []any) (any, error) {
	request, _ := ctx.Value(resolverRequestKey{}).(map[string]any)
	if request == nil {
		request = map[string]any{"headers": map[string]any{}, "domainName": nil}
	}
	state := map[string]any{"arguments": args, "args": args, "source": source, "identity": identityContext(e.identity), "stash": map[string]any{}, "prev": map[string]any{}, "info": map[string]any{"fieldName": field.Name, "parentTypeName": parent.Name, "variables": e.prepared.Variables, "selectionSetList": selectionNames(e.prepared, field.SelectionSet, "")}, "request": request, "__now": e.service.clock.Now()}
	defer func() {
		if appended, ok := state["__errors"].([]MappingError); ok {
			for i := range appended {
				e.add(&appended[i], path, field)
			}
		}
	}()
	code := value(resolver.Code)
	if value(resolver.Kind) != "PIPELINE" {
		result, err := e.unit(ctx, code, value(resolver.DataSourceName), state)
		var early *EarlyReturn
		if errors.As(err, &early) {
			return early.Value, nil
		}
		return result, err
	}
	initial, err := runMapping(ctx, code, "request", state)
	var early *EarlyReturn
	if errors.As(err, &early) {
		state["prev"] = map[string]any{"result": early.Value}
		state["result"] = early.Value
		return runMapping(ctx, code, "response", state)
	}
	if err != nil {
		return nil, err
	}
	state["prev"] = map[string]any{"result": initial}
	if resolver.PipelineConfig == nil {
		return nil, &MappingError{Type: "MappingTemplate", Message: "Pipeline functions are missing"}
	}
	for _, id := range resolver.PipelineConfig.Functions {
		fn, ok := e.snapshot.Functions[string(id)]
		if !ok {
			return nil, &MappingError{Type: "MappingTemplate", Message: "Pipeline function does not exist"}
		}
		result, err := e.unit(ctx, value(fn.Code), value(fn.DataSourceName), state)
		if errors.As(err, &early) {
			result, err = early.Value, nil
			if early.SkipTo == "END" {
				state["prev"] = map[string]any{"result": result}
				state["result"] = result
				break
			}
		}
		if err != nil {
			return nil, err
		}
		state["prev"] = map[string]any{"result": result}
		state["result"] = result
	}
	delete(state, "error")
	return runMapping(ctx, code, "response", state)
}
func (e *execution) unit(ctx context.Context, code, sourceName string, state map[string]any) (any, error) {
	dataSource, ok := e.snapshot.DataSources[sourceName]
	if !ok {
		return nil, &MappingError{Type: "DataSourceNotFound", Message: "Data source does not exist"}
	}
	var request map[string]any
	if code == "" {
		if value(dataSource.Type) != "AWS_LAMBDA" {
			return nil, &MappingError{Type: "MappingTemplate", Message: "A resolver mapping is required"}
		}
		payload := make(map[string]any, len(state))
		for k, v := range state {
			if !strings.HasPrefix(k, "__") {
				payload[k] = v
			}
		}
		request = map[string]any{"operation": "Invoke", "payload": payload}
	} else {
		value, err := runMapping(ctx, code, "request", state)
		if err != nil {
			return nil, err
		}
		var ok bool
		request, ok = value.(map[string]any)
		if !ok {
			return nil, &MappingError{Type: "MappingTemplate", Message: "Request handler must return an object"}
		}
	}
	var result any
	var err error
	if value(dataSource.Type) == "NONE" {
		result = request["payload"]
	} else if e.service.sources == nil {
		err = &MappingError{Type: "DataSourceError", Message: "Data source execution is unavailable"}
	} else {
		result, err = e.service.sources.Execute(ctx, e.snapshot.API, dataSource, request)
	}
	state["result"] = result
	delete(state, "error")
	if err != nil {
		mapped := executionError(err, nil, nil)
		state["error"] = map[string]any{"message": mapped.Message, "type": mapped.ErrorType}
	}
	if code == "" {
		return result, err
	}
	return runMapping(ctx, code, "response", state)
}
func (e *execution) add(err error, path []any, field *ast.Field) {
	e.errors = append(e.errors, executionError(err, path, field))
}
func executionError(err error, path []any, field *ast.Field) GraphQLError {
	result := GraphQLError{Message: err.Error(), ErrorType: "MappingTemplate", Path: path}
	var mapping *MappingError
	if errors.As(err, &mapping) {
		result.ErrorType = mapping.Type
		result.Data = mapping.Data
	}
	var wire *awswire.Error
	if errors.As(err, &wire) {
		result.ErrorType = wire.Code
	}
	if field != nil && field.Position != nil {
		result.Locations = []Location{{Line: field.Position.Line, Column: field.Position.Column}}
	}
	return result
}
func appendPath(path []any, next any) []any {
	out := make([]any, len(path)+1)
	copy(out, path)
	out[len(path)] = next
	return out
}
func included(directives ast.DirectiveList, variables map[string]any) bool {
	for _, directive := range directives {
		if directive.Name != "skip" && directive.Name != "include" {
			continue
		}
		argument := directive.Arguments.ForName("if")
		if argument == nil {
			continue
		}
		value, _ := argument.Value.Value(variables)
		condition, _ := value.(bool)
		if directive.Name == "skip" && condition || directive.Name == "include" && !condition {
			return false
		}
	}
	return true
}
func typeMatches(schema *ast.Schema, runtime, condition string) bool {
	if condition == "" || runtime == condition {
		return true
	}
	for _, candidate := range schema.PossibleTypes[condition] {
		if candidate.Name == runtime {
			return true
		}
	}
	return false
}
func collectFields(p *preparedOperation, parent *ast.Definition, selections ast.SelectionSet) []*ast.Field {
	var fields []*ast.Field
	byAlias := map[string]int{}
	var visit func(ast.SelectionSet)
	visit = func(set ast.SelectionSet) {
		for _, selection := range set {
			switch node := selection.(type) {
			case *ast.Field:
				if !included(node.Directives, p.Variables) {
					continue
				}
				if index, ok := byAlias[node.Alias]; ok {
					old := fields[index]
					merged := *old
					merged.SelectionSet = append(append(ast.SelectionSet(nil), old.SelectionSet...), node.SelectionSet...)
					fields[index] = &merged
				} else {
					byAlias[node.Alias] = len(fields)
					fields = append(fields, node)
				}
			case *ast.InlineFragment:
				if included(node.Directives, p.Variables) && typeMatches(p.Schema, parent.Name, node.TypeCondition) {
					visit(node.SelectionSet)
				}
			case *ast.FragmentSpread:
				if included(node.Directives, p.Variables) {
					if fragment := p.Document.Fragments.ForName(node.Name); fragment != nil && typeMatches(p.Schema, parent.Name, fragment.TypeCondition) {
						visit(fragment.SelectionSet)
					}
				}
			}
		}
	}
	visit(selections)
	return fields
}

// TODO: Comeback: add selectionSetGraphQL and native non-enumerable info fields.
func selectionNames(p *preparedOperation, selections ast.SelectionSet, prefix string) []string {
	var names []string
	for _, selection := range selections {
		switch node := selection.(type) {
		case *ast.Field:
			if included(node.Directives, p.Variables) {
				name := prefix + node.Alias
				names = append(names, name)
				names = append(names, selectionNames(p, node.SelectionSet, name+"/")...)
			}
		case *ast.InlineFragment:
			names = append(names, selectionNames(p, node.SelectionSet, prefix)...)
		case *ast.FragmentSpread:
			if fragment := p.Document.Fragments.ForName(node.Name); fragment != nil {
				names = append(names, selectionNames(p, fragment.SelectionSet, prefix)...)
			}
		}
	}
	return names
}
