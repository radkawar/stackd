package appsync

import (
	"context"
	"fmt"
	"reflect"

	"github.com/vektah/gqlparser/v2/ast"
)

func (s *Service) subscriptionStart(ctx context.Context, snapshot Snapshot, request GraphQLRequest, identity Identity) (*preparedOperation, error) {
	p, err := s.prepare(ctx, snapshot, request, identity)
	if err != nil {
		return nil, err
	}
	if p.Operation.Operation != ast.Subscription || p.Schema.Subscription == nil {
		return nil, &MappingError{Type: "ValidationError", Message: "A subscription operation is required"}
	}
	fields := collectFields(p, p.Schema.Subscription, p.Operation.SelectionSet)
	if len(fields) != 1 {
		return nil, &MappingError{Type: "ValidationError", Message: "A subscription must select exactly one root field"}
	}
	field := fields[0]
	if err := s.checkFieldAuth(ctx, identity, snapshot.API, p.Schema.Subscription, field.Definition); err != nil {
		return nil, err
	}
	if field.Definition.Directives.ForName("aws_subscribe") == nil {
		return nil, &MappingError{Type: "ValidationError", Message: "Subscription field is not linked to a mutation"}
	}
	if resolver, ok := snapshot.Resolvers[p.Schema.Subscription.Name+"."+field.Name]; ok {
		e := &execution{service: s, snapshot: snapshot, prepared: p, identity: identity}
		arguments := field.ArgumentMap(p.Variables)
		for _, arg := range field.Definition.Arguments {
			if input, ok := arguments[arg.Name]; ok {
				arguments[arg.Name], err = coerceInput(p.Schema, arg.Type, input)
				if err != nil {
					return nil, err
				}
			}
		}
		if _, err = e.resolve(ctx, resolver, nil, arguments, p.Schema.Subscription, field, []any{field.Alias}); err != nil {
			return nil, err
		}
		if len(e.errors) > 0 {
			return nil, &MappingError{Type: e.errors[0].ErrorType, Message: e.errors[0].Message}
		}
	}
	return p, nil
}
func (s *Service) subscriptionEvent(ctx context.Context, snapshot Snapshot, p *preparedOperation, identity Identity, mutationName string, payload any) (GraphQLResponse, bool) {
	// A control-plane schema change is authoritative for existing subscriptions.
	// Revalidation uses the original document and variables, not a stale field
	// capability captured when the client registered.
	current, err := s.compiled(snapshot.API)
	if err != nil {
		return graphQLFailure(err), true
	}
	if current != p.Schema {
		return graphQLFailure(&MappingError{Type: "ValidationError", Message: "Subscription schema has changed; subscribe again"}), true
	}
	fields := collectFields(p, p.Schema.Subscription, p.Operation.SelectionSet)
	if len(fields) != 1 {
		return graphQLFailure(fmt.Errorf("subscription root no longer exists")), true
	}
	field := fields[0]
	directive := field.Definition.Directives.ForName("aws_subscribe")
	if directive == nil {
		return GraphQLResponse{}, false
	}
	names, err := directive.Arguments.ForName("mutations").Value.Value(nil)
	if err != nil {
		return graphQLFailure(err), true
	}
	linked := false
	for _, name := range names.([]any) {
		if name == mutationName {
			linked = true
			break
		}
	}
	if !linked {
		return GraphQLResponse{}, false
	}
	object, _ := payload.(map[string]any)
	for name, expected := range field.ArgumentMap(p.Variables) {
		actual := object[name]
		if !subscriptionEqual(actual, expected) {
			return GraphQLResponse{}, false
		}
	}
	if err := s.checkFieldAuth(ctx, identity, snapshot.API, p.Schema.Subscription, field.Definition); err != nil {
		return graphQLFailure(err), true
	}
	e := &execution{service: s, snapshot: snapshot, prepared: p, identity: identity, projectOnly: true}
	result, _, bubble := e.complete(ctx, field.Definition.Type, payload, field.SelectionSet, []any{field.Alias}, field)
	var data map[string]any
	if !bubble {
		data = map[string]any{field.Alias: result}
	}
	return GraphQLResponse{Data: data, Errors: e.errors}, true
}
func subscriptionEqual(actual, expected any) bool {
	if a, ok := number(actual); ok {
		if b, ok := number(expected); ok {
			return a == b
		}
	}
	return reflect.DeepEqual(actual, expected)
}
