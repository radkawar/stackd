package appsync

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	api "stackd/internal/awsapi/appsync"
)

const nativeSchema = `
type Thing @aws_api_key @aws_iam { id: ID!, title: String!, optional: String, json: AWSJSON }
input ThingInput { id: ID!, title: String!, json: AWSJSON }
type Query { item(id: ID!): Thing @aws_api_key @aws_iam, fail: String, missing: String }
type Mutation { put(input: ThingInput!): Thing @aws_api_key @aws_iam }
type Subscription { changed(id: ID): Thing @aws_subscribe(mutations: ["put"]) @aws_api_key @aws_iam }
schema { query: Query, mutation: Mutation, subscription: Subscription }`

func nativeExecution(t *testing.T) (*Service, Snapshot, Identity) {
	t.Helper()
	key := Key{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", ID: "native"}
	record := APIRecord{Key: key, API: api.GraphqlApi{AuthenticationType: new(api.AuthenticationTypeAPI_KEY), AdditionalAuthenticationProviders: api.AdditionalAuthenticationProviders{{AuthenticationType: new(api.AuthenticationTypeAWS_IAM)}}}, Schema: nativeSchema, SchemaStatus: "SUCCESS"}
	source := api.DataSource{Name: new(api.ResourceName("none")), Type: new(api.DataSourceTypeNONE)}
	resolver := func(parent, field, code string) api.Resolver {
		return api.Resolver{TypeName: new(api.ResourceName(parent)), FieldName: new(api.ResourceName(field)), DataSourceName: source.Name, Code: new(api.Code(code)), Kind: new(api.ResolverKindUNIT)}
	}
	snapshot := Snapshot{API: record, DataSources: map[string]api.DataSource{"none": source}, Resolvers: map[string]api.Resolver{
		"Query.item":   resolver("Query", "item", `export function request(ctx){return {payload:{id:ctx.args.id,title:'loaded',json:{nested:1}}};} export function response(ctx){return ctx.result;}`),
		"Query.fail":   resolver("Query", "fail", `import {util} from '@aws-appsync/utils';export function request(ctx){util.error('owned failure','OwnedError');}export function response(ctx){return ctx.result;}`),
		"Mutation.put": {TypeName: new(api.ResourceName("Mutation")), FieldName: new(api.ResourceName("put")), Kind: new(api.ResolverKindPIPELINE), Code: new(api.Code(`export function request(ctx){ctx.stash.title=ctx.args.input.title+'!';return ctx.args.input;}export function response(ctx){return ctx.prev.result;}`)), PipelineConfig: &api.PipelineConfig{Functions: api.FunctionsIds{"fn"}}},
	}, Functions: map[string]api.FunctionConfiguration{"fn": {FunctionId: new(api.String("fn")), DataSourceName: source.Name, Code: new(api.Code(`export function request(ctx){return {payload:{id:ctx.prev.result.id,title:ctx.stash.title,json:ctx.prev.result.json}};}export function response(ctx){return ctx.result;}`))}}}
	service := NewWithConfig(Config{})
	t.Cleanup(func() { _ = service.Close() })
	return service, snapshot, Identity{Mode: "API_KEY", Context: context.Background()}
}
func TestNativeExecutionFixture(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/appsync-native.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Cases map[string]json.RawMessage `json:"cases"`
	}
	if err = json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	service, snapshot, identity := nativeExecution(t)
	cases := []struct {
		name, query string
		variables   map[string]any
	}{
		{"query", `query($id: ID!) { alias:item(id:$id){...F json} missing } fragment F on Thing {id title}`, map[string]any{"id": "one"}},
		{"jsonInput", `mutation($i: ThingInput!){put(input:$i){id title json}}`, map[string]any{"i": map[string]any{"id": "one", "title": "input", "json": `{"value":42}`}}},
		{"mappingError", `{ fail missing }`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := service.execute(context.Background(), snapshot, GraphQLRequest{Query: tc.query, Variables: tc.variables}, identity)
			var selected struct {
				Body GraphQLResponse `json:"body"`
			}
			if err := json.Unmarshal(capture.Cases[tc.name], &selected); err != nil {
				t.Fatal(err)
			}
			want := selected.Body
			if !reflect.DeepEqual(got.Data, want.Data) {
				t.Fatalf("data = %#v, native %#v; errors %#v", got.Data, want.Data, got.Errors)
			}
			if len(got.Errors) != len(want.Errors) {
				t.Fatalf("errors=%#v native=%#v", got.Errors, want.Errors)
			}
			for i := range got.Errors {
				if got.Errors[i].ErrorType != want.Errors[i].ErrorType || !reflect.DeepEqual(got.Errors[i].Path, want.Errors[i].Path) {
					t.Fatalf("error=%#v native=%#v", got.Errors[i], want.Errors[i])
				}
			}
		})
	}
}
func TestInvalidInputCannotRunEarlierMutation(t *testing.T) {
	service, snapshot, identity := nativeExecution(t)
	// Invalid AWS scalar input belongs to GraphQL admission, before ANY mutation
	// root resolver executes, even when the earlier field is otherwise valid.
	got := service.execute(context.Background(), snapshot, GraphQLRequest{Query: `mutation {first:put(input:{id:"one",title:"valid"}){id} second:put(input:{id:"two",title:"invalid",json:"no"}){id}}`}, identity)
	if got.Data != nil || len(got.Errors) == 0 {
		t.Fatalf("invalid input executed mutation: %#v", got)
	}
}
func TestSelectionMergingAndNullPropagation(t *testing.T) {
	service, snapshot, identity := nativeExecution(t)
	result := service.execute(context.Background(), snapshot, GraphQLRequest{Query: `query($hide:Boolean!){item(id:"one"){id} ...Q} fragment Q on Query {item(id:"one"){title optional @skip(if:$hide)}}`, Variables: map[string]any{"hide": true}}, identity)
	want := map[string]any{"item": map[string]any{"id": "one", "title": "loaded"}}
	if !reflect.DeepEqual(result.Data, want) || len(result.Errors) != 0 {
		t.Fatalf("merged selection=%#v", result)
	}
	resolver := snapshot.Resolvers["Query.item"]
	resolver.Code = new(api.Code(`export function request(ctx){return {payload:{id:ctx.args.id}};}export function response(ctx){return ctx.result;}`))
	snapshot.Resolvers["Query.item"] = resolver
	result = service.execute(context.Background(), snapshot, GraphQLRequest{Query: `{item(id:"one"){id title} missing}`}, identity)
	if result.Data["item"] != nil || len(result.Errors) != 1 || !reflect.DeepEqual(result.Errors[0].Path, []any{"item", "title"}) {
		t.Fatalf("non-null propagation=%#v", result)
	}
}
func TestSubscriptionSelectionAndArgumentOmission(t *testing.T) {
	service, snapshot, identity := nativeExecution(t)
	ctx := context.Background()
	p, err := service.subscriptionStart(ctx, snapshot, GraphQLRequest{Query: `subscription {changed(id:"one"){id title optional}}`}, identity)
	if err != nil {
		t.Fatal(err)
	}
	response, matched := service.subscriptionEvent(ctx, snapshot, p, identity, "put", map[string]any{"id": "two", "title": "not selected"})
	if matched {
		t.Fatalf("argument mismatch delivered %#v", response)
	}
	response, matched = service.subscriptionEvent(ctx, snapshot, p, identity, "put", map[string]any{"id": "one", "title": "notify!"})
	want := map[string]any{"changed": map[string]any{"id": "one", "title": "notify!", "optional": nil}}
	if !matched || !reflect.DeepEqual(response.Data, want) || len(response.Errors) != 0 {
		t.Fatalf("subscription projection=%#v match=%v", response, matched)
	}
	p, err = service.subscriptionStart(ctx, snapshot, GraphQLRequest{Query: `subscription {changed(id:null){optional}}`}, identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, matched = service.subscriptionEvent(ctx, snapshot, p, identity, "put", map[string]any{"id": "one"}); matched {
		t.Fatal("explicit null matched non-null argument")
	}
	if _, matched = service.subscriptionEvent(ctx, snapshot, p, identity, "put", map[string]any{}); !matched {
		t.Fatal("explicit null did not match missing result")
	}
}
func TestIntrospectionAndRuntimeEarlyReturn(t *testing.T) {
	service, snapshot, identity := nativeExecution(t)
	got := service.execute(context.Background(), snapshot, GraphQLRequest{Query: `{__type(name:"Thing"){name kind fields{name type{kind name ofType{name kind}}}}}`}, identity)
	object, ok := got.Data["__type"].(map[string]any)
	if !ok || object["name"] != "Thing" || object["kind"] != "OBJECT" || len(got.Errors) != 0 {
		t.Fatalf("introspection=%#v", got)
	}
	fields := object["fields"].([]any)
	id := fields[0].(map[string]any)
	typ := id["type"].(map[string]any)
	if id["name"] != "id" || typ["kind"] != "NON_NULL" || typ["ofType"].(map[string]any)["name"] != "ID" {
		t.Fatalf("field type=%#v", id)
	}
	resolver := snapshot.Resolvers["Query.item"]
	resolver.Code = new(api.Code(`import {runtime} from '@aws-appsync/utils';export function request(ctx){runtime.earlyReturn({id:'early',title:'done'});}export function response(ctx){return ctx.result;}`))
	snapshot.Resolvers["Query.item"] = resolver
	got = service.execute(context.Background(), snapshot, GraphQLRequest{Query: `{item(id:"one"){id title}}`}, identity)
	if !reflect.DeepEqual(got.Data, map[string]any{"item": map[string]any{"id": "early", "title": "done"}}) || len(got.Errors) != 0 {
		t.Fatalf("early return=%#v", got)
	}
}
