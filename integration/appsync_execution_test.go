package stackd_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	types "github.com/aws/aws-sdk-go-v2/service/appsync/types"
	"stackd"
)

func (c cloudClients) appsync(region, key string) *appsync.Client {
	return appsync.New(appsync.Options{Region: region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}
func TestAppSyncSignedLifecycleExecutionRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			var mu sync.Mutex
			records := map[string]map[string]any{}
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id := strings.TrimPrefix(r.URL.Path, "/")
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.Method == "PUT" {
					var record map[string]any
					if json.NewDecoder(r.Body).Decode(&record) != nil {
						w.WriteHeader(400)
						return
					}
					records[id] = record
				}
				_ = json.NewEncoder(w).Encode(records[id])
			}))
			defer target.Close()
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "111122223333"}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			sdk := cl.appsync("us-east-1", "111122223333")
			created, err := sdk.CreateGraphqlApi(ctx, &appsync.CreateGraphqlApiInput{Name: new("retained-http"), AuthenticationType: types.AuthenticationTypeApiKey, Tags: map[string]string{"application": "owned"}})
			if err != nil {
				t.Fatal(err)
			}
			id := aws.ToString(created.GraphqlApi.ApiId)
			schema := `type Record {id:ID!,title:String!} input RecordInput {id:ID!,title:String!} type Query {record(id:ID!):Record} type Mutation {put(input:RecordInput!):Record} schema {query:Query,mutation:Mutation}`
			if _, err = sdk.StartSchemaCreation(ctx, &appsync.StartSchemaCreationInput{ApiId: new(id), Definition: []byte(schema)}); err != nil {
				t.Fatal(err)
			}
			status, err := sdk.GetSchemaCreationStatus(ctx, &appsync.GetSchemaCreationStatusInput{ApiId: new(id)})
			if err != nil || status.Status != types.SchemaStatusSuccess {
				t.Fatalf("schema status=%v err=%v", status, err)
			}
			exported, err := sdk.GetIntrospectionSchema(ctx, &appsync.GetIntrospectionSchemaInput{ApiId: new(id), Format: types.OutputTypeJson, IncludeDirectives: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			var introspection struct {
				Data struct {
					Schema struct {
						QueryType struct{ Name string } `json:"queryType"`
					} `json:"__schema"`
				} `json:"data"`
			}
			if err = json.Unmarshal(exported.Schema, &introspection); err != nil {
				t.Fatal(err)
			}
			if introspection.Data.Schema.QueryType.Name != "Query" {
				t.Fatalf("exported schema: %#v", introspection)
			}
			key, err := sdk.CreateApiKey(ctx, &appsync.CreateApiKeyInput{ApiId: new(id)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = sdk.CreateDataSource(ctx, &appsync.CreateDataSourceInput{ApiId: new(id), Name: new("http"), Type: types.DataSourceTypeHttp, HttpConfig: &types.HttpDataSourceConfig{Endpoint: new(target.URL)}})
			if err != nil {
				t.Fatal(err)
			}
			runtime := &types.AppSyncRuntime{Name: types.RuntimeNameAppsyncJs, RuntimeVersion: new("1.0.0")}
			function, err := sdk.CreateFunction(ctx, &appsync.CreateFunctionInput{ApiId: new(id), Name: new("write"), DataSourceName: new("http"), Runtime: runtime, Code: new(`export function request(ctx){return {method:'PUT',resourcePath:'/'+ctx.prev.result.id,params:{headers:{'content-type':'application/json'},body:JSON.stringify(ctx.prev.result)}};}export function response(ctx){if(ctx.error){return null;}return JSON.parse(ctx.result.body);}`)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = sdk.CreateResolver(ctx, &appsync.CreateResolverInput{ApiId: new(id), TypeName: new("Mutation"), FieldName: new("put"), Kind: types.ResolverKindPipeline, Runtime: runtime, PipelineConfig: &types.PipelineConfig{Functions: []string{aws.ToString(function.FunctionConfiguration.FunctionId)}}, Code: new(`export function request(ctx){return {id:ctx.args.input.id,title:ctx.args.input.title+'!'};}export function response(ctx){return ctx.prev.result;}`)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = sdk.CreateResolver(ctx, &appsync.CreateResolverInput{ApiId: new(id), TypeName: new("Query"), FieldName: new("record"), DataSourceName: new("http"), Runtime: runtime, Code: new(`export function request(ctx){return {method:'GET',resourcePath:'/'+ctx.args.id};}export function response(ctx){return JSON.parse(ctx.result.body);}`)})
			if err != nil {
				t.Fatal(err)
			}
			query := func(document string) map[string]any {
				t.Helper()
				encoded, _ := json.Marshal(map[string]any{"query": document})
				request, _ := http.NewRequestWithContext(ctx, "POST", cl.server.URL+"/_stackd/appsync/"+id+"/graphql", strings.NewReader(string(encoded)))
				request.Header.Set("x-api-key", aws.ToString(key.ApiKey.Id))
				request.Header.Set("Content-Type", "application/json")
				response, e := cl.server.Client().Do(request)
				if e != nil {
					t.Fatal(e)
				}
				defer response.Body.Close()
				raw, _ := io.ReadAll(response.Body)
				var body map[string]any
				if e = json.Unmarshal(raw, &body); e != nil || response.StatusCode != 200 || body["errors"] != nil {
					t.Fatalf("GraphQL status=%d body=%s err=%v", response.StatusCode, raw, e)
				}
				return body["data"].(map[string]any)
			}
			result := query(`mutation {put(input:{id:"persisted",title:"before"}){id title}}`)
			if result["put"].(map[string]any)["title"] != "before!" {
				t.Fatalf("pipeline=%v", result)
			}
			mu.Lock()
			persisted := records["persisted"]["title"]
			mu.Unlock()
			if persisted != "before!" {
				t.Fatalf("HTTP effect=%v", persisted)
			}
			cl = reopen()
			sdk = cl.appsync("us-east-1", "111122223333")
			result = query(`{record(id:"persisted"){id title}}`)
			if result["record"].(map[string]any)["title"] != "before!" {
				t.Fatalf("retained resolver=%v", result)
			}
			_, err = cl.appsync("us-west-2", "111122223333").GetGraphqlApi(ctx, &appsync.GetGraphqlApiInput{ApiId: new(id)})
			var absent *types.NotFoundException
			if !errors.As(err, &absent) {
				t.Fatalf("region isolation error=%v", err)
			}
			_, err = cl.appsync("us-east-1", "444455556666").GetGraphqlApi(ctx, &appsync.GetGraphqlApiInput{ApiId: new(id)})
			if !errors.As(err, &absent) {
				t.Fatalf("account isolation error=%v", err)
			}
			if _, err = sdk.DeleteGraphqlApi(ctx, &appsync.DeleteGraphqlApiInput{ApiId: new(id)}); err != nil {
				t.Fatal(err)
			}
			_, err = sdk.GetGraphqlApi(ctx, &appsync.GetGraphqlApiInput{ApiId: new(id)})
			if !errors.As(err, &absent) {
				t.Fatalf("deleted API error=%v", err)
			}
		})
	}
}
