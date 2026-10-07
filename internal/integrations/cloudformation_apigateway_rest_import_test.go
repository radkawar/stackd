package integrations

import (
	"encoding/json"
	"reflect"
	"stackd/internal/services/cloudformation"
	"testing"
)

func guardSwagger(t *testing.T) map[string]any {
	t.Helper()
	const document = `{"swagger":"2.0","info":{"title":"guard-sam","version":"1.0"},"paths":{"/hello":{"get":{"security":[{"ApiGatewayAuthorizer":[]}],"responses":{},"x-amazon-apigateway-integration":{"type":"aws_proxy","httpMethod":"POST","uri":"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:hello/invocations"}},"options":{"consumes":["application/json"],"produces":["application/json"],"responses":{"200":{"headers":{"Access-Control-Allow-Origin":{"type":"string"}}}},"x-amazon-apigateway-integration":{"type":"mock","requestTemplates":{"application/json":"{\"statusCode\":200}"},"responses":{"default":{"statusCode":"200","responseParameters":{"method.response.header.Access-Control-Allow-Origin":"'*'"}}}}}}},"securityDefinitions":{"ApiGatewayAuthorizer":{"type":"apiKey","name":"Authorization","in":"header","x-amazon-apigateway-authtype":"cognito_user_pools","x-amazon-apigateway-authorizer":{"type":"cognito_user_pools","providerARNs":["arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_guard"]}}},"x-amazon-apigateway-gateway-responses":{"DEFAULT_4XX":{"responseParameters":{"gatewayresponse.header.Access-Control-Allow-Origin":"'*'"}},"DEFAULT_5XX":{"statusCode":"503","responseTemplates":{"application/json":"{\"error\":$context.error.messageString}"}}},"x-amazon-apigateway-binary-media-types":["application/octet-stream"]}`
	var body map[string]any
	if err := json.Unmarshal([]byte(document), &body); err != nil {
		t.Fatal(err)
	}
	return body
}
func TestGuardSwaggerImportsRealOwnedResourcesAndAtomicUpdates(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNRESTGatewayFixture(t, backend)
			body := guardSwagger(t)
			request := f.request("RestApi", "API", cloudformation.Properties{"Body": body, "BinaryMediaTypes": []any{"image/png"}})
			result := f.create(t, &request)
			api := f.native(t, "GetRestApi", map[string]any{"restApiId": result.Ref})
			if api["name"] != "guard-sam" || !reflect.DeepEqual(api["binaryMediaTypes"], []any{"image/png", "application/octet-stream"}) {
				t.Fatalf("imported API: %#v", api)
			}
			resources := f.native(t, "GetResources", map[string]any{"restApiId": result.Ref, "embed": []any{"methods"}})
			rows, _ := resources["item"].([]any)
			var resource string
			for _, v := range rows {
				row := v.(map[string]any)
				if row["path"] == "/hello" {
					resource = row["id"].(string)
				}
			}
			if resource == "" {
				t.Fatal("Swagger path did not create resource")
			}
			method := f.native(t, "GetMethod", map[string]any{"restApiId": result.Ref, "resourceId": resource, "httpMethod": "GET"})
			if method["authorizationType"] != "COGNITO_USER_POOLS" || method["authorizerId"] == "" || method["methodIntegration"].(map[string]any)["type"] != "AWS_PROXY" {
				t.Fatalf("imported method: %#v", method)
			}
			options := f.native(t, "GetMethod", map[string]any{"restApiId": result.Ref, "resourceId": resource, "httpMethod": "OPTIONS"})
			if options["authorizationType"] != "NONE" || options["methodIntegration"].(map[string]any)["type"] != "MOCK" || options["methodResponses"] == nil {
				t.Fatalf("imported OPTIONS: %#v", options)
			}
			deployment := f.request("Deployment", "Deployment", cloudformation.Properties{"RestApiId": result.Ref, "StageName": "live"})
			f.create(t, &deployment)
			route, err := f.owner.Resolve(f.ctx, result.Ref, "live", "OPTIONS", "/hello")
			if err != nil || route.Mock == nil || route.Mock.Headers["Access-Control-Allow-Origin"] != "*" {
				t.Fatalf("deployed mock route: %#v %v", route, err)
			}
			oldResources := resources
			invalid := guardSwagger(t)
			paths := invalid["paths"].(map[string]any)
			hello := paths["/hello"].(map[string]any)
			hello["get"].(map[string]any)["x-amazon-apigateway-integration"].(map[string]any)["type"] = "http_proxy"
			request.Previous = request.Properties
			request.Properties = cloudformation.Properties{"Body": invalid, "Mode": "overwrite", "Name": "must-not-commit", "BinaryMediaTypes": []any{"image/jpeg"}}
			if _, err := f.handlers[request.Type].Update(f.ctx, request); err == nil {
				t.Fatal("unsupported import committed")
			}
			after := f.native(t, "GetRestApi", map[string]any{"restApiId": result.Ref})
			if !reflect.DeepEqual(after, api) {
				t.Fatalf("failed update changed API: %#v -> %#v", api, after)
			}
			if current := f.native(t, "GetResources", map[string]any{"restApiId": result.Ref, "embed": []any{"methods"}}); !reflect.DeepEqual(oldResources, current) {
				t.Fatal("failed overwrite changed resources/methods")
			}
			changed := guardSwagger(t)
			changedPaths := changed["paths"].(map[string]any)
			changedPaths["/new"] = changedPaths["/hello"]
			delete(changedPaths, "/hello")
			request.Properties = cloudformation.Properties{"Body": changed, "Mode": "overwrite", "Name": "updated"}
			if _, err := f.handlers[request.Type].Update(f.ctx, request); err != nil {
				t.Fatal(err)
			}
			if old, err := f.owner.Resolve(f.ctx, result.Ref, "live", "OPTIONS", "/hello"); err != nil || old.Mock == nil {
				t.Fatalf("overwrite mutated immutable deployment: %#v %v", old, err)
			}
			if _, err := f.owner.Resolve(f.ctx, result.Ref, "live", "OPTIONS", "/new"); err == nil {
				t.Fatal("new live method appeared without deployment")
			}
			f.native(t, "PutGatewayResponse", map[string]any{"restApiId": result.Ref, "responseType": "DEFAULT_4XX", "responseParameters": map[string]any{"gatewayresponse.header.Access-Control-Allow-Origin": "'updated'"}})
			live, err := f.owner.Resolve(f.ctx, result.Ref, "live", "OPTIONS", "/hello")
			if err != nil || live.GatewayResponses["DEFAULT_4XX"].Headers["Access-Control-Allow-Origin"] != "updated" {
				t.Fatalf("gateway responses should be live: %#v %v", live, err)
			}
		})
	}
}
func TestGuardSwaggerRejectedImportLeavesNoAPI(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNRESTGatewayFixture(t, backend)
			for _, mutate := range []func(map[string]any){func(b map[string]any) { b["openapi"] = "3.0.0" }, func(b map[string]any) {
				b["x-amazon-apigateway-gateway-responses"].(map[string]any)["DEFAULT_4XX"].(map[string]any)["responseParameters"] = map[string]any{"gatewayresponse.header.X": "$context.identity.user"}
			}, func(b map[string]any) {
				b["securityDefinitions"].(map[string]any)["ApiGatewayAuthorizer"].(map[string]any)["in"] = "query"
			}, func(b map[string]any) { b["x-amazon-apigateway-binary-media-types"] = []any{"invalid"} }} {
				body := guardSwagger(t)
				mutate(body)
				data, _ := json.Marshal(body)
				if _, err := (cfnRESTGateway{f.commands, ""}).call(f.ctx, "ImportRestApi", map[string]any{"body": string(data), "failOnWarnings": true}); err == nil {
					t.Fatal("accepted unsupported import")
				}
				got := f.native(t, "GetRestApis", map[string]any{})
				rows, _ := got["item"].([]any)
				if len(rows) != 0 {
					t.Fatalf("failed import retained API: %#v", got)
				}
			}
		})
	}
}
func TestNativeSwaggerMergeAndOverwriteRemainDistinct(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNRESTGatewayFixture(t, backend)
			data, _ := json.Marshal(guardSwagger(t))
			imported := f.native(t, "ImportRestApi", map[string]any{"body": string(data)})
			id := imported["id"].(string)
			body := guardSwagger(t)
			delete(body, "securityDefinitions")
			delete(body, "x-amazon-apigateway-gateway-responses")
			delete(body, "x-amazon-apigateway-binary-media-types")
			hello := body["paths"].(map[string]any)["/hello"].(map[string]any)
			delete(hello, "get")
			data, _ = json.Marshal(body)
			f.native(t, "PutRestApi", map[string]any{"restApiId": id, "body": string(data)})
			rows := f.native(t, "GetResources", map[string]any{"restApiId": id})["item"].([]any)
			var resource string
			for _, value := range rows {
				row := value.(map[string]any)
				if row["path"] == "/hello" {
					resource = row["id"].(string)
				}
			}
			f.native(t, "GetMethod", map[string]any{"restApiId": id, "resourceId": resource, "httpMethod": "GET"})
			f.native(t, "GetMethod", map[string]any{"restApiId": id, "resourceId": resource, "httpMethod": "OPTIONS"})
			if api := f.native(t, "GetRestApi", map[string]any{"restApiId": id}); api["binaryMediaTypes"] == nil {
				t.Fatal("merge erased omitted binary settings")
			}
			f.native(t, "PutRestApi", map[string]any{"restApiId": id, "body": string(data), "mode": "overwrite"})
			rows = f.native(t, "GetResources", map[string]any{"restApiId": id})["item"].([]any)
			for _, value := range rows {
				row := value.(map[string]any)
				if row["path"] == "/hello" {
					resource = row["id"].(string)
				}
			}
			if _, err := (cfnRESTGateway{f.commands, ""}).call(f.ctx, "GetMethod", map[string]any{"restApiId": id, "resourceId": resource, "httpMethod": "GET"}); !cfnRESTMissing(err) {
				t.Fatalf("overwrite retained omitted GET: %v", err)
			}
			api := f.native(t, "GetRestApi", map[string]any{"restApiId": id})
			media, _ := api["binaryMediaTypes"].([]any)
			if len(media) != 0 {
				t.Fatal("overwrite retained omitted binary settings")
			}
			responses := f.native(t, "GetGatewayResponses", map[string]any{"restApiId": id})
			items, _ := responses["item"].([]any)
			if len(items) != 0 {
				t.Fatal("overwrite retained omitted gateway responses")
			}
		})
	}
}
