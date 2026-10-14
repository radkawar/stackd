package stackd_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"stackd"
	"stackd/internal/awstest"
)

// This exercises the public SDK and the actual deployed HTTP route, with no
// Lambda runtime prerequisite. Run both backends, including a retained reopen.
func TestRESTResponseLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "731842905617"
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			client := func(key, secret string) *apigateway.Client {
				return apigateway.New(apigateway.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			owner := client(account, "test")
			rest, err := owner.CreateRestApi(t.Context(), &apigateway.CreateRestApiInput{Name: aws.String("response-lifecycle")})
			if err != nil {
				t.Fatal(err)
			}
			resources, err := owner.GetResources(t.Context(), &apigateway.GetResourcesInput{RestApiId: rest.Id})
			if err != nil {
				t.Fatal(err)
			}
			var root *string
			for _, resource := range resources.Items {
				if aws.ToString(resource.Path) == "/" {
					root = resource.Id
				}
			}
			if root == nil {
				t.Fatal("missing root")
			}
			patch := func(op, path, value string) types.PatchOperation {
				return types.PatchOperation{Op: types.Op(op), Path: aws.String(path), Value: aws.String(value)}
			}
			putMethodResponse := func(method string) {
				t.Helper()
				_, err := owner.PutMethodResponse(t.Context(), &apigateway.PutMethodResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String(method), StatusCode: aws.String("200"), ResponseParameters: map[string]bool{"method.response.header.X-Phase": false, "method.response.header.X~Token": false, "method.response.header.X-Drop": false}})
				if err != nil {
					t.Fatal(err)
				}
			}
			putIntegrationResponse := func(method, phase string) {
				t.Helper()
				_, err := owner.PutIntegrationResponse(t.Context(), &apigateway.PutIntegrationResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String(method), StatusCode: aws.String("200"), ResponseParameters: map[string]string{"method.response.header.X-Phase": "'" + phase + "'", "method.response.header.X~Token": "'literal'", "method.response.header.X-Drop": "'drop'"}, ResponseTemplates: map[string]string{"application/json": `{"phase":"` + phase + `"}`}})
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, method := range []string{"GET", "POST", "PUT"} {
				auth := "NONE"
				if method == "POST" {
					auth = "AWS_IAM"
				}
				if _, err := owner.PutMethod(t.Context(), &apigateway.PutMethodInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String(method), AuthorizationType: aws.String(auth)}); err != nil {
					t.Fatal(err)
				}
				if method == "PUT" {
					_, err := owner.PutIntegration(t.Context(), &apigateway.PutIntegrationInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String(method), Type: types.IntegrationTypeAwsProxy, IntegrationHttpMethod: aws.String("POST"), Uri: aws.String("arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:" + account + ":function:response-proxy/invocations")})
					if err != nil {
						t.Fatal(err)
					}
					continue
				}
				out, err := owner.PutIntegration(t.Context(), &apigateway.PutIntegrationInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String(method), Type: types.IntegrationTypeMock, RequestTemplates: map[string]string{"application/json": `{"statusCode":200}`}})
				if err != nil {
					t.Fatal(err)
				}
				if len(out.IntegrationResponses) != 0 {
					t.Fatal("fresh MOCK fabricated an integration response")
				}
				putMethodResponse(method)
				if method == "POST" {
					putIntegrationResponse(method, "secured")
				}
			}
			getMethodResponse := func() *apigateway.GetMethodResponseOutput {
				t.Helper()
				out, err := owner.GetMethodResponse(t.Context(), &apigateway.GetMethodResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET"), StatusCode: aws.String("200")})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			getIntegrationResponse := func() *apigateway.GetIntegrationResponseOutput {
				t.Helper()
				out, err := owner.GetIntegrationResponse(t.Context(), &apigateway.GetIntegrationResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET"), StatusCode: aws.String("200")})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			deploy := func() {
				t.Helper()
				if _, err := owner.CreateDeployment(t.Context(), &apigateway.CreateDeploymentInput{RestApiId: rest.Id, StageName: aws.String("live")}); err != nil {
					t.Fatal(err)
				}
			}
			invoke := func(method string, status int, phase, body string) http.Header {
				t.Helper()
				request, err := http.NewRequestWithContext(t.Context(), method, clients.server.URL+"/_stackd/execute-api/"+aws.ToString(rest.Id)+"/live/", nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := clients.server.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != status || response.Header.Get("X-Phase") != phase || (body != "" && string(payload) != body) {
					t.Fatalf("%s status=%d headers=%v body=%s; want status=%d phase=%q body=%q", method, response.StatusCode, response.Header, payload, status, phase, body)
				}
				return response.Header
			}
			_, err = owner.GetIntegrationResponse(t.Context(), &apigateway.GetIntegrationResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET"), StatusCode: aws.String("200")})
			assertAPIError(t, err, "NotFoundException")
			deploy()
			invoke("GET", 500, "", "")
			putIntegrationResponse("GET", "first")
			invoke("GET", 500, "", "")
			deploy()
			invoke("GET", 200, "first", `{"phase":"first"}`)
			methodOut, err := owner.UpdateMethodResponse(t.Context(), &apigateway.UpdateMethodResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET"), StatusCode: aws.String("200"), PatchOperations: []types.PatchOperation{patch("replace", "/responseParameters/method.response.header.X-Phase", "true"), patch("replace", "/responseParameters/method.response.header.X~0Token", "true"), patch("remove", "/responseParameters/method.response.header.X-Drop", "")}})
			if err != nil {
				t.Fatal(err)
			}
			if !methodOut.ResponseParameters["method.response.header.X-Phase"] || !methodOut.ResponseParameters["method.response.header.X~Token"] || len(methodOut.ResponseParameters) != 2 {
				t.Fatalf("lost method header flags: %+v", methodOut)
			}
			integrationOut, err := owner.UpdateIntegrationResponse(t.Context(), &apigateway.UpdateIntegrationResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET"), StatusCode: aws.String("200"), PatchOperations: []types.PatchOperation{patch("replace", "/responseParameters/method.response.header.X-Phase", "'second'"), patch("replace", "/responseTemplates/application~1json", `{"phase":"second"}`)}})
			if err != nil {
				t.Fatal(err)
			}
			if integrationOut.ResponseTemplates["application/json"] != `{"phase":"second"}` {
				t.Fatalf("lost escaped template: %+v", integrationOut)
			}
			method, err := owner.GetMethod(t.Context(), &apigateway.GetMethodInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET")})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(method.MethodResponses["200"].ResponseParameters, methodOut.ResponseParameters) || !reflect.DeepEqual(method.MethodIntegration.IntegrationResponses["200"].ResponseTemplates, integrationOut.ResponseTemplates) {
				t.Fatalf("GetMethod disagrees with child response resources: %+v", method)
			}
			integration, err := owner.GetIntegration(t.Context(), &apigateway.GetIntegrationInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET")})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(integration.IntegrationResponses["200"].ResponseParameters, integrationOut.ResponseParameters) {
				t.Fatalf("GetIntegration disagrees: %+v", integration)
			}
			if invoke("GET", 200, "first", `{"phase":"first"}`).Get("X-Drop") != "drop" {
				t.Fatal("undeployed method patch changed snapshot")
			}
			deploy()
			if invoke("GET", 200, "second", `{"phase":"second"}`).Get("X-Drop") != "" {
				t.Fatal("deleted method header still emitted after deployment")
			}

			for _, invalid := range []types.PatchOperation{patch("replace", "/statusCode", "201"), patch("add", "/responseModels/application~1json", "Empty"), patch("replace", "/responseParameters/method.response.header.X-Phase", "yes"), patch("copy", "/responseParameters/method.response.header.X-Phase", "false"), patch("add", "/responseParameters/method.response.header.bad~2escape", "true")} {
				_, err := owner.UpdateMethodResponse(t.Context(), &apigateway.UpdateMethodResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET"), StatusCode: aws.String("200"), PatchOperations: []types.PatchOperation{patch("replace", "/responseParameters/method.response.header.X-Phase", "false"), invalid}})
				assertAPIError(t, err, "BadRequestException")
			}
			for _, invalid := range []types.PatchOperation{patch("replace", "/statusCode", "201"), patch("replace", "/selectionPattern", ".*"), patch("replace", "/contentHandling", "CONVERT_TO_BINARY"), patch("replace", "/responseTemplates/application~1json", "$input.body"), patch("add", "/responseTemplates/text~1plain", "text"), patch("replace", "/responseParameters/method.response.header.X-Phase", "integration.response.header.X-Phase"), patch("move", "/responseTemplates/application~1json", "text"), patch("add", "/responseTemplates/bad~", "text")} {
				_, err := owner.UpdateIntegrationResponse(t.Context(), &apigateway.UpdateIntegrationResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET"), StatusCode: aws.String("200"), PatchOperations: []types.PatchOperation{patch("replace", "/responseParameters/method.response.header.X-Phase", "'rejected'"), invalid}})
				assertAPIError(t, err, "BadRequestException")
			}
			if !getMethodResponse().ResponseParameters["method.response.header.X-Phase"] || getIntegrationResponse().ResponseParameters["method.response.header.X-Phase"] != "'second'" {
				t.Fatal("rejected multi-operation patch committed")
			}

			_, err = owner.PutGatewayResponse(t.Context(), &apigateway.PutGatewayResponseInput{RestApiId: rest.Id, ResponseType: types.GatewayResponseTypeDefault4xx, ResponseParameters: map[string]string{"gatewayresponse.header.X-Phase": "'denied-first'"}, ResponseTemplates: map[string]string{"application/json": `{"denied":"first"}`}})
			if err != nil {
				t.Fatal(err)
			}
			invoke("POST", 403, "denied-first", `{"denied":"first"}`)
			gateway, err := owner.UpdateGatewayResponse(t.Context(), &apigateway.UpdateGatewayResponseInput{RestApiId: rest.Id, ResponseType: types.GatewayResponseTypeDefault4xx, PatchOperations: []types.PatchOperation{patch("replace", "/statusCode", "418"), patch("replace", "/responseParameters/gatewayresponse.header.X-Phase", "'denied-live'"), patch("replace", "/responseTemplates/application~1json", `{"denied":"live"}`)}})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(gateway.StatusCode) != "418" || gateway.DefaultResponse {
				t.Fatalf("invalid gateway response projection: %+v", gateway)
			}
			invoke("POST", 418, "denied-live", `{"denied":"live"}`)
			for _, invalid := range []types.PatchOperation{patch("add", "/statusCode", "419"), patch("replace", "/statusCode", "600"), patch("remove", "/statusCode", ""), patch("replace", "/responseType", "DEFAULT_5XX"), patch("replace", "/responseTemplates/application~1json", "$context.identity.sourceIp"), patch("add", "/responseTemplates/text~1plain", "text"), patch("remove", "/responseParameters/gatewayresponse.header.Missing", "")} {
				_, err := owner.UpdateGatewayResponse(t.Context(), &apigateway.UpdateGatewayResponseInput{RestApiId: rest.Id, ResponseType: types.GatewayResponseTypeDefault4xx, PatchOperations: []types.PatchOperation{patch("replace", "/statusCode", "419"), invalid}})
				assertAPIError(t, err, "BadRequestException")
			}
			invoke("POST", 418, "denied-live", `{"denied":"live"}`)
			clients = reopen()
			owner = client(account, "test")
			if !getMethodResponse().ResponseParameters["method.response.header.X-Phase"] || getIntegrationResponse().ResponseParameters["method.response.header.X-Phase"] != "'second'" {
				t.Fatal("accepted response state or rejected-patch atomicity lost across reopen")
			}
			invoke("GET", 200, "second", `{"phase":"second"}`)
			invoke("POST", 418, "denied-live", `{"denied":"live"}`)

			// Each native IAM verb is evaluated against its exact response URI, not
			// against the method/integration parent or an invented action name.
			base := map[string]any{"RestApiId": aws.ToString(rest.Id), "ResourceId": aws.ToString(root), "HttpMethod": "GET", "StatusCode": "200"}
			call := func(c *apigateway.Client, operation string, input map[string]any) error {
				t.Helper()
				encoded, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				_, err = awstest.CallSDK(t.Context(), c, operation, encoded)
				return err
			}
			_, userKey, userSecret := clients.user(t, account, "response-editor")
			_, foreignKey, foreignSecret := clients.user(t, "284619730852", "response-outsider")
			putUserPolicy(t, clients.iam("284619730852", "test", ""), "response-outsider", allow(`"apigateway:*"`, "*"))
			for _, entry := range []struct{ operation, verb, suffix string }{
				{"GetMethodResponse", "GET", "/responses/200"}, {"UpdateMethodResponse", "PATCH", "/responses/200"}, {"DeleteMethodResponse", "DELETE", "/responses/200"},
				{"GetIntegrationResponse", "GET", "/integration/responses/200"}, {"UpdateIntegrationResponse", "PATCH", "/integration/responses/200"}, {"DeleteIntegrationResponse", "DELETE", "/integration/responses/200"},
				{"UpdateGatewayResponse", "PATCH", "/gatewayresponses/DEFAULT_4XX"},
			} {
				input := map[string]any{}
				for k, v := range base {
					input[k] = v
				}
				path := "/restapis/" + aws.ToString(rest.Id) + "/resources/" + aws.ToString(root) + "/methods/GET" + entry.suffix
				if entry.operation == "UpdateGatewayResponse" {
					input = map[string]any{"RestApiId": aws.ToString(rest.Id), "ResponseType": "DEFAULT_4XX"}
					path = "/restapis/" + aws.ToString(rest.Id) + entry.suffix
				}
				assertAPIError(t, call(client(foreignKey, foreignSecret), entry.operation, input), "NotFoundException")
				putUserPolicy(t, clients.iam(account, "test", ""), "response-editor", allow(fmt.Sprintf("%q", "apigateway:"+entry.verb), "arn:aws:apigateway:us-east-1::"+path))
				wrong := map[string]any{}
				for k, v := range input {
					wrong[k] = v
				}
				if entry.operation == "UpdateGatewayResponse" {
					wrong["ResponseType"] = "DEFAULT_5XX"
				} else {
					wrong["StatusCode"] = "201"
				}
				assertAPIError(t, call(client(userKey, userSecret), entry.operation, wrong), "AccessDeniedException")
				if err := call(client(userKey, userSecret), entry.operation, input); err != nil {
					t.Fatalf("%s exact native IAM route: %v", entry.operation, err)
				}
				if entry.operation == "DeleteMethodResponse" {
					putMethodResponse("GET")
				}
				if entry.operation == "DeleteIntegrationResponse" {
					putIntegrationResponse("GET", "second")
				}
			}
			for _, operation := range []string{"GetIntegrationResponse", "DeleteIntegrationResponse", "UpdateIntegrationResponse", "PutIntegrationResponse"} {
				input := map[string]any{}
				for k, v := range base {
					input[k] = v
				}
				input["HttpMethod"] = "PUT"
				assertAPIError(t, call(owner, operation, input), "BadRequestException")
			}
			// Positive add/remove paths use the same escaped JSON pointer keys.
			_, err = owner.UpdateMethodResponse(t.Context(), &apigateway.UpdateMethodResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET"), StatusCode: aws.String("200"), PatchOperations: []types.PatchOperation{patch("add", "/responseParameters/method.response.header.X-Added", "true"), patch("remove", "/responseParameters/method.response.header.X-Added", "")}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = owner.UpdateIntegrationResponse(t.Context(), &apigateway.UpdateIntegrationResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET"), StatusCode: aws.String("200"), PatchOperations: []types.PatchOperation{patch("add", "/responseParameters/method.response.header.X-Added", "'literal'"), patch("remove", "/responseParameters/method.response.header.X-Added", "")}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = owner.UpdateGatewayResponse(t.Context(), &apigateway.UpdateGatewayResponseInput{RestApiId: rest.Id, ResponseType: types.GatewayResponseTypeDefault4xx, PatchOperations: []types.PatchOperation{patch("add", "/responseParameters/gatewayresponse.header.X-Added", "'literal'"), patch("remove", "/responseParameters/gatewayresponse.header.X-Added", "")}})
			if err != nil {
				t.Fatal(err)
			}

			_, err = owner.DeleteMethodResponse(t.Context(), &apigateway.DeleteMethodResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET"), StatusCode: aws.String("200")})
			if err != nil {
				t.Fatal(err)
			}
			assertAPIError(t, call(owner, "GetMethodResponse", base), "NotFoundException")
			assertAPIError(t, call(owner, "DeleteMethodResponse", base), "NotFoundException")
			assertAPIError(t, call(owner, "UpdateMethodResponse", base), "NotFoundException")
			invoke("GET", 200, "second", `{"phase":"second"}`)
			deploy()
			invoke("GET", 500, "", "")
			putMethodResponse("GET")
			invoke("GET", 500, "", "")
			deploy()
			invoke("GET", 200, "second", `{"phase":"second"}`)
			if err := call(owner, "DeleteIntegrationResponse", base); err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"GetIntegrationResponse", "DeleteIntegrationResponse", "UpdateIntegrationResponse"} {
				assertAPIError(t, call(owner, operation, base), "NotFoundException")
			}
			integration, err = owner.GetIntegration(t.Context(), &apigateway.GetIntegrationInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET")})
			if err != nil {
				t.Fatal(err)
			}
			if len(integration.IntegrationResponses) != 0 {
				t.Fatal("deleted response returned by GetIntegration")
			}
			clients = reopen()
			owner = client(account, "test")
			assertAPIError(t, call(owner, "GetIntegrationResponse", base), "NotFoundException")
			if len(getMethodResponse().ResponseParameters) != 3 {
				t.Fatal("recreated method response lost on reopen")
			}
			invoke("GET", 200, "second", `{"phase":"second"}`)
			invoke("POST", 418, "denied-live", `{"denied":"live"}`)
			deploy()
			invoke("GET", 500, "", "")
			putIntegrationResponse("GET", "recreated")
			invoke("GET", 500, "", "")
			deploy()
			invoke("GET", 200, "recreated", `{"phase":"recreated"}`)
			// Empty configured templates survive reopen and differ from removal.
			_, err = owner.UpdateIntegrationResponse(t.Context(), &apigateway.UpdateIntegrationResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET"), StatusCode: aws.String("200"), PatchOperations: []types.PatchOperation{patch("replace", "/responseTemplates/application~1json", "")}})
			if err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			owner = client(account, "test")
			if value, exists := getIntegrationResponse().ResponseTemplates["application/json"]; !exists || value != "" {
				t.Fatal("empty configured template lost on reopen")
			}
			_, err = owner.UpdateIntegrationResponse(t.Context(), &apigateway.UpdateIntegrationResponseInput{RestApiId: rest.Id, ResourceId: root, HttpMethod: aws.String("GET"), StatusCode: aws.String("200"), PatchOperations: []types.PatchOperation{patch("remove", "/responseTemplates/application~1json", ""), patch("remove", "/responseParameters/method.response.header.X~0Token", "")}})
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := getIntegrationResponse().ResponseTemplates["application/json"]; exists {
				t.Fatal("removed template still returned")
			}
			if _, err := owner.DeleteGatewayResponse(t.Context(), &apigateway.DeleteGatewayResponseInput{RestApiId: rest.Id, ResponseType: types.GatewayResponseTypeDefault4xx}); err != nil {
				t.Fatal(err)
			}
			invoke("POST", 403, "", "")
			_, err = owner.UpdateGatewayResponse(t.Context(), &apigateway.UpdateGatewayResponseInput{RestApiId: rest.Id, ResponseType: types.GatewayResponseTypeDefault4xx})
			assertAPIError(t, err, "NotFoundException")
			_, err = owner.PutGatewayResponse(t.Context(), &apigateway.PutGatewayResponseInput{RestApiId: rest.Id, ResponseType: types.GatewayResponseTypeDefault4xx, StatusCode: aws.String("419"), ResponseParameters: map[string]string{"gatewayresponse.header.X-Phase": "'recreated-live'"}})
			if err != nil {
				t.Fatal(err)
			}
			invoke("POST", 419, "recreated-live", "")
		})
	}
}
