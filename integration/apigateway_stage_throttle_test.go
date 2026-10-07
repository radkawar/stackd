package stackd_test

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"stackd"
	"stackd/clock"
)

func TestRESTStageThrottleLiveUpdatesAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "123456789012"
			now := clock.NewManual(time.Date(2035, 1, 2, 0, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: now})
			client := func() *apigateway.Client {
				return apigateway.New(apigateway.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			owner := client()
			api, err := owner.CreateRestApi(t.Context(), &apigateway.CreateRestApiInput{Name: aws.String("stage-throttle")})
			if err != nil {
				t.Fatal(err)
			}
			resources, err := owner.GetResources(t.Context(), &apigateway.GetResourcesInput{RestApiId: api.Id})
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
				t.Fatal("missing root resource")
			}
			for _, path := range []string{"pets", "other"} {
				resource, err := owner.CreateResource(t.Context(), &apigateway.CreateResourceInput{RestApiId: api.Id, ParentId: root, PathPart: aws.String(path)})
				if err != nil {
					t.Fatal(err)
				}
				methods := []string{"GET"}
				if path == "pets" {
					methods = append(methods, "POST")
				}
				for _, method := range methods {
					if _, err := owner.PutMethod(t.Context(), &apigateway.PutMethodInput{RestApiId: api.Id, ResourceId: resource.Id, HttpMethod: aws.String(method), AuthorizationType: aws.String("NONE")}); err != nil {
						t.Fatal(err)
					}
					if _, err := owner.PutIntegration(t.Context(), &apigateway.PutIntegrationInput{RestApiId: api.Id, ResourceId: resource.Id, HttpMethod: aws.String(method), Type: types.IntegrationType("MOCK"), RequestTemplates: map[string]string{"application/json": "{\"statusCode\":200}"}}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := owner.CreateDeployment(t.Context(), &apigateway.CreateDeploymentInput{RestApiId: api.Id, StageName: aws.String("live")}); err != nil {
				t.Fatal(err)
			}
			patch := func(path, value string) types.PatchOperation {
				return types.PatchOperation{Op: types.Op("replace"), Path: aws.String(path), Value: aws.String(value)}
			}
			update := func(patches ...types.PatchOperation) *apigateway.UpdateStageOutput {
				t.Helper()
				out, err := owner.UpdateStage(t.Context(), &apigateway.UpdateStageInput{RestApiId: api.Id, StageName: aws.String("live"), PatchOperations: patches})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			out := update(patch("/*/*/throttling/burstLimit", "2"), patch("/*/*/throttling/rateLimit", "1"), patch("/*/GET/throttling/burstLimit", "3"), patch("/~1pets/*/throttling/rateLimit", "2"), patch("/~1pets/GET/throttling/burstLimit", "1"))
			if out.MethodSettings["~1pets/GET"].ThrottlingBurstLimit != 1 || out.MethodSettings["*/*"].ThrottlingRateLimit != 1 {
				t.Fatalf("UpdateStage dropped configured throttles: %+v", out.MethodSettings)
			}
			invoke := func(method, path, key string, want int) {
				t.Helper()
				request, err := http.NewRequestWithContext(t.Context(), method, clients.server.URL+"/_stackd/execute-api/"+aws.ToString(api.Id)+"/live/"+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				if key != "" {
					request.Header.Set("X-Api-Key", key)
				}
				response, err := clients.server.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != want {
					t.Fatalf("%s %s status=%d want=%d body=%s", method, path, response.StatusCode, want, body)
				}
			}
			invoke("GET", "pets", "", 200)
			invoke("GET", "pets", "unknown-optional-key", 429)
			invoke("POST", "pets", "", 200)
			invoke("POST", "pets", "", 200)
			invoke("POST", "pets", "", 429)
			for range 3 {
				invoke("GET", "other", "", 200)
			}
			invoke("GET", "other", "", 429)
			if err := now.Advance(499 * time.Millisecond); err != nil {
				t.Fatal(err)
			}
			invoke("GET", "pets", "", 429)
			if err := now.Advance(time.Millisecond); err != nil {
				t.Fatal(err)
			}
			invoke("GET", "pets", "", 200)
			// Lower the live limit without rebuilding the deployment snapshot.
			update(patch("/~1pets/GET/throttling/burstLimit", "0"))
			if err := now.Advance(time.Hour); err != nil {
				t.Fatal(err)
			}
			invoke("GET", "pets", "", 429)
			for _, invalid := range []types.PatchOperation{patch("/~1pets/GET/throttling/burstLimit", "-1"), patch("/~1pets/GET/throttling/burstLimit", "1.5"), patch("/~1pets/GET/throttling/rateLimit", "-1"), patch("/~1pets/GET/throttling/rateLimit", "NaN"), patch("/~1pets/GET/throttling/rateLimit", "Infinity")} {
				_, err := owner.UpdateStage(t.Context(), &apigateway.UpdateStageInput{RestApiId: api.Id, StageName: aws.String("live"), PatchOperations: []types.PatchOperation{patch("/~1pets/GET/throttling/burstLimit", "5"), invalid}})
				assertAPIError(t, err, "BadRequestException")
			}
			clients = reopen()
			owner = client()
			retained, err := owner.GetStage(t.Context(), &apigateway.GetStageInput{RestApiId: api.Id, StageName: aws.String("live")})
			if err != nil {
				t.Fatal(err)
			}
			if retained.MethodSettings["~1pets/GET"].ThrottlingBurstLimit != 0 || retained.MethodSettings["~1pets/*"].ThrottlingRateLimit != 2 {
				t.Fatalf("stage throttle lost across restart or failed patch committed: %+v", retained.MethodSettings)
			}
			invoke("GET", "pets", "", 429)
			invoke("POST", "pets", "", 200)
			invoke("POST", "pets", "", 200)
			invoke("POST", "pets", "", 429)
			update(patch("/~1pets/GET/throttling/burstLimit", "2"), patch("/~1pets/GET/throttling/rateLimit", "0"))
			invoke("GET", "pets", "", 200)
			invoke("GET", "pets", "", 200)
			invoke("GET", "pets", "", 429)
			if err := now.Advance(time.Hour); err != nil {
				t.Fatal(err)
			}
			invoke("GET", "pets", "", 429)
			update(types.PatchOperation{Op: types.Op("remove"), Path: aws.String("/~1pets/GET")})
			invoke("GET", "pets", "", 200)
			invoke("GET", "pets", "", 200)
			invoke("GET", "pets", "", 200)
			invoke("GET", "pets", "", 429)
		})
	}
}
