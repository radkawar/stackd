package stackd_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
)

// An HTTP Task and a rule share the real Connection owner. Both miss its token
// cache after reopen; the workflow wins authorization while the rule retains
// its original event and retry budget rather than treating contention as a DLQ.
func TestEventBridgeAPIDestinationConcurrentOAuthConsumers(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var tokens atomic.Int64
			started := make(chan int64, 2)
			first, second := make(chan struct{}), make(chan struct{})
			var releaseFirst, releaseSecond sync.Once
			defer releaseFirst.Do(func() { close(first) })
			defer releaseSecond.Do(func() { close(second) })
			winnerReceived := make(chan struct{}, 1)
			provider := &apiDestinationReceiver{respond: func(w http.ResponseWriter, request *http.Request, captured apiDestinationRequest) {
				if captured.Path == "/oauth" {
					n := tokens.Add(1)
					var release <-chan struct{}
					if n == 2 {
						release = first
					} else if n == 3 {
						release = second
					}
					if release != nil {
						started <- n
						select {
						case <-release:
						case <-request.Context().Done():
							return
						}
					}
					apiDestinationToken(w, captured, fmt.Sprintf("concurrent-token-%d", n))
					return
				}
				if captured.Path == "/workflow" {
					winnerReceived <- struct{}{}
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"accepted":true}`))
			}}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newAPIDestinationCloud(t, backend, tls.Client())
			connection := r.connection(t, "concurrent-oauth", "OAUTH_CLIENT_CREDENTIALS", apiDestinationOAuth(tls.URL, "owned-client-secret"), "")
			destination := r.destination(t, "concurrent-oauth", aws.ToString(connection.ConnectionArn), tls.URL+"/rule", "POST", 100)
			role := r.role(t, "concurrent-oauth", destination)
			r.putTarget(t, "concurrent-oauth", r.target(t, "concurrent-oauth", destination, role, 0, 60, ""))
			identity := r.clients.iam(eventDeliveryAccount, "test", "")
			workflowRole, err := identity.CreateRole(t.Context(), &iam.CreateRoleInput{
				RoleName:                 aws.String("concurrent-oauth-workflow"),
				AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			putRolePolicy(t, identity, "concurrent-oauth-workflow", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"states:InvokeHTTPEndpoint","Resource":"*"},{"Effect":"Allow","Action":"events:RetrieveConnectionCredentials","Resource":%q},{"Effect":"Allow","Action":["secretsmanager:DescribeSecret","secretsmanager:GetSecretValue"],"Resource":%q}]}`, aws.ToString(connection.ConnectionArn), aws.ToString(connection.SecretArn)))
			workflows := func() *sfn.Client {
				return sfn.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1}, func(o *sfn.Options) {
					o.BaseEndpoint = aws.String(r.clients.server.URL)
					o.APIOptions = append(o.APIOptions, stepFunctionsLocalEndpoint)
				})
			}
			definition, _ := json.Marshal(map[string]any{"StartAt": "Request", "States": map[string]any{"Request": map[string]any{
				"Type": "Task", "Resource": "arn:aws:states:::http:invoke", "End": true,
				"Parameters": map[string]any{"ApiEndpoint": tls.URL + "/workflow", "Method": "POST", "Authentication": map[string]any{"ConnectionArn": aws.ToString(connection.ConnectionArn)}, "RequestBody": map[string]string{"consumer": "workflow"}},
			}}})
			machine, err := workflows().CreateStateMachine(t.Context(), &sfn.CreateStateMachineInput{Name: aws.String("concurrent-oauth"), RoleArn: workflowRole.Role.Arn, Type: sfntypes.StateMachineTypeExpress, Definition: aws.String(string(definition))})
			if err != nil {
				t.Fatal(err)
			}
			r.clients = r.reopen()
			type workflowResult struct {
				out *sfn.StartSyncExecutionOutput
				err error
			}
			workflowDone := make(chan workflowResult, 1)
			go func() {
				out, err := workflows().StartSyncExecution(t.Context(), &sfn.StartSyncExecutionInput{StateMachineArn: machine.StateMachineArn, Input: aws.String(`{}`)})
				workflowDone <- workflowResult{out, err}
			}()
			waitToken := func(want int64) {
				t.Helper()
				select {
				case n := <-started:
					if n != want {
						t.Fatalf("token request %d, want %d", n, want)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("concurrent consumer did not reach real OAuth receiver")
				}
			}
			waitToken(2)
			id := r.send(t, "concurrent-oauth", `{"consumer":"rule","retain":"original"}`)
			waitToken(3)
			releaseFirst.Do(func() { close(first) })
			select {
			case <-winnerReceived:
			case <-time.After(10 * time.Second):
				t.Fatal("winning workflow did not invoke its actual HTTPS endpoint")
			}
			releaseSecond.Do(func() { close(second) })
			r.drain(t)
			pending := r.delivery(t, id)
			apiDestinationState(t, pending, "pending", 0)
			for _, request := range provider.snapshot() {
				if request.Path == "/rule" {
					t.Fatal("losing token exchange sent an endpoint request before fresh authorization")
				}
			}
			select {
			case result := <-workflowDone:
				if result.err != nil || result.out.Status != sfntypes.SyncExecutionStatusSucceeded {
					t.Fatal("winning workflow failed", result.out, result.err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("winning workflow did not finish")
			}
			r.clients = r.reopen()
			r.advance(t, pending.Due)
			apiDestinationState(t, r.delivery(t, id), "delivered", 1)
			var delivered []apiDestinationRequest
			for _, request := range provider.snapshot() {
				if request.Path == "/rule" {
					delivered = append(delivered, request)
				}
			}
			if len(delivered) != 1 || delivered[0].Header.Get("Authorization") != "Bearer concurrent-token-4" {
				t.Fatal("retained rule did not use newly authorized credentials after reopen", delivered)
			}
			apiDestinationJSON(t, delivered[0].Body, map[string]any{"consumer": "rule", "retain": "original"})
		})
	}
}
