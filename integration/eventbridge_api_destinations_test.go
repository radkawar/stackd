package stackd_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	eventstore "stackd/storage/eventbridge"
)

const apiDestinationLinkedRole = "arn:aws:iam::" + eventDeliveryAccount + ":role/aws-service-role/apidestinations.events.amazonaws.com/AWSServiceRoleForAmazonEventBridgeApiDestinations"

// These are local HTTPS acceptance tests, not a replay or a claim about native
// delivery captures. Only the receiver is test code: signing, Connections,
// Secrets Manager, IAM/KMS, routing, retained work and HTTP transport are real.
type apiDestinationRequest struct {
	Method, Path, EscapedPath, Body string
	Query                           url.Values
	Header                          http.Header
}

type apiDestinationReceiver struct {
	mu       sync.Mutex
	requests []apiDestinationRequest
	respond  func(http.ResponseWriter, *http.Request, apiDestinationRequest)
}

func (p *apiDestinationReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body read failed", http.StatusBadRequest)
		return
	}
	request := apiDestinationRequest{Method: r.Method, Path: r.URL.Path, EscapedPath: r.URL.EscapedPath(), Query: r.URL.Query(), Header: r.Header.Clone(), Body: string(body)}
	p.mu.Lock()
	p.requests = append(p.requests, request)
	p.mu.Unlock()
	if p.respond != nil {
		p.respond(w, r, request)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *apiDestinationReceiver) snapshot() []apiDestinationRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]apiDestinationRequest(nil), p.requests...)
}

type apiDestinationCloud struct {
	clients    cloudClients
	cloud      *stackd.Stack
	repository eventstore.Repository
	source     *clock.Manual
	reopen     func() cloudClients
}

func newAPIDestinationCloud(t *testing.T, backend string, outbound *http.Client) *apiDestinationCloud {
	t.Helper()
	r := &apiDestinationCloud{source: clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))}
	r.clients, r.reopen = retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: r.source, OutboundHTTP: outbound}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		r.repository = config.Storage.EventBridge
		cloud, server := startPublicCloud(t, config)
		r.cloud = cloud
		return cloud, server
	})
	return r
}

func (r *apiDestinationCloud) events() *eventbridge.Client {
	return eventDeliveryClient(r.clients, eventDeliveryAccount)
}

func (r *apiDestinationCloud) call(t *testing.T, operation string, input any) any {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	out, err := awstest.CallSDK(t.Context(), r.events(), operation, body)
	if err != nil {
		t.Fatal(operation, err)
	}
	return out
}

func (r *apiDestinationCloud) drain(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	out, err := r.cloud.RunDueJobs(ctx, 1000)
	if err != nil || out.More {
		t.Fatal("drain current service time", out, err)
	}
}

func (r *apiDestinationCloud) advance(t *testing.T, at time.Time) {
	t.Helper()
	if at.Before(r.source.Now()) {
		t.Fatal("test attempted to move service time backwards")
	}
	advanceClock(t, r.source, at.Sub(r.source.Now()))
	r.drain(t)
}

func (r *apiDestinationCloud) connection(t *testing.T, name, kind string, auth map[string]any, key string) *eventbridge.DescribeConnectionOutput {
	t.Helper()
	input := map[string]any{"Name": name, "AuthorizationType": kind, "AuthParameters": auth}
	if key != "" {
		input["KmsKeyIdentifier"] = key
	}
	r.call(t, "CreateConnection", input)
	r.drain(t)
	out, err := r.events().DescribeConnection(t.Context(), &eventbridge.DescribeConnectionInput{Name: aws.String(name)})
	if err != nil || out.ConnectionState != "AUTHORIZED" {
		t.Fatal("connection did not authorize against its real provider", out, err)
	}
	return out
}

func apiDestinationBasic(password string) map[string]any {
	return map[string]any{"BasicAuthParameters": map[string]string{"Username": "owned-user", "Password": password}}
}

func apiDestinationOAuth(endpoint, secret string) map[string]any {
	return map[string]any{"OAuthParameters": map[string]any{
		"AuthorizationEndpoint": endpoint + "/oauth", "HttpMethod": "POST",
		"ClientParameters": map[string]string{"ClientID": "owned-client", "ClientSecret": secret},
		"OAuthHttpParameters": map[string]any{
			"HeaderParameters": []map[string]any{{"Key": "X-Token-Request", "Value": "owned-grant"}},
			"BodyParameters":   []map[string]any{{"Key": "scope", "Value": "owned-receiver"}},
		},
	}}
}

func (r *apiDestinationCloud) destination(t *testing.T, name, connection, endpoint, method string, rate int) string {
	t.Helper()
	out := r.call(t, "CreateApiDestination", map[string]any{"Name": name, "ConnectionArn": connection, "InvocationEndpoint": endpoint, "HttpMethod": method, "InvocationRateLimitPerSecond": rate}).(*eventbridge.CreateApiDestinationOutput)
	return aws.ToString(out.ApiDestinationArn)
}

func (r *apiDestinationCloud) role(t *testing.T, name, destination string) string {
	t.Helper()
	root := r.clients.iam(eventDeliveryAccount, "test", "")
	out, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	r.invokePolicy(t, name, destination, false)
	return aws.ToString(out.Role.Arn)
}

func (r *apiDestinationCloud) invokePolicy(t *testing.T, name, destination string, deny bool) {
	t.Helper()
	effect := "Allow"
	if deny {
		effect = "Deny"
	}
	// Explicit denials prove that execution roles are not credential owners.
	putRolePolicy(t, r.clients.iam(eventDeliveryAccount, "test", ""), name, fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":%q,"Action":"events:InvokeApiDestination","Resource":%q},{"Effect":"Deny","Action":["events:RetrieveConnectionCredentials","secretsmanager:*","kms:*"],"Resource":"*"}]}`, effect, destination))
}

func (r *apiDestinationCloud) target(t *testing.T, name, destination, role string, retries, age int32, dlq string) eventtypes.Target {
	t.Helper()
	_, err := r.events().PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String(name), EventPattern: aws.String(fmt.Sprintf(`{"source":[%q]}`, name))})
	if err != nil {
		t.Fatal(err)
	}
	target := eventtypes.Target{Id: aws.String("http"), Arn: aws.String(destination), RoleArn: aws.String(role), InputPath: aws.String("$.detail"), RetryPolicy: &eventtypes.RetryPolicy{MaximumRetryAttempts: aws.Int32(retries), MaximumEventAgeInSeconds: aws.Int32(age)}}
	if dlq != "" {
		target.DeadLetterConfig = &eventtypes.DeadLetterConfig{Arn: aws.String(dlq)}
	}
	return target
}

func (r *apiDestinationCloud) putTarget(t *testing.T, name string, target eventtypes.Target) {
	t.Helper()
	out, err := r.events().PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String(name), Targets: []eventtypes.Target{target}})
	if err != nil || out.FailedEntryCount != 0 {
		t.Fatal("register HTTPS target", out, err)
	}
}

func (r *apiDestinationCloud) send(t *testing.T, rule, detail string) string {
	t.Helper()
	out, err := r.events().PutEvents(t.Context(), &eventbridge.PutEventsInput{Entries: []eventtypes.PutEventsRequestEntry{{Source: aws.String(rule), DetailType: aws.String("owned-http-event"), Detail: aws.String(detail)}}})
	if err != nil || out.FailedEntryCount != 0 || len(out.Entries) != 1 || aws.ToString(out.Entries[0].EventId) == "" {
		t.Fatal("admit HTTPS event", out, err)
	}
	return aws.ToString(out.Entries[0].EventId)
}

func (r *apiDestinationCloud) delivery(t *testing.T, eventID string) eventstore.DeliveryRecord {
	t.Helper()
	var found []eventstore.DeliveryRecord
	err := r.repository.View(t.Context(), func(reader eventstore.Reader) error {
		rows, err := reader.EventDeliveries(eventID)
		for _, row := range rows {
			if !row.BusProcessing && row.TargetID == "http" {
				found = append(found, row)
			}
		}
		return err
	})
	if err != nil || len(found) != 1 {
		t.Fatal("expected one retained HTTP delivery", found, err)
	}
	return found[0]
}

func apiDestinationState(t *testing.T, row eventstore.DeliveryRecord, state string, attempts int) {
	t.Helper()
	if row.State != state || row.Attempts != attempts {
		t.Fatalf("delivery state=%s attempts=%d, want %s/%d; code=%s diagnosis=%s", row.State, row.Attempts, state, attempts, row.LastErrorCode, row.LastErrorMessage)
	}
}

func apiDestinationJSON(t *testing.T, body string, want any) {
	t.Helper()
	var got any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal("receiver did not get JSON", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("actual HTTPS payload=%#v, want %#v", got, want)
	}
}

func apiDestinationToken(w http.ResponseWriter, request apiDestinationRequest, token string) {
	form, err := url.ParseQuery(request.Body)
	if err != nil || request.Method != "POST" || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || request.Header.Get("X-Token-Request") != "owned-grant" || !reflect.DeepEqual(form, url.Values{"client_id": {"owned-client"}, "client_secret": {"owned-client-secret"}, "grant_type": {"client_credentials"}, "scope": {"owned-receiver"}}) {
		http.Error(w, "invalid client credentials or grant", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":3600}`, token)
}

func TestEventBridgeAPIDestinationHTTPSComposition(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var tokens atomic.Int64
			provider := &apiDestinationReceiver{respond: func(w http.ResponseWriter, request *http.Request, captured apiDestinationRequest) {
				if captured.Path == "/oauth" {
					tokens.Add(1)
					apiDestinationToken(w, captured, "owned-token")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newAPIDestinationCloud(t, backend, tls.Client())
			for _, kind := range []string{"BASIC", "API_KEY", "OAUTH_CLIENT_CREDENTIALS"} {
				t.Run(kind, func(t *testing.T) {
					name := "https-" + strings.ToLower(kind)
					auth := apiDestinationBasic("owned-password")
					header, credential := "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("owned-user:owned-password"))
					if kind == "API_KEY" {
						auth = map[string]any{"ApiKeyAuthParameters": map[string]string{"ApiKeyName": "X-API-Key", "ApiKeyValue": "owned-api-key"}}
						header, credential = "X-API-Key", "owned-api-key"
					} else if kind == "OAUTH_CLIENT_CREDENTIALS" {
						auth = apiDestinationOAuth(tls.URL, "owned-client-secret")
						credential = "Bearer owned-token"
					}
					auth["InvocationHttpParameters"] = map[string]any{
						"HeaderParameters":      []map[string]any{{"Key": "x-precedence", "Value": "connection-header", "IsValueSecret": true}},
						"QueryStringParameters": []map[string]any{{"Key": "shared", "Value": "connection query"}},
						"BodyParameters":        []map[string]any{{"Key": "shared", "Value": "connection-body"}, {"Key": "credential-field", "Value": "owned-body-secret", "IsValueSecret": true}},
					}
					connection := r.connection(t, name, kind, auth, "")
					destination := r.destination(t, name, aws.ToString(connection.ConnectionArn), tls.URL+"/receive/*/item/*/end/*?shared=endpoint&endpoint=retained", "PATCH", 100)
					role := r.role(t, name, destination)
					target := r.target(t, name, destination, role, 0, 60, "")
					target.HttpParameters = &eventtypes.HttpParameters{PathParameterValues: []string{"space value", "*", "slash/value"}, QueryStringParameters: map[string]string{"shared": "target-query", "target": "target query"}, HeaderParameters: map[string]string{"X-Precedence": "target-header", "X-Target": "target-only", header: "must-not-win"}}
					if kind == "BASIC" {
						target.InputPath = nil
						target.InputTransformer = &eventtypes.InputTransformer{InputPathsMap: map[string]string{"value": "$.detail.value"}, InputTemplate: aws.String(`{"selected":<value>,"shared":"transformer"}`)}
					}
					r.putTarget(t, name, target)
					// Both typed target parameters and connection secrets cross reopen.
					r.clients = r.reopen()
					before := len(provider.snapshot())
					id := r.send(t, name, `{"value":"selected-value","shared":"event"}`)
					r.drain(t)
					apiDestinationState(t, r.delivery(t, id), "delivered", 1)
					var delivered []apiDestinationRequest
					for _, request := range provider.snapshot()[before:] {
						if request.Path != "/oauth" {
							delivered = append(delivered, request)
						}
					}
					if len(delivered) != 1 {
						t.Fatalf("expected one actual HTTPS invocation, got %d", len(delivered))
					}
					got := delivered[0]
					if got.Method != "PATCH" || got.EscapedPath != "/receive/space%20value/item/%2A/end/slash%2Fvalue" || !reflect.DeepEqual(got.Query, url.Values{"shared": {"connection query"}, "endpoint": {"retained"}, "target": {"target query"}}) {
						t.Fatalf("HTTPS method/path/query merge changed: %s %s %v", got.Method, got.EscapedPath, got.Query)
					}
					if !reflect.DeepEqual(got.Header.Values(header), []string{credential}) || !reflect.DeepEqual(got.Header.Values("X-Precedence"), []string{"connection-header"}) || got.Header.Get("X-Target") != "target-only" || got.Header.Get("Content-Type") != "application/json; charset=utf-8" {
						t.Fatal("actual HTTPS credentials/header precedence/content type differ")
					}
					want := map[string]any{"value": "selected-value", "shared": "connection-body", "credential-field": "owned-body-secret"}
					if kind == "BASIC" {
						delete(want, "value")
						want["selected"] = "selected-value"
					}
					apiDestinationJSON(t, got.Body, want)
				})
			}
			if tokens.Load() != 2 {
				t.Fatalf("OAuth creation and reopened invocation must each authenticate against provider, got %d token calls", tokens.Load())
			}
		})
	}
}

func (r *apiDestinationCloud) secretClient() *secretsmanager.Client {
	return secretsmanager.New(secretsmanager.Options{Region: "us-east-1", BaseEndpoint: aws.String(r.clients.server.URL), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1, Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", "")})
}

func apiDestinationKeyPolicy(deny bool) string {
	extra := ""
	if deny {
		extra = fmt.Sprintf(`,{"Effect":"Deny","Principal":{"AWS":%q},"Action":"kms:Decrypt","Resource":"*"}`, apiDestinationLinkedRole)
	}
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"AWS":%q},"Action":["kms:GenerateDataKey","kms:Decrypt","kms:DescribeKey"],"Resource":"*"}%s]}`, eventDeliveryAccount, apiDestinationLinkedRole, extra)
}

func TestEventBridgeAPIDestinationCurrentAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			provider := &apiDestinationReceiver{}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newAPIDestinationCloud(t, backend, tls.Client())
			// Provision the linked role before a KMS policy names it.
			r.connection(t, "bootstrap", "BASIC", apiDestinationBasic("bootstrap-password"), "")
			keys := r.clients.kms(eventDeliveryAccount, "test", "")
			key, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{Policy: aws.String(apiDestinationKeyPolicy(false))})
			if err != nil {
				t.Fatal(err)
			}
			connection := r.connection(t, "authority", "BASIC", apiDestinationBasic("owned-password"), aws.ToString(key.KeyMetadata.Arn))
			destination := r.destination(t, "authority", aws.ToString(connection.ConnectionArn), tls.URL+"/authority", "POST", 100)
			role := r.role(t, "authority", destination)
			target := r.target(t, "authority", destination, role, 0, 60, "")
			r.putTarget(t, "authority", target)
			check := func(allowed bool, code string) {
				t.Helper()
				before := len(provider.snapshot())
				id := r.send(t, "authority", `{"private":"owned-payload"}`)
				r.drain(t)
				row := r.delivery(t, id)
				if allowed {
					apiDestinationState(t, row, "delivered", 1)
					if len(provider.snapshot()) != before+1 {
						t.Fatal("restored authority did not issue exactly one request")
					}
				} else {
					apiDestinationState(t, row, "failed", 1)
					if len(provider.snapshot()) != before || row.LastErrorCode == "" || row.LastErrorMessage == "" || code != "" && row.LastErrorCode != code {
						t.Fatalf("revoked authority reached network or lost diagnosis: code=%s message=%s", row.LastErrorCode, row.LastErrorMessage)
					}
					for _, private := range []string{"owned-password", "owned-payload", "Basic "} {
						if strings.Contains(row.LastErrorMessage, private) {
							t.Fatal("delivery diagnosis leaked credentials or payload")
						}
					}
				}
			}
			check(true, "")
			root := r.clients.iam(eventDeliveryAccount, "test", "")
			_, access, secret := r.clients.user(t, eventDeliveryAccount, "target-operator")
			putUserPolicy(t, root, "target-operator", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"events:PutTargets","Resource":"*"},{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}]}`)
			operator := eventbridge.New(eventbridge.Options{Region: "us-east-1", BaseEndpoint: aws.String(r.clients.server.URL), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1, Credentials: credentials.NewStaticCredentialsProvider(access, secret, "")})
			deniedTarget := target
			deniedTarget.Id = aws.String("must-not-be-admitted")
			_, err = operator.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String("authority"), Targets: []eventtypes.Target{deniedTarget}})
			assertAPIError(t, err, "AccessDeniedException")
			listed, err := r.events().ListTargetsByRule(t.Context(), &eventbridge.ListTargetsByRuleInput{Rule: aws.String("authority")})
			if err != nil || len(listed.Targets) != 1 || aws.ToString(listed.Targets[0].Id) != "http" {
				t.Fatal("PassRole denial mutated target membership", listed, err)
			}
			r.invokePolicy(t, "authority", destination, true)
			check(false, "NO_PERMISSIONS")
			r.invokePolicy(t, "authority", destination, false)
			check(true, "")
			secrets := r.secretClient()
			_, err = secrets.PutResourcePolicy(t.Context(), &secretsmanager.PutResourcePolicyInput{SecretId: connection.SecretArn, ResourcePolicy: aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":%q},"Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`, apiDestinationLinkedRole))})
			// Managed credentials remain owned by EventBridge: public secret
			// policy writes cannot be used to mutate the linked role's access.
			assertAPIError(t, err, "InvalidRequestException")
			check(true, "")
			if _, err := keys.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: key.KeyMetadata.KeyId, PolicyName: aws.String("default"), Policy: aws.String(apiDestinationKeyPolicy(true))}); err != nil {
				t.Fatal(err)
			}
			check(false, "")
			if _, err := keys.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: key.KeyMetadata.KeyId, PolicyName: aws.String("default"), Policy: aws.String(apiDestinationKeyPolicy(false))}); err != nil {
				t.Fatal(err)
			}
			check(true, "")
			if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: key.KeyMetadata.KeyId}); err != nil {
				t.Fatal(err)
			}
			check(false, "")
			if _, err := keys.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: key.KeyMetadata.KeyId}); err != nil {
				t.Fatal(err)
			}
			check(true, "")
		})
	}
}

func TestEventBridgeAPIDestinationHTTPClassification(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var counts sync.Map
			provider := &apiDestinationReceiver{respond: func(w http.ResponseWriter, request *http.Request, captured apiDestinationRequest) {
				parts := strings.Split(strings.Trim(captured.Path, "/"), "/")
				if len(parts) != 2 {
					http.Error(w, "unexpected redirect or route", http.StatusBadRequest)
					return
				}
				counter, _ := counts.LoadOrStore(captured.Path, new(atomic.Int64))
				if counter.(*atomic.Int64).Add(1) > 1 {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				status, _ := strconv.Atoi(parts[0])
				if retryAfter := captured.Query.Get("retry-after"); retryAfter != "" {
					w.Header().Set("Retry-After", retryAfter)
				}
				if status == http.StatusFound {
					w.Header().Set("Location", "/must-not-follow")
				}
				w.WriteHeader(status)
				io.WriteString(w, "private-provider-response-must-not-be-retained")
			}}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newAPIDestinationCloud(t, backend, tls.Client())
			connection := r.connection(t, "classification", "BASIC", apiDestinationBasic("owned-password"), "")
			for _, tc := range []struct {
				name       string
				status     int
				retry      bool
				retryAfter string
				minDelay   time.Duration
			}{
				{name: "bad-request", status: 400},
				{name: "redirect", status: 302},
				{name: "unauthorized", status: 401, retry: true},
				{name: "proxy-auth", status: 407, retry: true},
				{name: "conflict", status: 409, retry: true},
				{name: "throttled", status: 429, retry: true},
				{name: "unavailable", status: 503, retry: true},
				{name: "positive-retry-after", status: 503, retry: true, retryAfter: "7", minDelay: 7 * time.Second},
				{name: "date-retry-after", status: 429, retry: true, retryAfter: "future-date", minDelay: 9 * time.Second},
				{name: "past-date-retry-after", status: 503, retry: true, retryAfter: "past-date"},
				{name: "negative-retry-after", status: 503, retryAfter: "-1"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					retryAfter := tc.retryAfter
					minimumDue := r.source.Now().Add(tc.minDelay)
					if retryAfter == "future-date" {
						minimumDue = minimumDue.Truncate(time.Second)
						retryAfter = minimumDue.Format(http.TimeFormat)
					} else if retryAfter == "past-date" {
						retryAfter = r.source.Now().Add(-time.Minute).Format(http.TimeFormat)
					}
					endpoint := tls.URL + fmt.Sprintf("/%d/%s", tc.status, tc.name)
					if retryAfter != "" {
						endpoint += "?" + url.Values{"retry-after": {retryAfter}}.Encode()
					}
					destination := r.destination(t, tc.name, aws.ToString(connection.ConnectionArn), endpoint, "POST", 100)
					role := r.role(t, tc.name, destination)
					r.putTarget(t, tc.name, r.target(t, tc.name, destination, role, 2, 60, ""))
					accepted := r.source.Now()
					before := len(provider.snapshot())
					id := r.send(t, tc.name, `{"case":"classification"}`)
					r.drain(t)
					row := r.delivery(t, id)
					wantState := "failed"
					if tc.retry {
						wantState = "pending"
					}
					apiDestinationState(t, row, wantState, 1)
					if row.LastErrorCode != "ERROR_FROM_TARGET" || !strings.Contains(row.LastErrorMessage, strconv.Itoa(tc.status)) || strings.Contains(row.LastErrorMessage, "private-provider") || len(provider.snapshot()) != before+1 {
						t.Fatalf("HTTP status classification or sanitized diagnosis changed: %+v", row)
					}
					if !tc.retry {
						r.advance(t, accepted.Add(time.Minute))
						apiDestinationState(t, r.delivery(t, id), "failed", 1)
						if len(provider.snapshot()) != before+1 {
							t.Fatal("terminal HTTP status retried or redirect was followed")
						}
						return
					}
					if !row.Due.After(accepted) || row.Due.Before(minimumDue) || !row.Due.Before(accepted.Add(time.Minute)) {
						t.Fatalf("retry deadline ignored service time/Retry-After: accepted=%s due=%s", accepted, row.Due)
					}
					if tc.name == "unavailable" {
						r.clients = r.reopen()
						reopened := r.delivery(t, id)
						if !reopened.Due.Equal(row.Due) || reopened.Attempts != row.Attempts || reopened.LastErrorCode != row.LastErrorCode || reopened.LastErrorMessage != row.LastErrorMessage {
							t.Fatal("pending HTTP retry changed across service/database reopen")
						}
					}
					r.advance(t, row.Due.Add(-time.Nanosecond))
					apiDestinationState(t, r.delivery(t, id), "pending", 1)
					if len(provider.snapshot()) != before+1 {
						t.Fatal("retry ran before its retained deadline")
					}
					r.advance(t, row.Due)
					apiDestinationState(t, r.delivery(t, id), "delivered", 2)
					if len(provider.snapshot()) != before+2 {
						t.Fatal("deadline did not produce exactly one real retry")
					}
				})
			}
		})
	}
}

func (r *apiDestinationCloud) dlq(t *testing.T, rule string) (string, string) {
	t.Helper()
	queues := r.clients.sqs(eventDeliveryAccount, "test", "")
	out, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String(rule + "-dlq")})
	if err != nil {
		t.Fatal(err)
	}
	arn := "arn:aws:sqs:us-east-1:" + eventDeliveryAccount + ":" + rule + "-dlq"
	ruleARN := "arn:aws:events:us-east-1:" + eventDeliveryAccount + ":rule/" + rule
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, arn, ruleARN)
	if _, err := queues.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: out.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
		t.Fatal(err)
	}
	return aws.ToString(out.QueueUrl), arn
}

func (r *apiDestinationCloud) assertDLQ(t *testing.T, queue, rule, destination, exhausted, retries string, detail any) {
	t.Helper()
	queues := r.clients.sqs(eventDeliveryAccount, "test", "")
	out, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: aws.String(queue), MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"}})
	if err != nil || len(out.Messages) != 1 {
		t.Fatal("expected exactly one terminal DLQ event", out, err)
	}
	message := out.Messages[0]
	// InputPath selects $.detail for these targets. The shared DLQ contract
	// preserves that accepted target payload rather than rebuilding an envelope.
	apiDestinationJSON(t, aws.ToString(message.Body), detail)
	assertEventDeliveryAttributes(t, message.MessageAttributes, map[string]string{
		"RULE_ARN":   "arn:aws:events:us-east-1:" + eventDeliveryAccount + ":rule/" + rule,
		"TARGET_ARN": destination, "ERROR_CODE": "ERROR_FROM_TARGET", "ERROR_MESSAGE": "sanitized target diagnosis",
		"EXHAUSTED_RETRY_CONDITION": exhausted, "RETRY_ATTEMPTS": retries,
	})
	diagnosis := aws.ToString(message.MessageAttributes["ERROR_MESSAGE"].StringValue)
	if diagnosis == "" || strings.Contains(diagnosis, "owned-password") || strings.Contains(diagnosis, "private-provider") {
		t.Fatal("DLQ diagnosis absent or exposes private HTTP material")
	}
	if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: aws.String(queue), ReceiptHandle: message.ReceiptHandle}); err != nil {
		t.Fatal(err)
	}
}

func TestEventBridgeAPIDestinationRetryLimitsAndDeadLetters(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			provider := &apiDestinationReceiver{respond: func(w http.ResponseWriter, request *http.Request, captured apiDestinationRequest) {
				if captured.Path == "/max-age" {
					w.Header().Set("Retry-After", "120")
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			}}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newAPIDestinationCloud(t, backend, tls.Client())
			connection := r.connection(t, "retry-limits", "BASIC", apiDestinationBasic("owned-password"), "")
			for _, name := range []string{"max-retries", "max-age"} {
				t.Run(name, func(t *testing.T) {
					destination := r.destination(t, name, aws.ToString(connection.ConnectionArn), tls.URL+"/"+name, "POST", 100)
					role := r.role(t, name, destination)
					queue, dlq := r.dlq(t, name)
					r.putTarget(t, name, r.target(t, name, destination, role, 1, 60, dlq))
					before := len(provider.snapshot())
					accepted := r.source.Now()
					id := r.send(t, name, `{"retain":"original-event"}`)
					r.drain(t)
					row := r.delivery(t, id)
					apiDestinationState(t, row, "pending", 1)
					if name == "max-age" && !row.Due.Equal(accepted.Add(time.Minute)) {
						t.Fatal("long Retry-After was not capped at maximum event age")
					}
					r.clients = r.reopen()
					retained := r.delivery(t, id)
					if !retained.Due.Equal(row.Due) || retained.Attempts != 1 {
						t.Fatal("pending exhaustion deadline did not survive reopen")
					}
					r.advance(t, row.Due)
					attempts, condition, retries := 2, "MaximumRetryAttempts", "1"
					if name == "max-age" {
						attempts, condition, retries = 1, "MaximumEventAgeInSeconds", "0"
					}
					row = r.delivery(t, id)
					apiDestinationState(t, row, "dead-lettered", attempts)
					if row.ExhaustedRetryCondition != condition || len(provider.snapshot()) != before+attempts {
						t.Fatal("HTTP retry/age exhaustion consumed the wrong number of attempts", row)
					}
					r.assertDLQ(t, queue, name, destination, condition, retries, map[string]any{"retain": "original-event"})
					r.advance(t, r.source.Now().Add(time.Minute))
					if len(provider.snapshot()) != before+attempts {
						t.Fatal("terminal dead-lettered delivery resumed")
					}
				})
			}
		})
	}
}

func (r *apiDestinationCloud) metric(t *testing.T, rule, metric string, start time.Time) float64 {
	t.Helper()
	client := cloudwatch.New(cloudwatch.Options{Region: "us-east-1", BaseEndpoint: aws.String(r.clients.server.URL), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1, Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", "")})
	out, err := client.GetMetricStatistics(t.Context(), &cloudwatch.GetMetricStatisticsInput{
		Namespace: aws.String("AWS/Events"), MetricName: aws.String(metric),
		Dimensions: []cwtypes.Dimension{{Name: aws.String("RuleName"), Value: aws.String(rule)}},
		StartTime:  aws.Time(start), EndTime: aws.Time(r.source.Now()), Period: aws.Int32(60),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticSum, cwtypes.StatisticSampleCount, cwtypes.StatisticMinimum, cwtypes.StatisticMaximum, cwtypes.StatisticAverage},
	})
	if err != nil {
		t.Fatal(err)
	}
	totals, unit := ebMetricStatistics(t, out.Datapoints)
	if len(out.Datapoints) != 0 && unit != cwtypes.StandardUnitCount {
		t.Fatal("invocation metric did not report Count", unit)
	}
	return totals[0]
}

func TestEventBridgeAPIDestinationRateAdmissionDeadlinesAndMetrics(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			provider := &apiDestinationReceiver{}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newAPIDestinationCloud(t, backend, tls.Client())
			connection := r.connection(t, "rate", "BASIC", apiDestinationBasic("owned-password"), "")
			destination := r.destination(t, "rate", aws.ToString(connection.ConnectionArn), tls.URL+"/rate", "POST", 1)
			role := r.role(t, "rate", destination)
			queue, dlq := r.dlq(t, "rate")
			r.putTarget(t, "rate", r.target(t, "rate", destination, role, 0, 60, dlq))
			start := r.source.Now()
			ids := []string{r.send(t, "rate", `{"ordinal":1}`), r.send(t, "rate", `{"ordinal":2}`), r.send(t, "rate", `{"ordinal":3}`)}
			r.drain(t)
			if len(provider.snapshot()) != 1 {
				t.Fatal("one-per-second destination admitted an initial burst")
			}
			var pending []string
			for _, id := range ids {
				row := r.delivery(t, id)
				if row.State == "delivered" {
					apiDestinationState(t, row, "delivered", 1)
				} else {
					apiDestinationState(t, row, "pending", 0)
					if !row.Due.Equal(start.Add(time.Second)) {
						t.Fatal("rate admission did not retain its next window deadline", row.Due)
					}
					pending = append(pending, id)
				}
			}
			if len(pending) != 2 {
				t.Fatal("rate-limited work was discarded or counted as a failed attempt")
			}
			r.clients = r.reopen()
			r.drain(t)
			if len(provider.snapshot()) != 1 {
				t.Fatal("restart forgot the current rate window")
			}
			for _, id := range pending {
				apiDestinationState(t, r.delivery(t, id), "pending", 0)
			}
			r.advance(t, start.Add(time.Second))
			if len(provider.snapshot()) != 2 {
				t.Fatal("next rate window did not release exactly one request")
			}
			var expired string
			for _, id := range pending {
				row := r.delivery(t, id)
				if row.State == "pending" {
					apiDestinationState(t, row, "pending", 0)
					if !row.Due.Equal(start.Add(2 * time.Second)) {
						t.Fatal("second rate admission lost its deadline")
					}
					expired = id
				} else {
					apiDestinationState(t, row, "delivered", 1)
				}
			}
			if expired == "" {
				t.Fatal("destination exceeded the second rate window")
			}
			r.advance(t, start.Add(time.Minute))
			row := r.delivery(t, expired)
			apiDestinationState(t, row, "dead-lettered", 0)
			if row.ExhaustedRetryCondition != "MaximumEventAgeInSeconds" || len(provider.snapshot()) != 2 {
				t.Fatal("rate-waiting event was invoked after its maximum age")
			}
			var detail any
			for i, id := range ids {
				if id == expired {
					detail = map[string]any{"ordinal": float64(i + 1)}
				}
			}
			r.assertDLQ(t, queue, "rate", destination, "MaximumEventAgeInSeconds", "0", detail)
			r.advance(t, start.Add(2*time.Minute))
			for name, want := range map[string]float64{
				"InvocationAttempts": 2, "SuccessfulInvocationAttempts": 2,
				"RetryInvocationAttempts": 0, "Invocations": 3,
				"FailedInvocations": 1, "InvocationsSentToDlq": 1,
			} {
				if got := r.metric(t, "rate", name, start); got != want {
					t.Errorf("%s=%v, want %v; admission/expiry must not invent network attempts", name, got, want)
				}
			}
		})
	}
}

func TestEventBridgeAPIDestinationIncarnations(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			provider := &apiDestinationReceiver{respond: func(w http.ResponseWriter, request *http.Request, captured apiDestinationRequest) {
				if captured.Path == "/old" || captured.Path == "/pending-delete" {
					w.Header().Set("Retry-After", "5")
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newAPIDestinationCloud(t, backend, tls.Client())
			connection := r.connection(t, "incarnation", "BASIC", apiDestinationBasic("old-password"), "")
			destination := r.destination(t, "incarnation", aws.ToString(connection.ConnectionArn), tls.URL+"/old", "POST", 100)
			// This narrowly scoped wildcard intentionally permits replacement
			// destination IDs, leaving incarnation fencing—not IAM—to reject old work.
			resource := "arn:aws:events:us-east-1:" + eventDeliveryAccount + ":api-destination/incarnation/*"
			role := r.role(t, "incarnation", resource)
			target := r.target(t, "incarnation", destination, role, 2, 60, "")
			r.putTarget(t, "incarnation", target)
			id := r.send(t, "incarnation", `{"version":"retained-payload"}`)
			r.drain(t)
			pending := r.delivery(t, id)
			apiDestinationState(t, pending, "pending", 1)
			r.call(t, "UpdateConnection", map[string]any{"Name": "incarnation", "AuthorizationType": "BASIC", "AuthParameters": apiDestinationBasic("updated-password")})
			r.call(t, "UpdateApiDestination", map[string]any{"Name": "incarnation", "InvocationEndpoint": tls.URL + "/updated", "HttpMethod": "PATCH"})
			r.clients = r.reopen()
			r.advance(t, pending.Due)
			apiDestinationState(t, r.delivery(t, id), "delivered", 2)
			requests := provider.snapshot()
			if len(requests) != 2 || requests[1].Path != "/updated" || requests[1].Method != "PATCH" || requests[1].Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("owned-user:updated-password")) {
				t.Fatal("retained retry did not use current destination and Connection credentials")
			}
			apiDestinationJSON(t, requests[1].Body, map[string]any{"version": "retained-payload"})
			r.call(t, "UpdateApiDestination", map[string]any{"Name": "incarnation", "InvocationEndpoint": tls.URL + "/pending-delete"})
			oldEvent := r.send(t, "incarnation", `{"version":"old-destination"}`)
			r.drain(t)
			oldWork := r.delivery(t, oldEvent)
			apiDestinationState(t, oldWork, "pending", 1)
			r.call(t, "DeleteApiDestination", map[string]string{"Name": "incarnation"})
			replacement := r.destination(t, "incarnation", aws.ToString(connection.ConnectionArn), tls.URL+"/replacement", "PUT", 100)
			if replacement == destination {
				t.Fatal("destination recreation reused an ARN incarnation")
			}
			before := len(provider.snapshot())
			r.advance(t, oldWork.Due)
			stale := r.delivery(t, oldEvent)
			apiDestinationState(t, stale, "failed", 2)
			if stale.LastErrorCode != "NO_RESOURCE" || len(provider.snapshot()) != before {
				t.Fatal("retained old destination ARN rebound to a replacement")
			}
			target.Arn = aws.String(replacement)
			r.putTarget(t, "incarnation", target)
			currentEvent := r.send(t, "incarnation", `{"version":"new-destination"}`)
			r.drain(t)
			apiDestinationState(t, r.delivery(t, currentEvent), "delivered", 1)
			if got := provider.snapshot(); len(got) != before+1 || got[len(got)-1].Path != "/replacement" || got[len(got)-1].Method != "PUT" {
				t.Fatal("explicitly rebound target did not invoke replacement")
			}
			r.call(t, "DeleteConnection", map[string]string{"Name": "incarnation"})
			r.advance(t, r.source.Now().Add(time.Second))
			recreated := r.connection(t, "incarnation", "BASIC", apiDestinationBasic("recreated-password"), "")
			if aws.ToString(recreated.ConnectionArn) == aws.ToString(connection.ConnectionArn) {
				t.Fatal("Connection recreation reused an ARN incarnation")
			}
			before = len(provider.snapshot())
			staleConnectionEvent := r.send(t, "incarnation", `{"version":"old-connection"}`)
			r.drain(t)
			stale = r.delivery(t, staleConnectionEvent)
			apiDestinationState(t, stale, "failed", 1)
			if stale.LastErrorCode != "NO_RESOURCE" || len(provider.snapshot()) != before {
				t.Fatal("destination's old Connection ARN rebound to a new secret owner")
			}
			r.call(t, "UpdateApiDestination", map[string]any{"Name": "incarnation", "ConnectionArn": aws.ToString(recreated.ConnectionArn)})
			recovered := r.send(t, "incarnation", `{"version":"new-connection"}`)
			r.drain(t)
			apiDestinationState(t, r.delivery(t, recovered), "delivered", 1)
			requests = provider.snapshot()
			if len(requests) != before+1 || requests[len(requests)-1].Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("owned-user:recreated-password")) {
				t.Fatal("destination did not recover with explicitly rebound credentials")
			}
		})
	}
}

func TestEventBridgeAPIDestinationOAuthRefreshRetry(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var tokens, invocations atomic.Int64
			provider := &apiDestinationReceiver{respond: func(w http.ResponseWriter, request *http.Request, captured apiDestinationRequest) {
				if captured.Path == "/oauth" {
					apiDestinationToken(w, captured, fmt.Sprintf("owned-token-%d", tokens.Add(1)))
					return
				}
				invocations.Add(1)
				switch captured.Header.Get("Authorization") {
				case "Bearer owned-token-1":
					w.Header().Set("Retry-After", "6")
					w.WriteHeader(http.StatusUnauthorized)
				case "Bearer owned-token-2":
					w.WriteHeader(http.StatusNoContent)
				default:
					w.WriteHeader(http.StatusBadRequest)
				}
			}}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newAPIDestinationCloud(t, backend, tls.Client())
			connection := r.connection(t, "oauth-retry", "OAUTH_CLIENT_CREDENTIALS", apiDestinationOAuth(tls.URL, "owned-client-secret"), "")
			destination := r.destination(t, "oauth-retry", aws.ToString(connection.ConnectionArn), tls.URL+"/receive", "POST", 100)
			role := r.role(t, "oauth-retry", destination)
			r.putTarget(t, "oauth-retry", r.target(t, "oauth-retry", destination, role, 2, 60, ""))
			accepted := r.source.Now()
			id := r.send(t, "oauth-retry", `{"oauth":"refresh"}`)
			r.drain(t)
			pending := r.delivery(t, id)
			apiDestinationState(t, pending, "pending", 1)
			if invocations.Load() != 1 || tokens.Load() != 2 || !pending.Due.Equal(accepted.Add(6*time.Second)) {
				t.Fatal("OAuth refresh became an unmetered inline invocation or lost Retry-After", pending)
			}
			r.advance(t, pending.Due)
			apiDestinationState(t, r.delivery(t, id), "delivered", 2)
			if invocations.Load() != 2 || tokens.Load() != 2 {
				t.Fatal("scheduled retry did not use the actual refreshed provider token")
			}
			r.advance(t, accepted.Add(time.Minute))
			for name, want := range map[string]float64{"InvocationAttempts": 2, "RetryInvocationAttempts": 1, "SuccessfulInvocationAttempts": 1, "FailedInvocations": 0} {
				if got := r.metric(t, "oauth-retry", name, accepted); got != want {
					t.Errorf("%s=%v want %v; OAuth exchange must not count as destination invocation", name, got, want)
				}
			}
		})
	}
}

func TestEventBridgeAPIDestinationOAuthRefreshFencing(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, mutation := range []string{"connection", "destination", "invoke-authority", "kms-authority"} {
			t.Run(backend+"/"+mutation, func(t *testing.T) {
				var tokens atomic.Int64
				refreshStarted := make(chan struct{})
				releaseRefresh := make(chan struct{})
				var release sync.Once
				t.Cleanup(func() { release.Do(func() { close(releaseRefresh) }) })
				provider := &apiDestinationReceiver{respond: func(w http.ResponseWriter, request *http.Request, captured apiDestinationRequest) {
					if captured.Path == "/oauth" {
						n := tokens.Add(1)
						if n == 2 {
							close(refreshStarted)
							select {
							case <-releaseRefresh:
								apiDestinationToken(w, captured, "must-not-cache-stale-token")
							case <-request.Context().Done():
							}
							return
						}
						apiDestinationToken(w, captured, fmt.Sprintf("owned-token-%d", n))
						return
					}
					switch captured.Header.Get("Authorization") {
					case "Bearer owned-token-1":
						w.WriteHeader(http.StatusUnauthorized)
					case "Bearer owned-token-3", "Basic " + base64.StdEncoding.EncodeToString([]byte("owned-user:replacement-password")):
						w.WriteHeader(http.StatusNoContent)
					default:
						w.WriteHeader(http.StatusBadRequest)
					}
				}}
				tls := httptest.NewTLSServer(provider)
				t.Cleanup(tls.Close)
				r := newAPIDestinationCloud(t, backend, tls.Client())
				var keyID string
				if mutation == "kms-authority" {
					r.connection(t, "bootstrap", "BASIC", apiDestinationBasic("bootstrap-password"), "")
					key, err := r.clients.kms(eventDeliveryAccount, "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{Policy: aws.String(apiDestinationKeyPolicy(false))})
					if err != nil {
						t.Fatal(err)
					}
					keyID = aws.ToString(key.KeyMetadata.Arn)
				}
				connection := r.connection(t, "oauth-fence", "OAUTH_CLIENT_CREDENTIALS", apiDestinationOAuth(tls.URL, "owned-client-secret"), keyID)
				destination := r.destination(t, "oauth-fence", aws.ToString(connection.ConnectionArn), tls.URL+"/receive", "POST", 100)
				role := r.role(t, "oauth-fence", destination)
				// The interrupted event is terminal; recovery must come from new
				// authorized work, not an old event accidentally spending retries.
				r.putTarget(t, "oauth-fence", r.target(t, "oauth-fence", destination, role, 0, 60, ""))
				id := r.send(t, "oauth-fence", `{"fence":"old-authority"}`)
				select {
				case <-refreshStarted:
				case <-time.After(3 * time.Second):
					t.Fatal("actual 401 did not begin OAuth refresh")
				}
				restore := func() {}
				switch mutation {
				case "connection":
					r.call(t, "UpdateConnection", map[string]any{"Name": "oauth-fence", "AuthorizationType": "BASIC", "AuthParameters": apiDestinationBasic("replacement-password")})
				case "destination":
					r.call(t, "UpdateApiDestination", map[string]any{"Name": "oauth-fence", "InvocationEndpoint": tls.URL + "/updated"})
				case "invoke-authority":
					r.invokePolicy(t, "oauth-fence", destination, true)
					restore = func() { r.invokePolicy(t, "oauth-fence", destination, false) }
				case "kms-authority":
					keys := r.clients.kms(eventDeliveryAccount, "test", "")
					if _, err := keys.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: aws.String(keyID), PolicyName: aws.String("default"), Policy: aws.String(apiDestinationKeyPolicy(true))}); err != nil {
						t.Fatal(err)
					}
					restore = func() {
						if _, err := keys.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: aws.String(keyID), PolicyName: aws.String("default"), Policy: aws.String(apiDestinationKeyPolicy(false))}); err != nil {
							t.Fatal(err)
						}
					}
				}
				release.Do(func() { close(releaseRefresh) })
				r.drain(t)
				apiDestinationState(t, r.delivery(t, id), "failed", 1)
				var data []apiDestinationRequest
				for _, request := range provider.snapshot() {
					if request.Path != "/oauth" {
						data = append(data, request)
					}
				}
				if len(data) != 1 || tokens.Load() != 2 {
					t.Fatal("mutation allowed unauthorized destination traffic after blocked refresh")
				}
				restore()
				r.putTarget(t, "oauth-fence", r.target(t, "oauth-fence", destination, role, 1, 60, ""))
				recovered := r.send(t, "oauth-fence", `{"fence":"current-authority"}`)
				r.drain(t)
				row := r.delivery(t, recovered)
				if row.State == "pending" {
					apiDestinationState(t, row, "pending", 1)
					if !strings.Contains(row.LastErrorMessage, "401") {
						t.Fatal("recovery failed for a reason other than refreshing the previous token", row)
					}
					r.advance(t, row.Due)
					row = r.delivery(t, recovered)
					apiDestinationState(t, row, "delivered", 2)
				} else {
					apiDestinationState(t, row, "delivered", 1)
				}
				data = nil
				for _, request := range provider.snapshot() {
					if request.Path == "/oauth" {
						continue
					}
					if request.Header.Get("Authorization") == "Bearer must-not-cache-stale-token" {
						t.Fatal("unauthorized refresh installed a stale cached token")
					}
					data = append(data, request)
				}
				last := data[len(data)-1]
				if mutation == "connection" {
					if tokens.Load() != 2 || last.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("owned-user:replacement-password")) {
						t.Fatal("Connection mutation did not fence OAuth and select new credentials")
					}
				} else if tokens.Load() != 3 || last.Header.Get("Authorization") != "Bearer owned-token-3" {
					t.Fatal("restoration did not obtain and deliver a fresh authorized provider token")
				}
				if mutation == "destination" && last.Path != "/updated" {
					t.Fatal("in-flight destination mutation reused the old URL")
				}
			})
		}
	}
}

func TestEventBridgeAPIDestinationFiveSecondCancellation(t *testing.T) {
	cancelled := make(chan struct{})
	provider := &apiDestinationReceiver{respond: func(w http.ResponseWriter, request *http.Request, captured apiDestinationRequest) {
		<-request.Context().Done()
		close(cancelled)
	}}
	tls := httptest.NewTLSServer(provider)
	t.Cleanup(tls.Close)
	// One wall-clock case is enough: the same HTTP owner serves both stores.
	// The injected client has no shorter deadline that could fake this proof.
	outbound := tls.Client()
	if outbound.Timeout != 0 {
		t.Fatal("TLS test client unexpectedly has its own timeout")
	}
	r := newAPIDestinationCloud(t, "memory", outbound)
	connection := r.connection(t, "timeout", "BASIC", apiDestinationBasic("owned-password"), "")
	destination := r.destination(t, "timeout", aws.ToString(connection.ConnectionArn), tls.URL+"/wait", "POST", 100)
	role := r.role(t, "timeout", destination)
	r.putTarget(t, "timeout", r.target(t, "timeout", destination, role, 1, 60, ""))
	serviceTime := r.source.Now()
	started := time.Now()
	id := r.send(t, "timeout", `{"timeout":"real-socket"}`)
	r.drain(t)
	elapsed := time.Since(started)
	row := r.delivery(t, id)
	apiDestinationState(t, row, "pending", 1)
	if elapsed < 4500*time.Millisecond || elapsed > 10*time.Second || !r.source.Now().Equal(serviceTime) || !strings.Contains(row.LastErrorMessage, "timed out") {
		t.Fatalf("five-second request deadline did not produce retryable timeout: elapsed=%s row=%+v", elapsed, row)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("five-second timeout did not cancel the actual TLS request")
	}
	if len(provider.snapshot()) != 1 || !row.Due.After(serviceTime) {
		t.Fatal("timeout bypassed retained retry scheduling")
	}
}

func TestEventBridgeAPIDestinationInflightShutdownRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var requests atomic.Int64
			started := make(chan struct{})
			cancelled := make(chan struct{})
			provider := &apiDestinationReceiver{respond: func(w http.ResponseWriter, request *http.Request, captured apiDestinationRequest) {
				if requests.Add(1) == 1 {
					close(started)
					<-request.Context().Done()
					close(cancelled)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}}
			tls := httptest.NewTLSServer(provider)
			t.Cleanup(tls.Close)
			r := newAPIDestinationCloud(t, backend, tls.Client())
			connection := r.connection(t, "shutdown", "BASIC", apiDestinationBasic("owned-password"), "")
			destination := r.destination(t, "shutdown", aws.ToString(connection.ConnectionArn), tls.URL+"/inflight", "POST", 100)
			role := r.role(t, "shutdown", destination)
			r.putTarget(t, "shutdown", r.target(t, "shutdown", destination, role, 0, 60, ""))
			id := r.send(t, "shutdown", `{"shutdown":"retained-event"}`)
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("accepted work did not reach the actual HTTP receiver")
			}
			if err := r.cloud.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-cancelled:
			case <-time.After(2 * time.Second):
				t.Fatal("service shutdown left its outbound request alive")
			}
			// The receiver physically saw an interrupted request. Shutdown must
			// not commit that interruption as the sole allowed failed attempt.
			apiDestinationState(t, r.delivery(t, id), "pending", 0)
			r.clients = r.reopen()
			r.drain(t)
			apiDestinationState(t, r.delivery(t, id), "delivered", 1)
			if requests.Load() != 2 {
				t.Fatal("reopen lost interrupted work or duplicated completed recovery")
			}
			for _, request := range provider.snapshot() {
				apiDestinationJSON(t, request.Body, map[string]any{"shutdown": "retained-event"})
			}
		})
	}
}
