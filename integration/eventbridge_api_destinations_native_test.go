package stackd_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

// Native resource UUIDs and page tokens are opaque. Bind complete values rather
// than replacing account, region or resource names: those remain assertions.
func apiDestinationBind(t *testing.T, bindings map[string]string, key, native, local string) {
	t.Helper()
	if native == "" || local == "" {
		t.Fatalf("missing opaque %s: native %q, local %q", key, native, local)
	}
	if previous, ok := bindings[native]; ok && previous != local {
		t.Fatalf("%s changed incarnation: previously %q, now %q", key, previous, local)
	}
	if key != "NextToken" {
		nativePrefix := native[:strings.LastIndex(native, "/")+1]
		localPrefix := local[:strings.LastIndex(local, "/")+1]
		if nativePrefix == "" || nativePrefix != localPrefix || local == localPrefix {
			t.Fatalf("%s changed resource scope/name or omitted its incarnation: native %q, local %q", key, native, local)
		}
		for original, bound := range bindings {
			if original != native && bound == local {
				t.Fatalf("distinct native incarnations share %s %q", key, local)
			}
		}
	}
	bindings[native] = local
}

func apiDestinationReplace(input json.RawMessage, bindings map[string]string) json.RawMessage {
	text := string(input)
	for native, local := range bindings {
		text = strings.ReplaceAll(text, native, local)
	}
	return json.RawMessage(text)
}

// Unlike the broader Connection lifecycle replay, this projection does not
// collapse states or omit empty values. Wall-clock values and diagnostic wording
// are opaque; field presence, state, rate, method, endpoint and pages remain.
func apiDestinationPublicProjection(value any) any {
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, item := range value {
			switch key {
			case "CreationTime", "LastModifiedTime", "LastAuthorizedTime":
				out[key] = "<timestamp>"
			case "StateReason", "ErrorMessage":
				if _, ok := item.(string); ok {
					out[key] = "<diagnostic>"
				} else {
					out[key] = item
				}
			default:
				out[key] = apiDestinationPublicProjection(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = apiDestinationPublicProjection(item)
		}
		return out
	default:
		return value
	}
}

type apiDestinationNativeTimes struct {
	nativeCreated, nativeModified time.Time
	localCreated, localModified   time.Time
}

func apiDestinationTimestamp(t *testing.T, value any) time.Time {
	t.Helper()
	switch value := value.(type) {
	case string:
		at, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			t.Fatal(err)
		}
		return at
	case float64:
		return time.UnixMilli(int64(value * 1000)).UTC()
	default:
		t.Fatalf("invalid public timestamp %#v", value)
		return time.Time{}
	}
}

func apiDestinationCompareTimes(t *testing.T, previous map[string]apiDestinationNativeTimes, native, local map[string]any) {
	t.Helper()
	arn, ok := native["ApiDestinationArn"].(string)
	if !ok {
		return
	}
	times := apiDestinationNativeTimes{
		nativeCreated:  apiDestinationTimestamp(t, native["CreationTime"]),
		nativeModified: apiDestinationTimestamp(t, native["LastModifiedTime"]),
		localCreated:   apiDestinationTimestamp(t, local["CreationTime"]),
		localModified:  apiDestinationTimestamp(t, local["LastModifiedTime"]),
	}
	if before, ok := previous[arn]; ok {
		if !times.nativeCreated.Equal(before.nativeCreated) || !times.localCreated.Equal(before.localCreated) {
			t.Fatal("destination creation time changed within one incarnation")
		}
		if times.nativeModified.Compare(before.nativeModified) != times.localModified.Compare(before.localModified) {
			t.Fatal("destination modification-time transition differs from native")
		}
	}
	if times.localCreated.IsZero() || times.localModified.Before(times.localCreated) {
		t.Fatal("invalid destination creation/modification ordering")
	}
	previous[arn] = times
}

func apiDestinationAssertProjection(t *testing.T, native, local map[string]any, bindings map[string]string) {
	t.Helper()
	body, err := json.Marshal(native)
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]any
	awsDecodeJSON(t, apiDestinationReplace(body, bindings), &expected)
	if want, got := apiDestinationPublicProjection(expected), apiDestinationPublicProjection(local); !reflect.DeepEqual(want, got) {
		t.Fatalf("native API Destination projection mismatch\nwant %#v\ngot  %#v", want, got)
	}
}

// These scope and cursor checks are local invariants, not native cross-account
// observations. Each scope owns the same names but independent incarnations.
func apiDestinationScopedReplay(t *testing.T, backend, account, region, tokenError string) {
	t.Helper()
	source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: source})
	scopes := []struct{ account, region string }{
		{account, region},
		{"222222222222", region},
		{account, "us-west-2"},
	}
	client := func(index int) *eventbridge.Client {
		scope := scopes[index]
		return eventbridge.New(eventbridge.Options{
			Region: scope.region, BaseEndpoint: aws.String(clients.server.URL),
			Credentials: credentials.NewStaticCredentialsProvider(scope.account, "test", ""),
			HTTPClient:  clients.server.Client(), RetryMaxAttempts: 1,
		})
	}
	descriptions := make([]map[string]any, len(scopes))
	connections := make([]string, len(scopes))
	destination := func(index int, name string) *eventbridge.CreateApiDestinationInput {
		scope := scopes[index]
		return &eventbridge.CreateApiDestinationInput{
			Name: aws.String(name), ConnectionArn: aws.String(connections[index]),
			Description:                  aws.String(scope.account + "/" + scope.region),
			HttpMethod:                   eventtypes.ApiDestinationHttpMethodPost,
			InvocationEndpoint:           aws.String("https://receiver.invalid/scoped"),
			InvocationRateLimitPerSecond: aws.Int32(7),
		}
	}
	describe := func(index int) map[string]any {
		t.Helper()
		out, err := client(index).DescribeApiDestination(t.Context(), &eventbridge.DescribeApiDestinationInput{Name: aws.String("scoped-destination-a")})
		if err != nil {
			t.Fatal(err)
		}
		value := connectionSDKObject(t, out)
		delete(value, "ResultMetadata")
		return value
	}
	for index, scope := range scopes {
		before, err := client(index).ListApiDestinations(t.Context(), &eventbridge.ListApiDestinationsInput{NamePrefix: aws.String("scoped-destination-")})
		if err != nil || len(before.ApiDestinations) != 0 || before.NextToken != nil {
			t.Fatalf("scope %v exposed another scope before creation: %+v, %v", scope, before, err)
		}
		connection, err := client(index).CreateConnection(t.Context(), &eventbridge.CreateConnectionInput{
			Name: aws.String("scoped-connection"), AuthorizationType: eventtypes.ConnectionAuthorizationTypeBasic,
			AuthParameters: &eventtypes.CreateConnectionAuthRequestParameters{
				BasicAuthParameters: &eventtypes.CreateConnectionBasicAuthRequestParameters{
					Username: aws.String("scoped-user"), Password: aws.String("scoped-inert-password"),
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		connections[index] = aws.ToString(connection.ConnectionArn)
		created, err := client(index).CreateApiDestination(t.Context(), destination(index, "scoped-destination-a"))
		if err != nil {
			t.Fatal(err)
		}
		prefix := "arn:aws:events:" + scope.region + ":" + scope.account + ":api-destination/scoped-destination-a/"
		if !strings.HasPrefix(aws.ToString(created.ApiDestinationArn), prefix) {
			t.Fatalf("destination escaped scope %v: %v", scope, created.ApiDestinationArn)
		}
		descriptions[index] = describe(index)
	}
	if _, err := client(0).CreateApiDestination(t.Context(), destination(0, "scoped-destination-b")); err != nil {
		t.Fatal(err)
	}
	first, err := client(0).ListApiDestinations(t.Context(), &eventbridge.ListApiDestinationsInput{NamePrefix: aws.String("scoped-destination-"), Limit: aws.Int32(1)})
	if err != nil || len(first.ApiDestinations) != 1 || aws.ToString(first.NextToken) == "" {
		t.Fatalf("cannot paginate owned destinations: %+v, %v", first, err)
	}
	for _, index := range []int{1, 2} {
		_, err := client(index).ListApiDestinations(t.Context(), &eventbridge.ListApiDestinationsInput{
			NamePrefix: aws.String("scoped-destination-"), Limit: aws.Int32(1), NextToken: first.NextToken,
		})
		assertAPIError(t, err, tokenError)
	}
	_, err = client(0).ListApiDestinations(t.Context(), &eventbridge.ListApiDestinationsInput{
		NamePrefix: aws.String("different-prefix"), Limit: aws.Int32(1), NextToken: first.NextToken,
	})
	assertAPIError(t, err, tokenError)

	clients = reopen()
	last, err := client(0).ListApiDestinations(t.Context(), &eventbridge.ListApiDestinationsInput{
		NamePrefix: aws.String("scoped-destination-"), Limit: aws.Int32(1), NextToken: first.NextToken,
	})
	if err != nil || len(last.ApiDestinations) != 1 || last.NextToken != nil ||
		aws.ToString(first.ApiDestinations[0].Name) != "scoped-destination-a" || aws.ToString(last.ApiDestinations[0].Name) != "scoped-destination-b" {
		t.Fatalf("owned cursor did not retain its page across reopen: first %+v, last %+v, %v", first, last, err)
	}
	for index := range scopes {
		if got := describe(index); !reflect.DeepEqual(got, descriptions[index]) {
			t.Fatalf("scope %v metadata changed across reopen: got %#v, want %#v", scopes[index], got, descriptions[index])
		}
	}
	if _, err := client(0).DeleteApiDestination(t.Context(), &eventbridge.DeleteApiDestinationInput{Name: aws.String("scoped-destination-a")}); err != nil {
		t.Fatal(err)
	}
	_, err = client(0).DescribeApiDestination(t.Context(), &eventbridge.DescribeApiDestinationInput{Name: aws.String("scoped-destination-a")})
	assertAPIError(t, err, "ResourceNotFoundException")
	advanceClock(t, source, time.Second)
	if _, err := client(0).CreateApiDestination(t.Context(), destination(0, "scoped-destination-a")); err != nil {
		t.Fatal(err)
	}
	recreated := describe(0)
	if recreated["ApiDestinationArn"] == descriptions[0]["ApiDestinationArn"] ||
		!apiDestinationTimestamp(t, recreated["CreationTime"]).After(apiDestinationTimestamp(t, descriptions[0]["CreationTime"])) {
		t.Fatal("same-name recreation reused a destination incarnation")
	}
	descriptions[0] = recreated
	clients = reopen()
	for index := range scopes {
		if got := describe(index); !reflect.DeepEqual(got, descriptions[index]) {
			t.Fatalf("scope %v was changed by another scope's recreation: got %#v, want %#v", scopes[index], got, descriptions[index])
		}
	}
}

func apiDestinationBindPublic(t *testing.T, native, local any, bindings map[string]string, times map[string]apiDestinationNativeTimes) {
	t.Helper()
	switch native := native.(type) {
	case map[string]any:
		actual, ok := local.(map[string]any)
		if !ok {
			t.Fatalf("native object became %T", local)
		}
		for key, value := range native {
			switch key {
			case "ApiDestinationArn", "ConnectionArn", "SecretArn", "NextToken":
				original, nativeString := value.(string)
				bound, localString := actual[key].(string)
				if !nativeString || !localString {
					t.Fatalf("opaque %s has invalid public shape: native %#v, local %#v", key, value, actual[key])
				}
				if original == "" {
					if bound != "" {
						t.Fatalf("native %s was detached but local retained %q", key, bound)
					}
				} else {
					apiDestinationBind(t, bindings, key, original, bound)
				}
			case "CreationTime", "LastModifiedTime", "LastAuthorizedTime":
				apiDestinationTimestamp(t, value)
				apiDestinationTimestamp(t, actual[key])
			default:
				apiDestinationBindPublic(t, value, actual[key], bindings, times)
			}
		}
		apiDestinationCompareTimes(t, times, native, actual)
	case []any:
		actual, ok := local.([]any)
		if !ok || len(native) != len(actual) {
			t.Fatalf("native collection differs: native %#v, local %#v", native, local)
		}
		for index, item := range native {
			apiDestinationBindPublic(t, item, actual[index], bindings, times)
		}
	}
}

type apiDestinationNativeFixture struct {
	Account, Region, Prefix string
	Identity                struct{ Arn string }
	Observations            []awsNativeObservation
	Audit                   struct {
		Events []struct {
			Label string `json:"call_label"`
			Event map[string]any
		}
	}
}

func TestEventBridgeNativeAPIDestinations(t *testing.T) {
	var fixture apiDestinationNativeFixture
	awsReadFixture(t, "eventbridge/api-destinations.json", &fixture)
	if len(fixture.Observations) == 0 {
		t.Fatal("native API Destination capture has no observations")
	}
	tokenError := ""
	for _, row := range fixture.Observations {
		if row.Label == "list-invalid-token" {
			tokenError = row.Result.Code
		}
	}
	if tokenError == "" || tokenError == "Success" {
		t.Fatal("native capture lacks the invalid-pagination-token rejection")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend+"/native", func(t *testing.T) {
			apiDestinationReplay(t, backend, fixture)
		})
		t.Run(backend+"/local-scopes", func(t *testing.T) {
			apiDestinationScopedReplay(t, backend, fixture.Account, fixture.Region, tokenError)
		})
	}
}

func apiDestinationReplay(t *testing.T, backend string, fixture apiDestinationNativeFixture) {
	t.Helper()
	source := clock.NewManual(time.UnixMilli(fixture.Observations[0].Started).UTC())
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source})
	_, username, ok := strings.Cut(fixture.Identity.Arn, ":user/")
	if !ok {
		t.Fatal("native fixture caller is not an IAM user")
	}
	_, key, secret := clients.user(t, fixture.Account, username)
	putUserPolicy(t, clients.iam(fixture.Account, "test", ""), username, allow(`"*"`, "*"))
	identity, err := clients.sts(key, secret, "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatal(err)
	}
	bindings := map[string]string{}
	times := map[string]apiDestinationNativeTimes{}
	type outcome struct {
		id        string
		at        time.Time
		sensitive []string
	}
	outcomes := map[string]outcome{}
	call := func(row awsNativeObservation) (any, *awstest.WireClient, error) {
		wire := &awstest.WireClient{Client: clients.server.Client()}
		input := apiDestinationReplace(row.Input, bindings)
		config := aws.Config{
			Region: fixture.Region, HTTPClient: wire, RetryMaxAttempts: 1,
			Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""),
		}
		endpoint := aws.String(clients.server.URL)
		var client any
		switch row.Service {
		case "events":
			client = eventbridge.NewFromConfig(config, func(o *eventbridge.Options) {
				o.BaseEndpoint = endpoint
				// Preserve captured empty enums the SDK serializer omits.
				// Routing, signing and response decoding remain SDK-owned.
				o.APIOptions = append(o.APIOptions, awstest.JSONBody(input))
			})
		case "iam":
			client = iam.NewFromConfig(config, func(o *iam.Options) { o.BaseEndpoint = endpoint })
		case "secretsmanager":
			client = secretsmanager.NewFromConfig(config, func(o *secretsmanager.Options) { o.BaseEndpoint = endpoint })
		default:
			t.Fatalf("unexpected native fixture service %q", row.Service)
		}
		out, err := awstest.CallSDK(t.Context(), client, row.Operation, input)
		return out, wire, err
	}
	deauthorizationPending := false
	for _, row := range fixture.Observations {
		if row.Label == "linked-role-before" {
			// The native account already owned the standing linked role. Local
			// CreateConnection provisions its own; no unrelated native role ID,
			// last-used date, policy or account inventory is an expectation.
			continue
		}
		if row.Result.Code == "Success" &&
			(strings.HasPrefix(row.Label, "cleanup-secret-absence-") || strings.HasPrefix(row.Label, "deleted-basic-secret-absence-") ||
				strings.HasPrefix(row.Label, "cleanup-connection-absence-") || strings.HasPrefix(row.Label, "describe-deleted-basic-") ||
				strings.HasPrefix(row.Label, "state-connection-deletion-") || strings.HasPrefix(row.Label, "reauth-connection-deletion-") ||
				strings.HasPrefix(row.Label, "reauth-old-secret-absence-")) {
			// Delayed cleanup polls are not a latency oracle. Replay the
			// terminal absence below, never accept Success as NotFound.
			continue
		}
		if !t.Run(row.Label, func(t *testing.T) {
			var native map[string]any
			awsDecodeJSON(t, row.Result.Output, &native)
			when := time.UnixMilli(row.Started).UTC()
			// Native modification timestamps can cross a second boundary during
			// the request. Drive that observed mutation instant, not wall time.
			if row.Service == "events" && (row.Operation == "create-api-destination" || row.Operation == "update-api-destination") && row.Result.Code == "Success" {
				modified := apiDestinationTimestamp(t, native["LastModifiedTime"])
				if modified.After(when) {
					when = modified
				}
			}
			if !deauthorizationPending {
				if when.After(source.Now()) {
					advanceClock(t, source, when.Sub(source.Now()))
				}
				trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			}
			out, wire, err := call(row)
			awsNativeResult(t, row, err)
			if wire.Status != row.Result.HTTPStatus {
				t.Fatalf("native HTTP status %d, local %d", row.Result.HTTPStatus, wire.Status)
			}
			outcomes[row.Result.RequestID] = outcome{
				id: nativeAuditRequestID(t, out, err), at: source.Now(),
				sensitive: apiDestinationSensitiveValues(t, row.Input),
			}
			switch row.Label {
			case "deauthorize-basic":
				// Exercise the captured concurrent-update rejection without
				// imposing native wall-clock latency on the local scheduler.
				deauthorizationPending = true
			case "update-basic-reauthorize":
				deauthorizationPending = false
			}
			if err != nil {
				return
			}
			switch row.Service {
			case "events":
				switch row.Label {
				case "describe-basic-deauthorized", "describe-basic-reauthorized", "describe-destination-deauthorized", "describe-destination-reauthorized", "reauth-active-1":
					// These reads straddle independently propagated state.
					// Keep their exact SDK outcomes and correlated audits, but
					// use the settled followup for public state projections.
					return
				}
				var local map[string]any
				awsDecodeJSON(t, wire.Body, &local)
				apiDestinationBindPublic(t, native, local, bindings, times)
				apiDestinationAssertProjection(t, native, local, bindings)
				switch row.Label {
				case "describe-restored", "describe-destination-connection-deleted", "describe-recreated-default", "state-primary-deauthorized-settled", "reauth-active-2":
					clients = reopen()
					_, againWire, err := call(row)
					if err != nil {
						t.Fatal(err)
					}
					var again map[string]any
					awsDecodeJSON(t, againWire.Body, &again)
					if !reflect.DeepEqual(local, again) {
						t.Fatalf("destination metadata or incarnation changed across reopen: before %#v, after %#v", local, again)
					}
				}
			case "secretsmanager":
				got := out.(*secretsmanager.DescribeSecretOutput)
				if aws.ToString(got.OwningService) != native["OwningService"] {
					t.Fatal("managed secret lost its native owning service")
				}
				secretARN, ok := native["ARN"].(string)
				if !ok || bindings[secretARN] != aws.ToString(got.ARN) {
					t.Fatal("connection did not resolve its bound managed secret incarnation")
				}
			case "iam":
				// Role provisioning is a setup dependency. The controls proof
				// compares its SDK outcomes, not unrelated IAM metadata.
			}
		}) {
			return
		}
	}
	clients = reopen()
	// Read this service's public management history once. Repeated unfiltered
	// history scans grow with every lookup's own audit event.
	auditRecords := map[[2]string]map[string]any{}
	pages := cloudtrail.NewLookupEventsPaginator(organizationTrailClient(clients, fixture.Account, fixture.Region), &cloudtrail.LookupEventsInput{
		MaxResults: aws.Int32(50),
		LookupAttributes: []trailtypes.LookupAttribute{{
			AttributeKey: trailtypes.LookupAttributeKeyEventSource, AttributeValue: aws.String("events.amazonaws.com"),
		}},
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range page.Events {
			var record map[string]any
			awsDecodeJSON(t, []byte(aws.ToString(event.CloudTrailEvent)), &record)
			requestID, _ := record["requestID"].(string)
			eventName, _ := record["eventName"].(string)
			key := [2]string{requestID, eventName}
			if _, duplicate := auditRecords[key]; duplicate {
				t.Fatalf("duplicate %s outcome for request %s", eventName, requestID)
			}
			auditRecords[key] = record
		}
	}
	compared := 0
	audited := map[string]bool{}
	for _, audit := range fixture.Audit.Events {
		if audit.Event["eventSource"] != "events.amazonaws.com" {
			continue
		}
		nativeID, _ := audit.Event["requestID"].(string)
		local, replayed := outcomes[nativeID]
		if !replayed {
			continue
		}
		t.Run("audit/"+audit.Label, func(t *testing.T) {
			body, err := json.Marshal(audit.Event)
			if err != nil {
				t.Fatal(err)
			}
			var want map[string]any
			awsDecodeJSON(t, apiDestinationReplace(body, bindings), &want)
			want["eventTime"] = local.at.UTC().Format(time.RFC3339)
			actor := want["userIdentity"].(map[string]any)
			actor["principalId"], actor["accessKeyId"] = aws.ToString(identity.UserId), key
			got, present := auditRecords[[2]string{local.id, want["eventName"].(string)}]
			if !present {
				t.Fatalf("missing %s outcome for request %s", want["eventName"], local.id)
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			for _, sensitive := range local.sensitive {
				if strings.Contains(string(encoded), sensitive) {
					t.Fatal("native-redacted Connection authentication value leaked into management audit")
				}
			}
			apiDestinationAuditTimes(t, want)
			apiDestinationAuditTimes(t, got)
			assertNativeAuditEvent(t, got, want, "")
			for _, field := range []string{"userIdentity", "apiVersion"} {
				actual, present := got[field]
				native, expected := want[field]
				if present != expected || !reflect.DeepEqual(actual, native) {
					t.Fatalf("native audit %s differs: got %#v, want %#v", field, actual, native)
				}
			}
		})
		compared++
		audited[audit.Label] = true
	}
	for _, label := range []string{"create-basic", "create-default", "update-rate-1", "list-page-2", "describe-recreated-default", "delete-targeted-destination", "update-basic-reauthorize"} {
		if !audited[label] {
			t.Fatalf("native capture lost the correlated %s management projection", label)
		}
	}
	t.Logf("Compared %d exact-ID native management projections; resource UUIDs, request IDs, timestamp values and pagination tokens are opaque. No AWS HTTP delivery or cleanup latency claim.", compared)
}

func apiDestinationAuditTimes(t *testing.T, value any) {
	t.Helper()
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			switch key {
			case "creationTime", "lastModifiedTime", "lastAuthorizedTime":
				if _, ok := item.(string); !ok {
					t.Fatalf("native audit timestamp %s must retain its string shape: %#v", key, item)
				}
				apiDestinationTimestamp(t, item)
				value[key] = "<timestamp>"
			default:
				apiDestinationAuditTimes(t, item)
			}
		}
	case []any:
		for _, item := range value {
			apiDestinationAuditTimes(t, item)
		}
	}
}

func apiDestinationSensitiveValues(t *testing.T, input json.RawMessage) []string {
	t.Helper()
	var request map[string]any
	awsDecodeJSON(t, input, &request)
	var values []string
	var collect func(any)
	collect = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, item := range value {
				switch key {
				case "Password", "ApiKeyValue", "ClientSecret", "Value":
					// Native Create/UpdateConnection masks every invocation
					// parameter value, including IsValueSecret=false.
					if text, ok := item.(string); ok && text != "" {
						encoded, err := json.Marshal(text)
						if err != nil {
							t.Fatal(err)
						}
						values = append(values, string(encoded))
					}
				default:
					collect(item)
				}
			}
		case []any:
			for _, item := range value {
				collect(item)
			}
		}
	}
	collect(request["AuthParameters"])
	return values
}
