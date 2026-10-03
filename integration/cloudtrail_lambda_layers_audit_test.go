package stackd_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type lambdaLayerAuditFixture struct {
	Account      string
	Started      string `json:"started_at"`
	Observations []struct {
		lambdaQualifiedRow
		Region string
	}
	Audit struct {
		Events []struct {
			Label  string `json:"observation_label"`
			Event  map[string]any
			Lookup struct {
				Resources []trailtypes.Resource
			} `json:"lookup_entry"`
		}
	}
	Artifact struct {
		ZIP []byte `json:"zip_base64"`
	}
}

// Compare the statement as JSON while preserving its native string-valued wire
// field. Object key ordering is not a policy contract; replacing it with an audit
// object, omitting it, or changing its policy remains observable to this consumer.
func lambdaLayerAuditStatement(t *testing.T, event map[string]any) {
	t.Helper()
	response, _ := event["responseElements"].(map[string]any)
	value, present := response["statement"]
	if !present {
		return
	}
	text, ok := value.(string)
	if !ok {
		t.Fatalf("layer permission audit statement is not a JSON string: %#v", value)
	}
	var statement any
	if err := json.Unmarshal([]byte(text), &statement); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	response["statement"] = string(body)
}

func TestCloudTrailLambdaLayersNativeConsumers(t *testing.T) {
	controls := s3NativeLoad(t, "cloudtrail", "owned_s3_delivery")
	objects := s3NativeLoad(t, "s3", "owned_object_delivery")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture := lambdaFixture[lambdaLayerAuditFixture](t, "layer_source_audit")
			body, err := json.Marshal(fixture)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(strings.ReplaceAll(string(body), fixture.Account, eventDeliveryAccount)), &fixture); err != nil {
				t.Fatal(err)
			}
			started, err := time.Parse(time.RFC3339, fixture.Started)
			if err != nil {
				t.Fatal(err)
			}
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "layer-audit.sqlite"))
			}
			source := clock.NewManual(started)
			cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
			trails := trailNativeClient(clients)
			trailNativeProvision(t, clients, controls, objects, false)
			if _, err := trails.UpdateTrail(t.Context(), &cloudtrail.UpdateTrailInput{Name: aws.String(controls.Identity["trail_name"]), IsMultiRegionTrail: aws.Bool(true)}); err != nil {
				t.Fatal(err)
			}
			if _, err := trails.PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{
				TrailName:              aws.String(controls.Identity["trail_name"]),
				AdvancedEventSelectors: []trailtypes.AdvancedEventSelector{{FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Management"}}}}},
			}); err != nil {
				t.Fatal(err)
			}
			s3NativeReplay(t, trails, controls, "start-logging")
			layers := map[string]*awslambda.Client{}
			buckets := map[string]*s3.Client{}
			for _, region := range []string{"us-east-1", "us-west-2"} {
				layers[region] = awslambda.New(awslambda.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				buckets[region] = s3.New(s3NativeClient(clients, eventDeliveryAccount, "test").Options(), func(o *s3.Options) { o.Region = region })
			}
			native := map[string]map[string]any{}
			lookupResources := map[string][]trailtypes.Resource{}
			for _, row := range fixture.Audit.Events {
				native[row.Label] = row.Event
				lookupResources[row.Label] = row.Lookup.Resources
			}
			versions := lambdaPolicyRevisions{}
			revisions := lambdaPolicyRevisions{}
			expected := map[string]map[string]any{}
			labels := map[string]string{}
			errorsByID := map[string]string{}
			for _, row := range fixture.Observations {
				// S3 setup is replayed through the real regional SDK. Its cleanup
				// probes are retained as evidence, not extra Lambda audit outcomes.
				if row.Service != "lambda" && (row.Service != "s3" || strings.HasPrefix(row.Label, "cleanup-")) {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) {
					want := native[row.Label]
					if row.Service == "lambda" {
						if want == nil {
							t.Fatalf("native request lacks a correlated CloudTrail event: %s", row.Label)
						}
						when, err := time.Parse(time.RFC3339, want["eventTime"].(string))
						if err != nil {
							t.Fatal(err)
						}
						advanceClock(t, source, when.Sub(source.Now()))
					}
					input := row.Input
					if content, ok := input["Content"].(map[string]any); ok {
						if blob, ok := content["ZipFile"].(map[string]any); ok {
							content["ZipFile"] = blob["base64"]
						}
					}
					delete(input, "Body") // streaming S3 bodies are attached below
					encoded, err := json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					for native, local := range versions {
						encoded = []byte(strings.ReplaceAll(string(encoded), native, local))
					}
					operation := ""
					for _, word := range strings.Split(row.Operation, "_") {
						operation += strings.ToUpper(word[:1]) + word[1:]
					}
					var client any = layers[row.Region]
					if row.Service == "s3" {
						client = buckets[row.Region]
					}
					out, callErr := awstest.CallSDK(t.Context(), client, operation, encoded, func(input any) {
						if put, ok := input.(*s3.PutObjectInput); ok {
							put.Body = bytes.NewReader(fixture.Artifact.ZIP)
						}
					})
					if row.Result.Code == "Success" {
						if callErr != nil {
							t.Fatal(callErr)
						}
					} else {
						assertAPIError(t, callErr, row.Result.Code)
					}
					if row.Service == "s3" {
						if put, ok := out.(*s3.PutObjectOutput); ok {
							versions.observe(t, row.Result.Output["VersionId"].(string), aws.ToString(put.VersionId))
						}
						return
					}
					id := nativeAuditRequestID(t, out, callErr)
					if callErr != nil {
						var rejected smithy.APIError
						if !errors.As(callErr, &rejected) {
							t.Fatal(callErr)
						}
						errorsByID[id] = rejected.ErrorMessage()
					} else {
						switch result := out.(type) {
						case *awslambda.PublishLayerVersionOutput:
							want["responseElements"].(map[string]any)["createdDate"] = aws.ToString(result.CreatedDate)
						case *awslambda.AddLayerVersionPermissionOutput:
							response := want["responseElements"].(map[string]any)
							revisions.observe(t, response["revisionId"].(string), aws.ToString(result.RevisionId))
							response["revisionId"] = aws.ToString(result.RevisionId)
						}
					}
					encoded, err = json.Marshal(want)
					if err != nil {
						t.Fatal(err)
					}
					for native, local := range versions {
						encoded = []byte(strings.ReplaceAll(string(encoded), native, local))
					}
					if err := json.Unmarshal(encoded, &want); err != nil {
						t.Fatal(err)
					}
					lambdaLayerAuditStatement(t, want)
					expected[id], labels[id] = want, row.Label
				}) {
					t.FailNow()
				}
			}
			if len(expected) != len(fixture.Audit.Events) {
				t.Fatalf("replayed %d of %d correlated native layer outcomes", len(expected), len(fixture.Audit.Events))
			}
			compare := func(got map[string]any) string {
				t.Helper()
				id, _ := got["requestID"].(string)
				want := expected[id]
				if want == nil {
					t.Fatalf("unexpected layer audit: %#v", got)
				}
				lambdaLayerAuditStatement(t, got)
				assertNativeAuditEvent(t, got, want, errorsByID[id])
				return id
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, cloud)
			found := map[string]bool{}
			for _, region := range []string{"us-east-1", "us-west-2"} {
				regional := cloudtrail.New(trails.Options(), func(o *cloudtrail.Options) { o.Region = region })
				lookup := &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventSource, AttributeValue: aws.String("lambda.amazonaws.com")}}, MaxResults: aws.Int32(50)}
				for {
					out, err := regional.LookupEvents(t.Context(), lookup)
					if err != nil {
						t.Fatal(err)
					}
					for _, event := range out.Events {
						var got map[string]any
						if err := json.Unmarshal([]byte(aws.ToString(event.CloudTrailEvent)), &got); err != nil {
							t.Fatal(err)
						}
						id := compare(got)
						if found[id] || got["awsRegion"] != region || !reflect.DeepEqual(event.Resources, lookupResources[labels[id]]) {
							t.Fatalf("duplicate, mis-scoped or invented layer lookup resource: %+v", event)
						}
						if aws.ToString(event.EventName) != got["eventName"] || aws.ToString(event.EventId) != got["eventID"] || aws.ToString(event.ReadOnly) != strconv.FormatBool(got["readOnly"].(bool)) {
							t.Fatalf("LookupEvents envelope diverged from layer event: %+v", event)
						}
						found[id] = true
					}
					if out.NextToken == nil {
						break
					}
					lookup.NextToken = out.NextToken
				}
			}
			if len(found) != len(expected) {
				t.Fatalf("LookupEvents exposed %d of %d layer outcomes", len(found), len(expected))
			}
			delivered := map[string]bool{}
			for _, got := range trailNativeRecords(t, trailNativeObjects(t, s3NativeClient(clients, eventDeliveryAccount, "test"), objects.Identity["log_bucket"], "owned/AWSLogs/")) {
				if got["eventSource"] != "lambda.amazonaws.com" {
					continue
				}
				id := compare(got)
				if delivered[id] {
					t.Fatalf("duplicate layer audit delivered to S3: %s", id)
				}
				delivered[id] = true
			}
			if len(delivered) != len(expected) {
				t.Fatalf("configured S3 consumer received %d of %d layer outcomes", len(delivered), len(expected))
			}
		})
	}
}
