package stackd_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	endpoints "github.com/aws/smithy-go/endpoints"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

// The compact replay references source/sequence positions in kms_evidence.json.gz.
// That evidence keeps all three runs, supplementary probes and the separately
// recovered cleanup; replay does not turn propagation failures into API rules.
type s3KMSCall struct {
	Label, Source, Service, Operation, Actor, Code string
	Region                                         string
	Sequence, Status                               int
	Input                                          json.RawMessage
	Body                                           string
	Plaintext                                      *string
	Output                                         map[string]any
	Context                                        map[string]string
	InputContext                                   map[string]string
	Reopen                                         bool
	Absent                                         []string
	Bind                                           map[string]string
	ErrorDetails                                   map[string]string
	Session                                        string
}

type s3KMSReplay struct {
	clients    cloudClients
	values     map[string]string
	sessions   map[string]aws.Credentials
	httpClient s3.HTTPClient
}

// Keep the original references alongside rebound values so projection can
// distinguish timestamp invariants from provider capture timestamps.
type s3NativeBoundOutput struct {
	native, rebound any
}

func (r *s3KMSReplay) rebind(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for name, value := range r.values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		text = strings.ReplaceAll(text, "${"+name+"}", string(encoded[1:len(encoded)-1]))
	}
	for remaining := text; ; {
		_, after, found := strings.Cut(remaining, "${")
		if !found {
			break
		}
		name, rest, closed := strings.Cut(after, "}")
		if !closed || !strings.Contains(name, ":") {
			t.Fatalf("unbound native resource: %s", text)
		}
		// IAM policy variables are native policy syntax, not fixture bindings.
		remaining = rest
	}
	return []byte(text)
}

// SDK fixtures keep the local HTTP listener fixed; raw replay exercises native
// account-prefixed hosts separately.
type s3ControlFixtureEndpoint url.URL

func (endpoint s3ControlFixtureEndpoint) ResolveEndpoint(ctx context.Context, parameters s3control.EndpointParameters) (endpoints.Endpoint, error) {
	resolved, err := s3control.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, parameters)
	if err != nil {
		return resolved, err
	}
	resolved.URI = url.URL(endpoint)
	return resolved, nil
}

func (r *s3KMSReplay) s3ControlClient(actor, region string) *s3control.Client {
	cred := r.sessions[actor]
	client := s3control.HTTPClient(r.clients.server.Client())
	if r.httpClient != nil {
		client = r.httpClient
	}
	scheme, _, _ := strings.Cut(r.clients.server.URL, "://")
	return s3control.New(s3control.Options{
		Region:             region,
		EndpointResolverV2: s3ControlFixtureEndpoint{Scheme: scheme, Host: r.clients.server.Listener.Addr().String()},
		Credentials:        credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken),
		HTTPClient:         client, RetryMaxAttempts: 1,
	})
}

// Resolve ARN requests with the SDK's native endpoint rules, then deliver the
// signed request locally without replacing its HTTP Host authority.
type s3FixtureEndpoint struct{}

func (s3FixtureEndpoint) ResolveEndpoint(ctx context.Context, parameters s3.EndpointParameters) (endpoints.Endpoint, error) {
	if strings.HasPrefix(aws.ToString(parameters.Bucket), "arn:") {
		parameters.Endpoint = nil
		parameters.ForcePathStyle = aws.Bool(false)
	}
	return s3.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, parameters)
}

type s3FixtureHTTPClient struct {
	s3.HTTPClient
	endpoint *url.URL
}

func (client s3FixtureHTTPClient) Do(request *http.Request) (*http.Response, error) {
	if request.URL.Host == client.endpoint.Host {
		return client.HTTPClient.Do(request)
	}
	local := request.Clone(request.Context())
	if local.Host == "" {
		local.Host = request.URL.Host
	}
	local.URL.Scheme, local.URL.Host = client.endpoint.Scheme, client.endpoint.Host
	return client.HTTPClient.Do(local)
}

func (r *s3KMSReplay) s3Client(actor string) *s3.Client {
	return r.s3RegionClient(actor, "us-east-1")
}

func (r *s3KMSReplay) s3RegionClient(actor, region string) *s3.Client {
	cred := r.sessions[actor]
	var provider aws.CredentialsProvider = credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)
	if actor == "anonymous" {
		provider = aws.AnonymousCredentials{}
	}
	client := s3.HTTPClient(r.clients.server.Client())
	if r.httpClient != nil {
		client = r.httpClient
	}
	endpoint, _ := url.Parse(r.clients.server.URL)
	client = s3FixtureHTTPClient{HTTPClient: client, endpoint: endpoint}
	return s3.New(s3.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL),
		Credentials: provider,
		HTTPClient:  client, EndpointResolverV2: s3FixtureEndpoint{}, UsePathStyle: true, RetryMaxAttempts: 1,
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired})
}

func (r *s3KMSReplay) cloudtrailClient(actor, region string) *cloudtrail.Client {
	cred := r.sessions[actor]
	return cloudtrail.New(cloudtrail.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken),
		HTTPClient:  r.clients.server.Client(), RetryMaxAttempts: 1})
}

func s3KMSDecode(t *testing.T, value string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (r *s3KMSReplay) call(t *testing.T, row s3KMSCall) any {
	t.Helper()
	cred, ok := r.sessions[row.Actor]
	if !ok {
		t.Fatalf("%s: missing actor %s", row.Label, row.Actor)
	}
	region := row.Region
	if region == "" {
		region = "us-east-1"
	}
	var client any
	switch row.Service {
	case "s3":
		client = r.s3RegionClient(row.Actor, region)
	case "s3control":
		client = r.s3ControlClient(row.Actor, region)
	case "kms":
		client = r.clients.kmsRegion(region, cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)
	case "cloudtrail":
		client = r.cloudtrailClient(row.Actor, region)
	case "iam":
		client = r.clients.iam(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)
	case "sts":
		client = r.clients.sts(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)
	case "organizations":
		client = organizations.New(organizations.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
	case "firehose":
		client = r.clients.firehose(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)
	case "sns":
		client = r.clients.snsRegion(region, cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)
	case "sqs":
		client = r.clients.sqs(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)
	case "eventbridge":
		client = eventbridge.New(eventbridge.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
	case "lambda":
		client = awslambda.New(awslambda.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
	case "logs":
		client = cloudwatchlogs.New(cloudwatchlogs.Options{Region: region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
	default:
		t.Fatalf("%s: unknown service %s", row.Label, row.Service)
	}
	out, err := awstest.CallSDK(t.Context(), client, row.Operation, r.rebind(t, row.Input), func(input any) {
		switch input := input.(type) {
		case *s3.PutObjectInput:
			input.Body = bytes.NewReader(s3KMSDecode(t, row.Body))
			// boto3/CLI omit this header and S3 stores binary/octet-stream;
			// the Go SDK otherwise supplies application/octet-stream itself.
			if input.ContentType == nil {
				input.ContentType = aws.String("binary/octet-stream")
			}
			if row.InputContext != nil {
				input.SSEKMSEncryptionContext = aws.String(base64.StdEncoding.EncodeToString(r.rebind(t, row.InputContext)))
			}
		case *s3.UploadPartInput:
			input.Body = bytes.NewReader(s3KMSDecode(t, row.Body))
		case *s3.CopyObjectInput:
			if row.InputContext != nil {
				input.SSEKMSEncryptionContext = aws.String(base64.StdEncoding.EncodeToString(r.rebind(t, row.InputContext)))
			}
		}
	})
	if row.Code != "Success" {
		// Native numeric HEAD codes describe an empty error body, not an
		// SDK-generated error spelling. The HTTP status remains authoritative.
		if _, numeric := strconv.Atoi(row.Code); numeric != nil {
			assertAPIError(t, err, row.Code)
		}
		var response *smithyhttp.ResponseError
		if row.Status != 0 && (!errors.As(err, &response) || response.HTTPStatusCode() != row.Status) {
			t.Fatalf("%s (%s:%d): HTTP status differs from native %d: %v", row.Label, row.Source, row.Sequence, row.Status, err)
		}
		return nil
	}
	if err != nil {
		t.Fatalf("%s (%s:%d): %v", row.Label, row.Source, row.Sequence, err)
	}
	metadata := reflect.ValueOf(out).Elem().FieldByName("ResultMetadata").Interface().(middleware.Metadata)
	response, ok := awsmiddleware.GetRawResponse(metadata).(*smithyhttp.Response)
	if row.Status != 0 && (!ok || response.StatusCode != row.Status) {
		t.Fatalf("%s: HTTP status differs from native %d: %+v", row.Label, row.Status, response)
	}
	if object, ok := out.(*s3.GetObjectOutput); ok {
		var body []byte
		var err error
		if row.Plaintext == nil {
			_, err = io.Copy(io.Discard, object.Body)
		} else {
			body, err = io.ReadAll(object.Body)
		}
		closeErr := object.Body.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("%s: reading plaintext: %v %v", row.Label, err, closeErr)
		}
		if row.Plaintext != nil && !bytes.Equal(body, s3KMSDecode(t, *row.Plaintext)) {
			t.Fatalf("%s: plaintext differs from native consumer bytes", row.Label)
		}
	}
	data, err := awstest.MarshalSDK(out)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	for name, path := range row.Bind {
		value := awsFixtureField(got, path)
		text, ok := value.(string)
		if !ok || text == "" {
			t.Fatalf("%s: empty created resource %s", row.Label, path)
		}
		r.values[name] = text
	}
	if row.Session != "" {
		var session *ststypes.Credentials
		switch out := out.(type) {
		case *sts.AssumeRoleOutput:
			session = out.Credentials
		case *sts.GetSessionTokenOutput:
			session = out.Credentials
		case *iam.CreateAccessKeyOutput:
			r.sessions[row.Session] = aws.Credentials{AccessKeyID: aws.ToString(out.AccessKey.AccessKeyId), SecretAccessKey: aws.ToString(out.AccessKey.SecretAccessKey)}
		default:
			t.Fatalf("%s: %T does not issue credentials", row.Label, out)
		}
		if session != nil {
			r.sessions[row.Session] = aws.Credentials{AccessKeyID: aws.ToString(session.AccessKeyId), SecretAccessKey: aws.ToString(session.SecretAccessKey), SessionToken: aws.ToString(session.SessionToken)}
		}
	}
	var want map[string]any
	if err := json.Unmarshal(r.rebind(t, row.Output), &want); err != nil {
		t.Fatal(err)
	}
	if want != nil {
		s3NativeProjection(t, row.Label, s3NativeBoundOutput{native: row.Output, rebound: want}, got)
	}
	for _, field := range row.Absent {
		value := awsFixtureField(got, field)
		if value != nil && value != "" {
			t.Fatalf("%s exposed %s omitted by native response: %#v", row.Label, field, value)
		}
	}
	if row.Context != nil {
		var wantContext, actualContext map[string]string
		if err := json.Unmarshal(r.rebind(t, row.Context), &wantContext); err != nil {
			t.Fatal(err)
		}
		encoded, ok := got["SSEKMSEncryptionContext"].(string)
		if !ok {
			t.Fatalf("%s omitted encryption context", row.Label)
		}
		if err := json.Unmarshal(s3KMSDecode(t, encoded), &actualContext); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(wantContext, actualContext) {
			t.Fatalf("%s: decoded context got %v want %v", row.Label, actualContext, wantContext)
		}
	}
	return out
}

func newS3KMSReplay(clients cloudClients) *s3KMSReplay {
	return &s3KMSReplay{clients: clients, values: map[string]string{"account": "123456789012", "otherAccount": "222222222222", "partition": "aws"},
		sessions: map[string]aws.Credentials{
			"caller":    {AccessKeyID: "test", SecretAccessKey: "test"},
			"other":     {AccessKeyID: "222222222222", SecretAccessKey: "test"},
			"anonymous": {},
		}}
}

func TestS3KMSNativeConsumerReplay(t *testing.T) {
	var fixture struct{ Calls, Precedence []s3KMSCall }
	awsReadFixture(t, "s3/kms_replay.json.gz", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 19, 20, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source})
			replay := newS3KMSReplay(clients)
			for _, row := range fixture.Calls {
				replay.call(t, row)
			}
			// Old alias objects must still read using their original key after both
			// retargeting and reconstruction of all services/repositories.
			replay.clients = reopen()
			for _, row := range fixture.Calls {
				if row.Label == "old-alias-object" || row.Label == "enabled-get" || row.Label == "get-full" {
					replay.call(t, row)
				}
			}
			// Extend the captured writes with durable plaintext consumers for the
			// retargeted key and the custom encryption context. These extra GETs
			// are local round-trip checks, not additional native observations.
			for _, row := range fixture.Calls {
				if row.Label != "new-alias-object" && row.Label != "put-context" {
					continue
				}
				var input s3.PutObjectInput
				var expected s3.PutObjectOutput
				if err := json.Unmarshal(replay.rebind(t, row.Input), &input); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(replay.rebind(t, row.Output), &expected); err != nil {
					t.Fatal(err)
				}
				out, err := replay.s3Client("caller").GetObject(t.Context(), &s3.GetObjectInput{Bucket: input.Bucket, Key: input.Key})
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(out.Body)
				closeErr := out.Body.Close()
				if err != nil || closeErr != nil {
					t.Fatalf("durable plaintext: %v %v", err, closeErr)
				}
				if !bytes.Equal(body, s3KMSDecode(t, row.Body)) || aws.ToString(out.SSEKMSKeyId) != aws.ToString(expected.SSEKMSKeyId) {
					t.Fatalf("%s: durable plaintext or canonical key differs from captured write", row.Label)
				}
			}
			keys := replay.clients.kms("test", "test", "")
			pending, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			replay.values["pendingARN"] = aws.ToString(pending.KeyMetadata.Arn)
			if _, err := keys.ScheduleKeyDeletion(t.Context(), &kms.ScheduleKeyDeletionInput{KeyId: pending.KeyMetadata.Arn, PendingWindowInDays: aws.Int32(7)}); err != nil {
				t.Fatal(err)
			}
			for _, row := range fixture.Precedence {
				replay.call(t, row)
			}
			// Failed writes cannot replace an existing object or publish a partial one.
			for _, row := range fixture.Calls {
				if row.Label == "get-full" {
					replay.call(t, row)
				}
			}
			for _, key := range []string{"objects/bad-md5", "objects/bad-checksum", "objects/pending-key"} {
				_, err := replay.s3Client("caller").GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String("s3-kms-replay-data"), Key: &key})
				assertAPIError(t, err, "NoSuchKey")
			}
		})
	}
}
