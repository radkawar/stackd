package stackd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type ec2NetworkCapture struct {
	Sequence                        int
	Label, Service, Operation, Code string
	Input                           json.RawMessage
	StartedAt                       time.Time `json:"started_at"`
	HTTPStatus                      int       `json:"http_status"`
	RawResponseBody                 string
	RequestID                       string
	Audit                           map[string]any `json:"-"`
}

func ec2NetworkCaptures(t *testing.T) []ec2NetworkCapture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/ec2/networking.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Capture struct{ Calls []ec2NetworkCapture }
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.Capture.Calls
}

// The reference transport lets the independent AWS SDK decode the exact retained
// native response. Only the actual client invokes the emulator; expected state is
// never computed by stackd's codecs or repository implementations.
type nativeXMLResponse string

func (body nativeXMLResponse) Do(request *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/xml;charset=UTF-8"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: request}, nil
}

func ec2NetworkDocument(t *testing.T, output any) map[string]any {
	t.Helper()
	data, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	delete(result, "ResultMetadata")
	return result
}

var ec2NetworkIdentity = regexp.MustCompile(`(?:eipalloc|eipassoc|vpc-cidr-assoc|vpc|subnet|sg|sgr|rtbassoc|rtb|igw|eni|aclassoc|acl|dopt)-[0-9a-f]{8,17}|[a-z0-9]+-az[0-9]+`)

// These EC2 response lists are sets, including rules whose priority is their
// RuleNumber rather than their serialized position. Identity bytes do not order
// a native resource against its independently allocated local counterpart.
func ec2NetworkSort(t *testing.T, value any, bindings map[string]string, native bool) {
	known := make(map[string]string, 2*len(bindings))
	for native, actual := range bindings {
		known[native], known[actual] = actual, actual
	}
	unbound := []byte("<identity>")
	resolve := func(identity []byte) []byte {
		if bound, ok := known[string(identity)]; ok {
			return []byte(bound)
		}
		return unbound
	}
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for _, child := range value {
				visit(child)
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
			slices.SortFunc(value, func(a, b any) int {
				left, _ := json.Marshal(a)
				right, _ := json.Marshal(b)
				if native {
					left = ec2AuditReplace(t, left, bindings)
					right = ec2AuditReplace(t, right, bindings)
				}
				if order := bytes.Compare(ec2NetworkIdentity.ReplaceAll(left, unbound), ec2NetworkIdentity.ReplaceAll(right, unbound)); order != 0 {
					return order
				}
				// Known identities resolve ties; previously unseen association
				// IDs must not obscure their already-bound parent resources.
				return bytes.Compare(ec2NetworkIdentity.ReplaceAllFunc(left, resolve), ec2NetworkIdentity.ReplaceAllFunc(right, resolve))
			})
		}
	}
	visit(value)
}

func ec2NetworkCompare(t *testing.T, path string, native, actual any, bindings map[string]string) {
	t.Helper()
	switch expected := native.(type) {
	case map[string]any:
		got, ok := actual.(map[string]any)
		if !ok || len(expected) != len(got) {
			t.Fatalf("%s: native object %#v, got %#v", path, expected, actual)
		}
		keys := make([]string, 0, len(expected))
		for key := range expected {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			value, present := got[key]
			if !present {
				t.Fatalf("%s.%s missing", path, key)
			}
			ec2NetworkCompare(t, path+"."+key, expected[key], value, bindings)
		}
	case []any:
		got, ok := actual.([]any)
		if !ok || len(expected) != len(got) {
			t.Fatalf("%s: native list %#v, got %#v", path, expected, actual)
		}
		for index, value := range expected {
			ec2NetworkCompare(t, fmt.Sprintf("%s[%d]", path, index), value, got[index], bindings)
		}
	case string:
		got, ok := actual.(string)
		if !ok {
			t.Fatalf("%s: native string %q, got %#v", path, expected, actual)
		}
		before, after := ec2NetworkIdentity.FindAllString(expected, -1), ec2NetworkIdentity.FindAllString(got, -1)
		if len(before) == len(after) {
			for index, original := range before {
				local := after[index]
				if prior, exists := bindings[original]; exists && prior != local {
					t.Fatalf("%s: %s changed from %s to %s", path, original, prior, local)
				}
				for other, assigned := range bindings {
					if other != original && assigned == local {
						t.Fatalf("%s: distinct native identities %s and %s collapsed to %s", path, other, original, local)
					}
				}
				bindings[original] = local
			}
		}
		if path == "response.NextToken" && expected != "" && got != "" {
			bindings[expected] = got
		}
		mapped, bound := bindings[expected]
		if !bound {
			encoded, _ := json.Marshal(expected)
			awsDecodeJSON(t, ec2AuditReplace(t, encoded, bindings), &mapped)
		}
		if mapped != got {
			t.Fatalf("%s: native %q, got %q", path, expected, got)
		}
	default:
		if !reflect.DeepEqual(native, actual) {
			t.Fatalf("%s: native %#v, got %#v", path, native, actual)
		}
	}
}

func ec2NetworkAction(operation string) string {
	var action strings.Builder
	for _, word := range strings.Split(operation, "-") {
		action.WriteString(strings.ToUpper(word[:1]))
		action.WriteString(word[1:])
	}
	return action.String()
}

func TestEC2NativeNetworkLifecycle(t *testing.T) {
	rows := ec2NetworkCaptures(t)
	rows = slices.DeleteFunc(rows, func(row ec2NetworkCapture) bool { return row.Sequence >= 149 })
	replayEC2NetworkRows(t, rows)
}

func replayEC2NetworkRows(t *testing.T, rows []ec2NetworkCapture) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(rows[0].StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "000000000000", Clock: source})
			bindings := map[string]string{}
			addresses := newEC2NetworkAddresses(bindings)
			for index := 0; index < len(rows); index++ {
				row := rows[index]
				// Account preflights and CLI errors are not EC2 service outcomes.
				if row.Service != "ec2" || row.Code == "CLIError" {
					continue
				}
				if row.Sequence == 0 {
					row.Sequence = index + 1
				}
				if row.StartedAt.After(source.Now()) {
					source.Advance(row.StartedAt.Sub(source.Now()))
				}
				action := ec2NetworkAction(row.Operation)
				if !t.Run(fmt.Sprintf("%03d_%s", row.Sequence, row.Label), func(t *testing.T) {
					input := ec2NetworkInput(t, row, bindings)
					wire := &awstest.WireClient{Client: clients.server.Client()}
					options := ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: wire, RetryMaxAttempts: 1}
					client := ec2.New(options)
					actual, err := awstest.CallSDK(t.Context(), client, action, input)
					if row.Code != "Success" {
						assertAPIError(t, err, row.Code)
					} else if err != nil {
						t.Fatal(err)
					}
					if wire.Status != row.HTTPStatus {
						t.Fatalf("HTTP status %d, native %d", wire.Status, row.HTTPStatus)
					}
					if err == nil {
						options.HTTPClient = nativeXMLResponse(row.RawResponseBody)
						expected, decodeErr := awstest.CallSDK(t.Context(), ec2.New(options), action, row.Input)
						if decodeErr != nil {
							t.Fatalf("decode retained native response: %v", decodeErr)
						}
						got, want := ec2NetworkDocument(t, actual), ec2NetworkDocument(t, expected)
						if action == "DescribeNetworkInterfaces" {
							var request ec2.DescribeNetworkInterfacesInput
							if err := json.Unmarshal(input, &request); err != nil {
								t.Fatal(err)
							}
							if request.MaxResults != nil && request.NextToken == nil {
								var consumed int
								want, got, consumed = ec2NetworkInterfacePages(t, client, rows[index:], expected.(*ec2.DescribeNetworkInterfacesOutput), actual.(*ec2.DescribeNetworkInterfacesOutput), bindings)
								index += consumed - 1
							}
						}
						addresses.observe(t, action, row.Input, want, got)
						ec2NetworkSort(t, got, bindings, false)
						ec2NetworkSort(t, want, bindings, true)
						addresses.comparePlacement(t, want, got)
						ec2NetworkCompare(t, "response", want, got, bindings)
					}
					if row.Audit != nil {
						requestID := nativeAuditRequestID(t, actual, err)
						trails := cloudtrail.New(cloudtrail.Options{Region: options.Region, BaseEndpoint: options.BaseEndpoint, Credentials: options.Credentials, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
						record := auditLookupRecord(t, trails, requestID, action)
						assertEC2AuditCapture(t, source.Now(), row.Audit, record, requestID, err, bindings, addresses.normalizeAuditPlacement)
					}
				}) {
					return
				}
				if row.Code == "Success" && !strings.HasPrefix(action, "Describe") {
					clients = reopen()
				}
			}
		})
	}
}

// The SDK/CLI supplied creation tokens before sending the native request, but
// older captures recorded their input before that middleware ran. Restore the
// actual token from its native response or audit record instead of comparing random SDK tokens.
func ec2NetworkInput(t *testing.T, row ec2NetworkCapture, bindings map[string]string) json.RawMessage {
	t.Helper()
	input := ec2AuditReplace(t, row.Input, bindings)
	action := ec2NetworkAction(row.Operation)
	if (action != "CreateRouteTable" && action != "CreateNetworkAcl" && action != "CreateNetworkInterface") || (row.Code != "Success" && row.Audit == nil) {
		return input
	}
	var parameters map[string]json.RawMessage
	if err := json.Unmarshal(input, &parameters); err != nil {
		t.Fatal(err)
	}
	if parameters["ClientToken"] == nil {
		var token *string
		if request, ok := row.Audit["requestParameters"].(map[string]any); ok {
			if value, ok := request["clientToken"].(string); ok {
				token = &value
			}
		}
		if token == nil && row.Code == "Success" {
			var output struct {
				ClientToken *string `xml:"clientToken"`
			}
			if err := xml.Unmarshal([]byte(row.RawResponseBody), &output); err != nil {
				t.Fatal(err)
			}
			token = output.ClientToken
		}
		if token != nil {
			parameters["ClientToken"], _ = json.Marshal(*token)
			input, _ = json.Marshal(parameters)
		}
	}
	return input
}

func TestEC2NativeNetworkCreationTokens(t *testing.T) {
	for _, name := range []string{"route_table_idempotency", "network_acl_idempotency", "network_creation_whitespace", "network_creation_token_length"} {
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile("../testdata/aws/ec2/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct{ Calls []ec2NetworkCapture }
			if err := json.Unmarshal(body, &fixture); err != nil {
				t.Fatal(err)
			}
			rows := make([]ec2NetworkCapture, 0, len(fixture.Calls))
			for index, row := range fixture.Calls {
				row.Sequence = index + 1
				switch row.Label {
				case "case_changed_token_distinct_request", "case_changed_token_retry_after_internal_error", "lowercase_variant_of_fresh_uppercase":
					t.Run(row.Label, func(t *testing.T) {
						t.Skip("native case-only token requests returned InternalError; unresolved AWS anomaly retained in fixture, not claimed conformant")
					})
				default:
					rows = append(rows, row)
				}
			}
			replayEC2NetworkRows(t, rows)
		})
	}
}

type ec2WireElement struct {
	XMLName  xml.Name
	Text     string           `xml:",chardata"`
	Children []ec2WireElement `xml:",any"`
}

func ec2WireCanonical(element *ec2WireElement) {
	element.Text = strings.TrimSpace(element.Text)
	switch element.XMLName.Local {
	case "requestId", "RequestID":
		element.Text = "<request-id>"
	case "Message":
		element.Text = "<diagnostic>"
	}
	for index := range element.Children {
		ec2WireCanonical(&element.Children[index])
	}
	slices.SortFunc(element.Children, func(a, b ec2WireElement) int { return strings.Compare(a.XMLName.Local, b.XMLName.Local) })
}

func TestEC2NativeQueryWire(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/ec2/networking.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Wire struct {
			Calls []struct {
				Label, Method   string
				Parameters      [][2]string       `json:"wire_parameters"`
				Status          int               `json:"http_status"`
				Headers         map[string]string `json:"response_headers"`
				RawResponseBody string
			}
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	clients := clockCloud(t, stackd.Config{AccountID: "000000000000"})
	for _, row := range fixture.Wire.Calls {
		t.Run(row.Label, func(t *testing.T) {
			var encoded strings.Builder
			for index, pair := range row.Parameters {
				if index > 0 {
					encoded.WriteByte('&')
				}
				encoded.WriteString(url.QueryEscape(pair[0]))
				encoded.WriteByte('=')
				encoded.WriteString(url.QueryEscape(pair[1]))
			}
			target, body := clients.server.URL, encoded.String()
			if row.Method == http.MethodGet {
				target, body = target+"?"+body, ""
			}
			request, err := http.NewRequestWithContext(t.Context(), row.Method, target, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			digest := sha256.Sum256([]byte(body))
			wireQuery := request.URL.RawQuery
			if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, request, hex.EncodeToString(digest[:]), "ec2", "us-east-1", time.Now()); err != nil {
				t.Fatal(err)
			}
			// SigV4 sorts duplicate values for signing; EC2 still interprets
			// duplicates in their original wire order after verification.
			request.URL.RawQuery = wireQuery
			response, err := clients.server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			actual, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != row.Status {
				t.Fatalf("HTTP %d, native %d: %s", response.StatusCode, row.Status, actual)
			}
			if response.Header.Get("Content-Type") != row.Headers["Content-Type"] {
				t.Fatalf("Content-Type %q, native %q", response.Header.Get("Content-Type"), row.Headers["Content-Type"])
			}
			var got, want ec2WireElement
			if err := xml.Unmarshal(actual, &got); err != nil {
				t.Fatal(err)
			}
			if err := xml.Unmarshal([]byte(row.RawResponseBody), &want); err != nil {
				t.Fatal(err)
			}
			for _, child := range got.Children {
				if (child.XMLName.Local == "requestId" || child.XMLName.Local == "RequestID") && child.Text != response.Header.Get("X-Amzn-Requestid") {
					t.Fatalf("body request ID %q differs from header %q", child.Text, response.Header.Get("X-Amzn-Requestid"))
				}
			}
			ec2WireCanonical(&got)
			ec2WireCanonical(&want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("native XML differs\n got %#v\nwant %#v\nbody %s", got, want, actual)
			}
		})
	}
}
