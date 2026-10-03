package iam_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/services/iam"
)

// This complements the exact owned-user CSV replay with the captured API
// lifecycle, omitted fields, encoded wire content, and cache invariance. The
// pending worker is gated explicitly; AWS's elapsed generation time is not
// modeled as a fabricated delay.
func TestCredentialReportAWSLifecycleReplay(t *testing.T) {
	type observation struct {
		Case                 string            `json:"case"`
		Code                 string            `json:"code"`
		Message              string            `json:"message"`
		HTTPStatus           int               `json:"http_status"`
		Output               map[string]string `json:"output"`
		GeneratedTime        string            `json:"generated_time"`
		Format               string            `json:"report_format"`
		OutputFields         []string          `json:"output_fields"`
		Header               []string          `json:"header"`
		TrailingLF           bool              `json:"csv_ends_with_newline"`
		CRLF                 bool              `json:"csv_uses_crlf"`
		WireContentMatches   bool              `json:"wire_content_base64_matches_cli"`
		WireGeneratedTime    string            `json:"wire_generated_time"`
		ContentUnchanged     bool              `json:"content_identical_to_first_success"`
		GeneratedAtUnchanged bool              `json:"generated_time_identical_to_first_success"`
	}
	data, err := os.ReadFile("../../../testdata/aws/iam/credential_report.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		CaptureComplete bool          `json:"capture_complete"`
		CleanupVerified bool          `json:"cleanup_verified"`
		Observations    []observation `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.CaptureComplete || !fixture.CleanupVerified {
		t.Fatal("AWS fixture is not a completed, cleaned capture")
	}
	cases := make(map[string]observation)
	for _, row := range fixture.Observations {
		if _, exists := cases[row.Case]; exists {
			t.Fatalf("duplicate fixture case %q", row.Case)
		}
		cases[row.Case] = row
	}
	observed := func(name string) observation {
		t.Helper()
		row, ok := cases[name]
		if !ok {
			t.Fatalf("missing fixture case %q", name)
		}
		return row
	}
	completed := observed("completed_report")
	epoch, err := time.Parse(time.RFC3339, completed.GeneratedTime)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	repository := newCredentialReportTestRepository(nil, true)
	service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: clock.NewManual(epoch)})
	t.Cleanup(func() { repository.release(); _ = service.Close() })
	client := clientFor(t, service, scope.AccountID, "us-east-1")
	transport := &credentialReportWireTransport{base: http.DefaultTransport}
	options := client.Options()
	options.HTTPClient = &http.Client{Transport: transport}
	client = sdkiam.New(options)
	getError := func(name string) {
		t.Helper()
		row := observed(name)
		output, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
		requireCode(t, err, row.Code)
		requireCredentialReportHTTPStatus(t, err, row.HTTPStatus)
		var apiError smithy.APIError
		if !errors.As(err, &apiError) || apiError.ErrorMessage() != row.Message || output != nil {
			t.Fatalf("%s: output=%+v error=%v, AWS message=%q", name, output, err, row.Message)
		}
	}
	generate := func(name string) {
		t.Helper()
		row := observed(name)
		output, err := client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{})
		if err != nil {
			t.Fatal(err)
		}
		actual := map[string]string{"State": string(output.State)}
		if output.Description != nil {
			actual["Description"] = *output.Description
		}
		if !reflect.DeepEqual(actual, row.Output) {
			t.Fatalf("%s: generated=%v, AWS=%v", name, actual, row.Output)
		}
		wire, status := transport.last()
		var envelope struct {
			Result struct {
				State       string  `xml:"State"`
				Description *string `xml:"Description"`
			} `xml:"GenerateCredentialReportResult"`
		}
		if err := xml.Unmarshal(wire, &envelope); err != nil {
			t.Fatal(err)
		}
		if status != row.HTTPStatus || envelope.Result.State != actual["State"] || (envelope.Result.Description == nil) != (output.Description == nil) {
			t.Fatalf("%s wire=%s status=%d", name, wire, status)
		}
	}
	getError("existing_report")
	if _, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("before-report")}); err != nil {
		t.Fatal(err)
	}
	generate("generate_initial")
	getError("get_immediately_after_generate")
	repository.release()
	waitCredentialReportCommit(t, ctx, repository, scope, 1)
	generate("generate_poll_1")
	var original []byte
	get := func(name string) {
		t.Helper()
		row := observed(name)
		output, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
		if err != nil {
			t.Fatal(err)
		}
		if string(output.ReportFormat) != row.Format || output.GeneratedTime == nil || !output.GeneratedTime.Equal(epoch) {
			t.Fatalf("%s: metadata=%+v, AWS=%+v", name, output, row)
		}
		wire, status := transport.last()
		var envelope struct {
			Result struct {
				Content       string `xml:"Content"`
				GeneratedTime string `xml:"GeneratedTime"`
				ReportFormat  string `xml:"ReportFormat"`
				Fields        []struct {
					XMLName xml.Name
				} `xml:",any"`
			} `xml:"GetCredentialReportResult"`
		}
		if err := xml.Unmarshal(wire, &envelope); err != nil {
			t.Fatal(err)
		}
		if status != row.HTTPStatus || envelope.Result.Content != base64.StdEncoding.EncodeToString(output.Content) || envelope.Result.GeneratedTime != row.WireGeneratedTime || envelope.Result.ReportFormat != row.Format || !row.WireContentMatches {
			t.Fatalf("%s: generated report wire metadata or Base64 differs from capture", name)
		}
		// The three known fields plus any unexpected generated additions form
		// the complete API result field set, excluding response metadata.
		fields := []string{"Content", "GeneratedTime", "ReportFormat"}
		for _, field := range envelope.Result.Fields {
			fields = append(fields, field.XMLName.Local)
		}
		slices.Sort(fields)
		if !slices.Equal(fields, row.OutputFields) {
			t.Fatalf("%s: result fields=%v; AWS=%v", name, fields, row.OutputFields)
		}
		if strings.SplitN(string(output.Content), "\n", 2)[0] != strings.Join(row.Header, ",") || bytes.HasSuffix(output.Content, []byte("\n")) != row.TrailingLF || bytes.Contains(output.Content, []byte("\r\n")) != row.CRLF {
			t.Fatalf("%s: CSV header or line ending differs from AWS", name)
		}
		if name == "completed_report" {
			original = slices.Clone(output.Content)
		} else if !row.ContentUnchanged || !row.GeneratedAtUnchanged || !bytes.Equal(output.Content, original) {
			t.Fatalf("%s: cached report changed after a current IAM mutation", name)
		}
	}
	get("completed_report")
	generate("generate_cached_repeat")
	get("cached_report_repeat")
	if _, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("after-report")}); err != nil {
		t.Fatal(err)
	}
	generate("generate_after_new_user")
	get("cached_report_after_new_user")
	for _, name := range []string{"before-report", "after-report"} {
		if _, err := client.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String(name)}); err != nil {
			t.Fatal(err)
		}
	}
	get("cached_report_after_owned_cleanup")
}

// Recording the actual SDK transport response exercises generated Query output
// encoding and the SDK's Blob decoder together, without replacing either.
type credentialReportWireTransport struct {
	base   http.RoundTripper
	mu     sync.Mutex
	body   []byte
	status int
}

func (transport *credentialReportWireTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	transport.mu.Lock()
	transport.body, transport.status = slices.Clone(body), response.StatusCode
	transport.mu.Unlock()
	return response, nil
}

func (transport *credentialReportWireTransport) last() ([]byte, int) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return slices.Clone(transport.body), transport.status
}
