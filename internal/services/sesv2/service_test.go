package sesv2_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/sesv2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/sesv2"
	"stackd/storage/sqlite"
	sqlrepo "stackd/storage/sqlite/sesv2"
	"strings"
	"testing"
	"time"
)

var scope = service.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}

func contextFor(t *testing.T, scope service.Scope) context.Context {
	return awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":root"})
}
func command(t *testing.T, s *service.Service, scope service.Scope, action string, in any) (any, *awswire.Error) {
	t.Helper()
	model, _ := awscatalog.LookupService("sesv2")
	op, _ := model.Operation(action)
	return s.ExecuteCommand(contextFor(t, scope), awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: in})
}
func success(t *testing.T, s *service.Service, action string, in any) any {
	t.Helper()
	out, e := command(t, s, scope, action, in)
	if e != nil {
		t.Fatalf("%s: %v", action, e)
	}
	return out
}
func simple(to string) *api.SendEmailInput {
	return &api.SendEmailInput{FromEmailAddress: new(api.EmailAddress("sender@example.invalid")), Destination: &api.Destination{ToAddresses: api.EmailAddressList{api.EmailAddress(to)}}, Content: &api.EmailContent{Simple: &api.Message{Subject: &api.Content{Data: new(api.MessageData("Hello café"))}, Body: &api.Body{Text: &api.Content{Data: new(api.MessageData("plain body"))}, Html: &api.Content{Data: new(api.MessageData("<p>HTML body</p>"))}}}}}
}
func verify(t *testing.T, s *service.Service, r service.Repository, address string) {
	t.Helper()
	success(t, s, "CreateEmailIdentity", &api.CreateEmailIdentityInput{EmailIdentity: new(api.Identity(address))})
	var id service.Identity
	if e := r.View(t.Context(), func(r service.Reader) error {
		var e error
		id, e = r.Identity(service.ResourceKey{Scope: scope, Name: address})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	request := httptest.NewRequest("GET", service.VerificationPath+"?token="+id.VerificationToken, nil)
	out := httptest.NewRecorder()
	s.VerificationHandler().ServeHTTP(out, request)
	if out.Code != 200 {
		t.Fatal(out.Code, out.Body.String())
	}
	again := httptest.NewRecorder()
	s.VerificationHandler().ServeHTTP(again, request)
	if again.Code != 400 {
		t.Fatal("verification token was reusable")
	}
}
func retained(t *testing.T, r service.Repository, id string) service.Message {
	t.Helper()
	var out service.Message
	if e := r.View(t.Context(), func(r service.Reader) error {
		var e error
		out, e = r.Message(service.ResourceKey{Scope: scope, Name: id})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	return out
}
func TestSendingMIMEAuthorityAndBulk(t *testing.T) {
	r := service.NewMemoryRepository(nil)
	dir := t.TempDir()
	s := service.NewWithConfig(service.Config{Repository: r, CaptureDirectory: dir, PublicEndpoint: "http://localhost:4566"})
	defer s.Close()
	_, e := command(t, s, scope, "SendEmail", simple("success@simulator.amazonses.com"))
	if e == nil || e.Code != "MessageRejected" {
		t.Fatalf("unverified sender: %v", e)
	}
	verify(t, s, r, "sender@example.invalid")
	_, e = command(t, s, scope, "SendEmail", simple("unverified@example.invalid"))
	if e == nil || e.Code != "MessageRejected" {
		t.Fatalf("sandbox recipient: %v", e)
	}
	input := simple("success@simulator.amazonses.com")
	input.Destination.BccAddresses = api.EmailAddressList{"complaint@simulator.amazonses.com"}
	out := success(t, s, "SendEmail", input).(*api.SendEmailOutput)
	m := retained(t, r, string(*out.MessageId))
	parsed, err := mail.ReadMessage(bytes.NewReader(m.MIME))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Get("Bcc") != "" || len(m.BCC) != 1 {
		t.Fatal("BCC envelope privacy violated")
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
	if err != nil || subject != "Hello café" {
		t.Fatalf("subject %q %v", subject, err)
	}
	kind, p, _ := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if kind != "multipart/alternative" {
		t.Fatal(kind)
	}
	multi := multipart.NewReader(parsed.Body, p["boundary"])
	part, err := multi.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(part)
	if string(body) != "plain body" {
		t.Fatalf("body=%q", body)
	}
	success(t, s, "CreateEmailTemplate", &api.CreateEmailTemplateInput{TemplateName: new(api.EmailTemplateName("greeting")), TemplateContent: &api.EmailTemplateContent{Subject: new(api.EmailTemplateSubject("Hi {{name}}")), Text: new(api.EmailTemplateText("Your code is {{code}}")), Html: new(api.EmailTemplateHtml("<b>{{name}}</b>"))}})
	bulk := success(t, s, "SendBulkEmail", &api.SendBulkEmailInput{FromEmailAddress: input.FromEmailAddress, DefaultContent: &api.BulkEmailContent{Template: &api.Template{TemplateName: new(api.EmailTemplateName("greeting")), TemplateData: new(api.EmailTemplateData(`{"name":"Alice & Bob","code":"123456"}`))}}, BulkEmailEntries: api.BulkEmailEntryList{{Destination: &api.Destination{ToAddresses: api.EmailAddressList{"success@simulator.amazonses.com"}}}, {Destination: &api.Destination{ToAddresses: api.EmailAddressList{"unverified@example.invalid"}}}, {Destination: &api.Destination{ToAddresses: api.EmailAddressList{"success@simulator.amazonses.com"}}, ReplacementEmailContent: &api.ReplacementEmailContent{ReplacementTemplate: &api.ReplacementTemplate{ReplacementTemplateData: new(api.EmailTemplateData(`{"name":"missing-code"}`))}}}}}).(*api.SendBulkEmailOutput)
	if string(*bulk.BulkEmailEntryResults[0].Status) != "SUCCESS" || string(*bulk.BulkEmailEntryResults[1].Status) != "MESSAGE_REJECTED" || string(*bulk.BulkEmailEntryResults[2].Status) != "FAILED" {
		t.Fatalf("bulk=%+v", bulk)
	}
	rendered := retained(t, r, string(*bulk.BulkEmailEntryResults[0].MessageId))
	if rendered.Subject != "Hi Alice & Bob" || rendered.HTML != "<b>Alice & Bob</b>" {
		t.Fatal(rendered.Subject, rendered.HTML)
	}
	if _, err = s.JobDriver().RunDue(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(service.CapturePath(dir, m.Key))
	if err != nil || !bytes.Equal(disk, m.MIME) {
		t.Fatal("MIME artifact differs", err)
	}
	for _, other := range []service.Scope{{"aws", "999999999999", "us-east-1"}, {"aws", "123456789012", "us-west-2"}, {"aws-cn", "123456789012", "us-east-1"}} {
		_, e = command(t, s, other, "SendEmail", input)
		if e == nil || e.Code != "MessageRejected" {
			t.Fatalf("scope leak %#v %v", other, e)
		}
	}
}
func TestRawMIMEAndMalformedInputs(t *testing.T) {
	r := service.NewMemoryRepository(nil)
	s := service.NewWithConfig(service.Config{Repository: r, PublicEndpoint: "http://localhost"})
	defer s.Close()
	verify(t, s, r, "sender@example.invalid")
	raw := "From: sender@example.invalid\r\nTo: success@simulator.amazonses.com\r\nBcc: complaint@simulator.amazonses.com\r\nSubject: Raw\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nbody\r\n--x\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=test.bin\r\n\r\nAAEC\r\n--x--\r\n"
	in := &api.SendEmailInput{Content: &api.EmailContent{Raw: &api.RawMessage{Data: []byte(raw)}}}
	out := success(t, s, "SendEmail", in).(*api.SendEmailOutput)
	m := retained(t, r, string(*out.MessageId))
	if bytes.Contains(m.MIME, []byte("Bcc:")) || len(m.BCC) != 1 || !bytes.Contains(m.MIME, []byte("AAEC")) {
		t.Fatal("raw MIME envelope/content lost")
	}
	for _, bad := range []string{"no headers", strings.Replace(raw, "--x--", "--wrong--", 1), strings.Replace(raw, "AAEC", "not base64!", 1), strings.Replace(raw, "body", strings.Repeat("x", 999), 1)} {
		in.Content.Raw.Data = []byte(bad)
		_, e := command(t, s, scope, "SendEmail", in)
		if e == nil || e.Code != "BadRequestException" {
			t.Fatalf("malformed MIME accepted: %v", e)
		}
	}
}
func TestCaptureRetrySurvivesSQLiteRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	c := clock.NewManual(time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC))
	dir := filepath.Join(t.TempDir(), "capture")
	if err = os.WriteFile(dir, []byte("block directory creation"), 0600); err != nil {
		t.Fatal(err)
	}
	r := sqlrepo.New(db)
	s := service.NewWithConfig(service.Config{Repository: r, Clock: c, CaptureDirectory: dir, PublicEndpoint: "http://localhost"})
	verify(t, s, r, "sender@example.invalid")
	out := success(t, s, "SendEmail", simple("success@simulator.amazonses.com")).(*api.SendEmailOutput)
	id := string(*out.MessageId)
	if _, err = s.JobDriver().RunDue(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	before := retained(t, r, id)
	if !before.CapturePending || before.CaptureError == "" {
		t.Fatal("capture failure lost pending ownership")
	}
	s.Close()
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r = sqlrepo.New(db)
	s = service.NewWithConfig(service.Config{Repository: r, Clock: c, CaptureDirectory: dir, PublicEndpoint: "http://localhost"})
	defer s.Close()
	if err = c.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = s.JobDriver().RunDue(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	after := retained(t, r, id)
	body, err := os.ReadFile(service.CapturePath(dir, after.Key))
	if err != nil || after.CapturePending || after.CaptureError != "" || !bytes.Equal(body, before.MIME) {
		t.Fatalf("capture restart lost bytes/ownership: %v pending=%v error=%s", err, after.CapturePending, after.CaptureError)
	}
}
func TestNativeSendingValidation(t *testing.T) {
	raw, e := os.ReadFile("../../../testdata/aws/sesv2/validation.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Calls []struct {
			Label, Code string
			Parameters  json.RawMessage
		}
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	s := service.NewWithConfig(service.Config{})
	defer s.Close()
	model, _ := awscatalog.LookupService("sesv2")
	op, _ := model.Operation("SendEmail")
	for _, row := range fixture.Calls {
		if row.Label == "account" {
			continue
		}
		var in api.SendEmailInput
		if e = awsapi.DecodeSDKInput(model, op, row.Parameters, &in); e != nil {
			t.Fatal(e)
		}
		_, rejected := command(t, s, scope, "SendEmail", &in)
		if rejected == nil || rejected.Code != row.Code {
			t.Fatalf("%s: got %v want %s", row.Label, rejected, row.Code)
		}
	}
}
