package sesv2_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"stackd/internal/awsapi"
	classic "stackd/internal/awsapi/ses"
	api "stackd/internal/awsapi/sesv2"
	"stackd/internal/awscatalog"
	service "stackd/internal/services/sesv2"
	"stackd/storage/sqlite"
	sqlrepo "stackd/storage/sqlite/sesv2"
	"strings"
	"testing"
)

func TestClassicNativeSendAndControlBoundaries(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/ses/classic-validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Calls []struct {
			Label, Operation, Service, Code string
			Parameters                      json.RawMessage
		}
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	selected := map[string]bool{
		"missing-template-get": true, "missing-template-update": true, "missing-template-delete": true,
		"missing-configuration-get": true, "missing-configuration-delete": true,
		"create-template": true, "duplicate-template": true, "create-configuration": true, "duplicate-configuration": true,
		"simple-unverified": true, "simple-empty-body": true, "simple-malformed-address": true, "simple-missing-configuration": true,
		"raw-unverified": true, "raw-malformed": true, "template-unverified": true, "template-missing": true, "template-bad-json": true,
		"bulk-unverified": true, "bulk-missing-template": true, "bulk-bad-json": true,
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var r service.Repository = service.NewMemoryRepository(nil)
			if backend == "sqlite" {
				db, e := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
				if e != nil {
					t.Fatal(e)
				}
				defer db.Close()
				r = sqlrepo.New(db)
			}
			owner := service.NewWithConfig(service.Config{Repository: r, PublicEndpoint: "http://localhost"})
			defer owner.Close()
			frontend := owner.Classic()
			model, _ := awscatalog.LookupService("ses")
			seen := map[string]bool{}
			for _, row := range fixture.Calls {
				if !selected[row.Label] {
					continue
				}
				seen[row.Label] = true
				action := ""
				for _, part := range strings.Split(row.Operation, "-") {
					action += strings.ToUpper(part[:1]) + part[1:]
				}
				input, e := classic.NewInput(action)
				if e != nil {
					t.Fatal(e)
				}
				if e = json.Unmarshal(row.Parameters, input); e != nil {
					t.Fatal(e)
				}
				op, _ := model.Operation(action)
				_, rejected := frontend.ExecuteCommand(contextFor(t, scope), awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
				code := "Success"
				if rejected != nil {
					code = rejected.Code
				}
				if code != row.Code {
					t.Fatalf("%s: got %s (%v), native %s", row.Label, code, rejected, row.Code)
				}
			}
			for label := range selected {
				if !seen[label] {
					t.Fatalf("missing native fixture case %s", label)
				}
			}
			if e := r.View(t.Context(), func(reader service.Reader) error {
				messages, e := reader.Messages(scope)
				if e != nil {
					return e
				}
				for _, m := range messages {
					if m.ContentKind != "SES_VERIFICATION" {
						t.Fatalf("rejected native send persisted message %s", m.Key.Name)
					}
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestClassicBulkControlAdmissionAndSharedStatuses(t *testing.T) {
	r := service.NewMemoryRepository(nil)
	s := service.NewWithConfig(service.Config{Repository: r, PublicEndpoint: "http://localhost"})
	defer s.Close()
	verify(t, s, r, "sender@example.invalid")
	input := &classic.SendBulkTemplatedEmailInput{Source: new(classic.Address("sender@example.invalid")), Template: new(classic.TemplateName("missing")), DefaultTemplateData: new(classic.TemplateData("{}")), Destinations: classic.BulkEmailDestinationList{{Destination: &classic.Destination{ToAddresses: classic.AddressList{"success@simulator.amazonses.com"}}}}}
	model, _ := awscatalog.LookupService("ses")
	op, _ := model.Operation("SendBulkTemplatedEmail")
	_, rejected := s.Classic().ExecuteCommand(contextFor(t, scope), awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
	if rejected == nil || rejected.Code != "TemplateDoesNotExist" {
		t.Fatalf("missing bulk template was accepted: %v", rejected)
	}
	v2 := &api.SendBulkEmailInput{FromEmailAddress: new(api.EmailAddress("sender@example.invalid")), DefaultContent: &api.BulkEmailContent{Template: &api.Template{TemplateName: new(api.EmailTemplateName("missing"))}}, BulkEmailEntries: api.BulkEmailEntryList{{Destination: &api.Destination{ToAddresses: api.EmailAddressList{"success@simulator.amazonses.com"}}}}}
	out := success(t, s, "SendBulkEmail", v2).(*api.SendBulkEmailOutput)
	if out.BulkEmailEntryResults[0].Status == nil || *out.BulkEmailEntryResults[0].Status != api.BulkEmailStatusTEMPLATE_NOT_FOUND {
		t.Fatal("v2 returned a status outside its modeled template failure")
	}
	classicSuccess(t, s, "CreateConfigurationSet", &classic.CreateConfigurationSetInput{ConfigurationSet: &classic.ConfigurationSet{Name: new(classic.ConfigurationSetName("paused"))}})
	classicSuccess(t, s, "UpdateConfigurationSetSendingEnabled", &classic.UpdateConfigurationSetSendingEnabledInput{ConfigurationSetName: new(classic.ConfigurationSetName("paused")), Enabled: new(classic.Enabled(false))})
	input.ConfigurationSetName = new(classic.ConfigurationSetName("paused"))
	_, rejected = s.Classic().ExecuteCommand(contextFor(t, scope), awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
	if rejected == nil || rejected.Code != "ConfigurationSetSendingPaused" {
		t.Fatalf("paused classic configuration was accepted: %v", rejected)
	}
	success(t, s, "PutAccountSendingAttributes", &api.PutAccountSendingAttributesInput{SendingEnabled: new(api.Enabled(false))})
	out = success(t, s, "SendBulkEmail", v2).(*api.SendBulkEmailOutput)
	if out.BulkEmailEntryResults[0].Status == nil || *out.BulkEmailEntryResults[0].Status != api.BulkEmailStatusACCOUNT_SENDING_PAUSED {
		t.Fatal("v2 did not distinguish account pause from suspension")
	}
}
