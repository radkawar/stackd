package sesv2_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"reflect"
	"stackd/internal/awsapi"
	classic "stackd/internal/awsapi/ses"
	api "stackd/internal/awsapi/sesv2"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	service "stackd/internal/services/sesv2"
	"stackd/storage/sqlite"
	sqlrepo "stackd/storage/sqlite/sesv2"
	"strings"
	"testing"
)

func classicCommand(t *testing.T, s *service.Service, scope service.Scope, action string, in any) (any, *awswire.Error) {
	t.Helper()
	model, _ := awscatalog.LookupService("ses")
	op, _ := model.Operation(action)
	return s.Classic().ExecuteCommand(contextFor(t, scope), awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: in})
}
func classicSuccess(t *testing.T, s *service.Service, action string, in any) any {
	t.Helper()
	out, e := classicCommand(t, s, scope, action, in)
	if e != nil {
		t.Fatalf("%s: %v", action, e)
	}
	return out
}
func identityState(t *testing.T, r service.Repository, key service.ResourceKey) service.Identity {
	t.Helper()
	var id service.Identity
	if e := r.View(t.Context(), func(r service.Reader) error {
		var e error
		id, e = r.Identity(key)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	return id
}
func followVerification(t *testing.T, s *service.Service, token string, want int) {
	t.Helper()
	out := httptest.NewRecorder()
	s.VerificationHandler().ServeHTTP(out, httptest.NewRequest("GET", service.VerificationPath+"?token="+token, nil))
	if out.Code != want {
		t.Fatalf("verification status %d, want %d: %s", out.Code, want, out.Body.String())
	}
}

func TestClassicVerificationSharesIdentityState(t *testing.T) {
	r := service.NewMemoryRepository(nil)
	s := service.NewWithConfig(service.Config{Repository: r, PublicEndpoint: "http://localhost"})
	defer s.Close()
	key := service.ResourceKey{Scope: scope, Name: "sender@example.invalid"}
	classicSuccess(t, s, "VerifyEmailIdentity", &classic.VerifyEmailIdentityInput{EmailAddress: new(classic.Address(key.Name))})
	first := identityState(t, r, key)
	deny := `{"Statement":{"Effect":"Deny","Principal":"*","Action":"ses:SendEmail","Resource":"` + key.ARN("identity") + `"}}`
	classicSuccess(t, s, "PutIdentityPolicy", &classic.PutIdentityPolicyInput{Identity: new(classic.Identity(key.Name)), PolicyName: new(classic.PolicyName("retained")), Policy: new(classic.Policy(deny))})
	classicSuccess(t, s, "VerifyEmailAddress", &classic.VerifyEmailAddressInput{EmailAddress: new(classic.Address(key.Name))})
	second := identityState(t, r, key)
	followVerification(t, s, first.VerificationToken, 400)
	pending := success(t, s, "GetEmailIdentity", &api.GetEmailIdentityInput{EmailIdentity: new(api.Identity(key.Name))}).(*api.GetEmailIdentityOutput)
	if *pending.VerificationStatus != api.VerificationStatusPENDING || bool(*pending.VerifiedForSendingStatus) {
		t.Fatalf("pending classic identity in v2: %+v", pending)
	}
	listed := classicSuccess(t, s, "ListVerifiedEmailAddresses", &classic.ListVerifiedEmailAddressesInput{}).(*classic.ListVerifiedEmailAddressesOutput)
	if len(listed.VerifiedEmailAddresses) != 0 {
		t.Fatalf("pending address returned as verified: %v", listed.VerifiedEmailAddresses)
	}
	followVerification(t, s, second.VerificationToken, 200)
	followVerification(t, s, second.VerificationToken, 400)
	if _, e := command(t, s, scope, "SendEmail", simple("success@simulator.amazonses.com")); e == nil || e.Code != "AccessDeniedException" {
		t.Fatalf("repeat verification lost sending policy: %v", e)
	}
	attrs := classicSuccess(t, s, "GetIdentityVerificationAttributes", &classic.GetIdentityVerificationAttributesInput{Identities: classic.IdentityList{classic.Identity(key.Name), "missing@example.invalid"}}).(*classic.GetIdentityVerificationAttributesOutput)
	if len(attrs.VerificationAttributes) != 1 || *attrs.VerificationAttributes[classic.Identity(key.Name)].VerificationStatus != classic.VerificationStatusSuccess {
		t.Fatalf("verification projection: %+v", attrs)
	}
	listed = classicSuccess(t, s, "ListVerifiedEmailAddresses", &classic.ListVerifiedEmailAddressesInput{}).(*classic.ListVerifiedEmailAddressesOutput)
	if !reflect.DeepEqual(listed.VerifiedEmailAddresses, classic.AddressList{classic.Address(key.Name)}) {
		t.Fatal(listed.VerifiedEmailAddresses)
	}
	classicSuccess(t, s, "DeleteVerifiedEmailAddress", &classic.DeleteVerifiedEmailAddressInput{EmailAddress: new(classic.Address(key.Name))})
	if _, e := command(t, s, scope, "GetEmailIdentity", &api.GetEmailIdentityInput{EmailIdentity: new(api.Identity(key.Name))}); e == nil || e.Code != "NotFoundException" {
		t.Fatalf("classic deletion not visible in v2: %v", e)
	}
	classicSuccess(t, s, "DeleteIdentity", &classic.DeleteIdentityInput{Identity: new(classic.Identity(key.Name))})
}

func TestIdentityPoliciesControlDelegatedSending(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var r service.Repository = service.NewMemoryRepository(nil)
			reopen := func() {}
			if backend == "sqlite" {
				path := filepath.Join(t.TempDir(), "state.db")
				db, e := sqlite.Open(t.Context(), path)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { db.Close() })
				r = sqlrepo.New(db)
				reopen = func() {
					if e := db.Close(); e != nil {
						t.Fatal(e)
					}
					db, e = sqlite.Open(t.Context(), path)
					if e != nil {
						t.Fatal(e)
					}
					r = sqlrepo.New(db)
				}
			}
			s := service.NewWithConfig(service.Config{Repository: r, PublicEndpoint: "http://localhost"})
			t.Cleanup(func() { s.Close() })
			verify(t, s, r, "sender@example.invalid")
			arn := (service.ResourceKey{Scope: scope, Name: "sender@example.invalid"}).ARN("identity")
			delegate := scope
			delegate.AccountID = "999999999999"
			in := simple("success@simulator.amazonses.com")
			in.FromEmailAddressIdentityArn = new(api.AmazonResourceName(arn))
			if _, e := command(t, s, delegate, "SendEmail", in); e == nil || e.Code != "AccessDeniedException" {
				t.Fatalf("cross-account send without owner grant: %v", e)
			}
			document := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"ses:SendEmail","Resource":"` + arn + `","Condition":{"StringEquals":{"ses:FromAddress":"sender@example.invalid","ses:ApiVersion":"2"}}}]}`
			classicSuccess(t, s, "PutIdentityPolicy", &classic.PutIdentityPolicyInput{Identity: new(classic.Identity(arn)), PolicyName: new(classic.PolicyName("delegate")), Policy: new(classic.Policy(document))})
			policies := success(t, s, "GetEmailIdentityPolicies", &api.GetEmailIdentityPoliciesInput{EmailIdentity: new(api.Identity("sender@example.invalid"))}).(*api.GetEmailIdentityPoliciesOutput)
			if policies.Policies["delegate"] != api.Policy(document) {
				t.Fatalf("classic policy absent in v2: %v", policies.Policies)
			}
			s.Close()
			reopen()
			s = service.NewWithConfig(service.Config{Repository: r, PublicEndpoint: "http://localhost"})
			out, e := command(t, s, delegate, "SendEmail", in)
			if e != nil {
				t.Fatalf("retained delegated send: %v", e)
			}
			messageID := string(*out.(*api.SendEmailOutput).MessageId)
			if e := r.View(context.Background(), func(r service.Reader) error {
				m, e := r.Message(service.ResourceKey{Scope: delegate, Name: messageID})
				if e != nil {
					return e
				}
				from, e := mail.ParseAddress(m.From)
				if e != nil || from.Address != "sender@example.invalid" || m.Text != "plain body" {
					t.Fatalf("delegated MIME envelope: %+v (%v)", m, e)
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			classicInput := &classic.SendEmailInput{Source: new(classic.Address("sender@example.invalid")), SourceArn: new(classic.AmazonResourceName(arn)), Destination: &classic.Destination{ToAddresses: classic.AddressList{"success@simulator.amazonses.com"}}, Message: &classic.Message{Subject: &classic.Content{Data: new(classic.MessageData("subject"))}, Body: &classic.Body{Text: &classic.Content{Data: new(classic.MessageData("body"))}}}}
			if _, e := classicCommand(t, s, delegate, "SendEmail", classicInput); e == nil || e.Code != "AccessDenied" {
				t.Fatalf("v2 ApiVersion policy allowed classic send: %v", e)
			}
			if _, e := classicCommand(t, s, delegate, "GetIdentityPolicies", &classic.GetIdentityPoliciesInput{Identity: new(classic.Identity(arn)), PolicyNames: classic.PolicyNameList{"delegate"}}); e == nil || e.Code != "AccessDenied" {
				t.Fatalf("delegate read owner policy: %v", e)
			}
			deny := `{"Statement":{"Effect":"Deny","Principal":"*","Action":"ses:SendEmail","Resource":"` + arn + `"}}`
			success(t, s, "CreateEmailIdentityPolicy", &api.CreateEmailIdentityPolicyInput{EmailIdentity: new(api.Identity("sender@example.invalid")), PolicyName: new(api.PolicyName("block")), Policy: new(api.Policy(document))})
			success(t, s, "UpdateEmailIdentityPolicy", &api.UpdateEmailIdentityPolicyInput{EmailIdentity: new(api.Identity("sender@example.invalid")), PolicyName: new(api.PolicyName("block")), Policy: new(api.Policy(deny))})
			if _, e := command(t, s, delegate, "SendEmail", in); e == nil || e.Code != "AccessDeniedException" {
				t.Fatalf("explicit owner denial ignored: %v", e)
			}
			classicSuccess(t, s, "DeleteIdentityPolicy", &classic.DeleteIdentityPolicyInput{Identity: new(classic.Identity(arn)), PolicyName: new(classic.PolicyName("block"))})
			if _, e := command(t, s, delegate, "SendEmail", in); e != nil {
				t.Fatalf("removed deny still applied: %v", e)
			}
			success(t, s, "DeleteEmailIdentityPolicy", &api.DeleteEmailIdentityPolicyInput{EmailIdentity: new(api.Identity("sender@example.invalid")), PolicyName: new(api.PolicyName("delegate"))})
			if _, e := command(t, s, delegate, "SendEmail", in); e == nil || e.Code != "AccessDeniedException" {
				t.Fatalf("revoked grant still applied: %v", e)
			}
			classicSuccess(t, s, "DeleteIdentityPolicy", &classic.DeleteIdentityPolicyInput{Identity: new(classic.Identity(arn)), PolicyName: new(classic.PolicyName("delegate"))})
		})
	}
}

func TestNativeClassicIdentityPolicies(t *testing.T) {
	raw, e := os.ReadFile("../../../testdata/aws/ses/classic-validation.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Region string
		Caller struct{ Account string }
		Calls  []struct {
			Label, Service, Operation, Code string
			Parameters, Output              json.RawMessage
		}
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	nativeScope := service.Scope{Partition: "aws", AccountID: fixture.Caller.Account, Region: fixture.Region}
	s := service.NewWithConfig(service.Config{PublicEndpoint: "http://localhost"})
	defer s.Close()
	labels := map[string]bool{
		"missing-identities": true, "missing-policy-list": true, "missing-policy-get": true, "missing-policy-delete": true,
		"verify-email": true, "repeat-verify-email": true, "identity-case-lookup": true, "v2-duplicate-pending-identity": true,
		"v2-update-missing-policy": true, "pending-policy-get-absent": true, "pending-policy-delete-absent": true,
		"policy-invalid-json": true, "policy-wrong-resource": true, "policy-invalid-principal": true,
		"policy-put": true, "policy-overwrite": true, "policy-list": true, "policy-get": true, "v2-duplicate-policy": true,
	}
	for _, row := range fixture.Calls {
		if !labels[row.Label] {
			continue
		}
		parts := strings.Split(row.Operation, "-")
		for i, part := range parts {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
		action := strings.Join(parts, "")
		model, _ := awscatalog.LookupService(row.Service)
		op, _ := model.Operation(action)
		newInput := classic.NewInput
		if row.Service == "sesv2" {
			newInput = api.NewInput
		}
		in, e := newInput(action)
		if e != nil {
			t.Fatal(e)
		}
		if e = awsapi.DecodeSDKInput(model, op, row.Parameters, in); e != nil {
			t.Fatal(e)
		}
		var out any
		var rejected *awswire.Error
		if row.Service == "sesv2" {
			out, rejected = command(t, s, nativeScope, action, in)
		} else {
			out, rejected = classicCommand(t, s, nativeScope, action, in)
		}
		code := "Success"
		if rejected != nil {
			code = rejected.Code
		}
		if code != row.Code {
			t.Fatalf("%s: got %v, native %s", row.Label, rejected, row.Code)
		}
		if rejected != nil {
			continue
		}
		encoded, e := json.Marshal(out)
		if e != nil {
			t.Fatal(e)
		}
		var got, want map[string]any
		if e = json.Unmarshal(encoded, &got); e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(row.Output, &want); e != nil {
			t.Fatal(e)
		}
		for _, output := range []map[string]any{got, want} {
			if policies, ok := output["Policies"].(map[string]any); ok {
				for name, document := range policies {
					var parsed any
					if e = json.Unmarshal([]byte(document.(string)), &parsed); e != nil {
						t.Fatal(e)
					}
					policies[name] = parsed
				}
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: got %#v, native %#v", row.Label, got, want)
		}
	}
}
