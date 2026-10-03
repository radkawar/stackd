package stackd_test

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/smithy-go"

	"stackd/storage"
)

func TestAlternateContactLifecycleMatchesAWS(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/account/contacts.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Operation, Code string
			Input                 json.RawMessage
			Output                struct {
				AlternateContact *accounttypes.AlternateContact
			}
			Error struct {
				Message string `json:"message"`
			}
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	c := newCloudClients(t)
	client := c.account("test", "test", "")
	for _, row := range fixture.Observations {
		switch row.Case {
		case "missing_alternate_contact", "delete_missing_alternate_contact", "create_alternate_contact", "get_created_alternate_contact", "replace_alternate_contact", "get_replaced_alternate_contact", "delete_alternate_contact", "get_deleted_alternate_contact", "delete_alternate_contact_again":
		default:
			continue
		}
		t.Run(row.Case, func(t *testing.T) {
			var err error
			var contact *accounttypes.AlternateContact
			switch row.Operation {
			case "get-alternate-contact":
				var input account.GetAlternateContactInput
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				var output *account.GetAlternateContactOutput
				output, err = client.GetAlternateContact(t.Context(), &input)
				if output != nil {
					contact = output.AlternateContact
				}
			case "put-alternate-contact":
				var input account.PutAlternateContactInput
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				_, err = client.PutAlternateContact(t.Context(), &input)
			case "delete-alternate-contact":
				var input account.DeleteAlternateContactInput
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				_, err = client.DeleteAlternateContact(t.Context(), &input)
			}
			if row.Code == "Success" {
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(contact, row.Output.AlternateContact) {
					t.Fatalf("AWS contact differs: %+v != %+v", contact, row.Output.AlternateContact)
				}
			} else {
				assertAPIError(t, err, row.Code)
				var apiErr smithy.APIError
				if !errors.As(err, &apiErr) || apiErr.ErrorMessage() != row.Error.Message {
					t.Fatalf("AWS error message differs: %v", err)
				}
			}
		})
	}
}

func primaryContact() *accounttypes.ContactInformation {
	return &accounttypes.ContactInformation{FullName: aws.String("Account Owner"), AddressLine1: aws.String("1 Test Street"), AddressLine2: aws.String("Floor 2"), City: aws.String("London"), PostalCode: aws.String("SW1A 1AA"), CountryCode: aws.String("GB"), PhoneNumber: aws.String("+44 20 7946 0000"), CompanyName: aws.String("Example Company"), WebsiteUrl: aws.String("https://example.test")}
}

func TestPrimaryContactsCopyAtAccountCreationAndRemainIndependent(t *testing.T) {
	f := newOrganizationReportFixture(t, storage.NewMemory())
	ctx := t.Context()
	parent := f.cloud.account("test", "test", "")
	initial := primaryContact()
	if _, err := parent.PutContactInformation(ctx, &account.PutContactInformationInput{ContactInformation: initial}); err != nil {
		t.Fatal(err)
	}
	if _, err := parent.PutAlternateContact(ctx, &account.PutAlternateContactInput{AlternateContactType: accounttypes.AlternateContactTypeBilling, Name: aws.String("Owner"), Title: aws.String("Billing"), EmailAddress: aws.String("billing@example.test"), PhoneNumber: aws.String("2025550100")}); err != nil {
		t.Fatal(err)
	}
	member := f.account(t, f.rootID, "copied-contact")
	child := f.cloud.account(member, "test", "")
	out, err := child.GetContactInformation(ctx, &account.GetContactInformationInput{})
	if err != nil {
		t.Fatal(err)
	}
	expected := *initial
	expected.FullName = aws.String("copied-contact")
	if !reflect.DeepEqual(out.ContactInformation, &expected) {
		t.Fatalf("contact initialization: %+v", out.ContactInformation)
	}
	_, err = child.GetAlternateContact(ctx, &account.GetAlternateContactInput{AlternateContactType: accounttypes.AlternateContactTypeBilling})
	assertAPIError(t, err, "ResourceNotFoundException")
	initial.CompanyName = aws.String("Changed Parent")
	if _, err := parent.PutContactInformation(ctx, &account.PutContactInformationInput{ContactInformation: initial}); err != nil {
		t.Fatal(err)
	}
	out, err = child.GetContactInformation(ctx, &account.GetContactInformationInput{})
	if err != nil || !reflect.DeepEqual(out.ContactInformation, &expected) {
		t.Fatal("parent update changed copied contact", err)
	}
	expected.AddressLine2, expected.CompanyName, expected.WebsiteUrl = nil, nil, nil
	if _, err := child.PutContactInformation(ctx, &account.PutContactInformationInput{ContactInformation: &expected}); err != nil {
		t.Fatal(err)
	}
	out, err = child.GetContactInformation(ctx, &account.GetContactInformationInput{})
	if err != nil || !reflect.DeepEqual(out.ContactInformation, &expected) {
		t.Fatal("primary contact replacement retained omitted fields", err)
	}
	parentOut, err := parent.GetContactInformation(ctx, &account.GetContactInformationInput{})
	if err != nil || !reflect.DeepEqual(parentOut.ContactInformation, initial) {
		t.Fatal("child update changed parent", err)
	}
}

func TestAlternateContactTypePermissionAndAccountIsolation(t *testing.T) {
	c := newCloudClients(t)
	ctx := t.Context()
	_, key, secret := c.user(t, "test", "contact-editor")
	client := c.account(key, secret, "")
	in := &account.PutAlternateContactInput{AlternateContactType: accounttypes.AlternateContactTypeOperations, Name: aws.String("Operations"), Title: aws.String("Contact"), EmailAddress: aws.String("ops@example.test"), PhoneNumber: aws.String("2025550100")}
	_, err := client.PutAlternateContact(ctx, in)
	assertAPIError(t, err, "AccessDeniedException")
	putUserPolicy(t, c.iam("test", "test", ""), "contact-editor", `{"Statement":{"Effect":"Allow","Action":"account:*AlternateContact","Resource":"arn:aws:account::000000000000:account","Condition":{"ForAnyValue:StringEquals":{"account:AlternateContactTypes":"OPERATIONS"}}}}`)
	if _, err := client.PutAlternateContact(ctx, in); err != nil {
		t.Fatal(err)
	}
	_, err = client.GetAlternateContact(ctx, &account.GetAlternateContactInput{AlternateContactType: accounttypes.AlternateContactTypeBilling})
	assertAPIError(t, err, "AccessDeniedException")
	in.AlternateContactType = accounttypes.AlternateContactTypeBilling
	_, err = client.PutAlternateContact(ctx, in)
	assertAPIError(t, err, "AccessDeniedException")
	_, err = c.account("111111111111", "test", "").GetAlternateContact(ctx, &account.GetAlternateContactInput{AlternateContactType: accounttypes.AlternateContactTypeOperations})
	assertAPIError(t, err, "ResourceNotFoundException")
	_, err = client.GetContactInformation(ctx, &account.GetContactInformationInput{})
	assertAPIError(t, err, "AccessDeniedException")
	for _, kind := range []accounttypes.AlternateContactType{"operations", "OTHER"} {
		_, err = c.account("test", "test", "").GetAlternateContact(ctx, &account.GetAlternateContactInput{AlternateContactType: kind})
		assertAPIError(t, err, "AccessDeniedException")
	}
}

func TestPrimaryContactNormalizationAndRejectedWriteMatchAWS(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/account/primary_contact.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Code, Message string
			MatchesInput        map[string]bool `json:"matches_input"`
			MatchesOriginal     map[string]bool `json:"matches_original"`
			ResponseFields      []string        `json:"response_fields"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	c := newCloudClients(t)
	client := c.account("test", "test", "")
	original := map[string]string{"FullName": "Contact Owner", "AddressLine1": "1 Test Street", "City": "London", "StateOrRegion": "London", "PostalCode": "SW1A 1AA", "CountryCode": "GB", "PhoneNumber": "+44 20 7946 0000"}
	put := func(values map[string]string) error {
		t.Helper()
		body, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		var contact accounttypes.ContactInformation
		if err := json.Unmarshal(body, &contact); err != nil {
			t.Fatal(err)
		}
		_, err = client.PutContactInformation(t.Context(), &account.PutContactInformationInput{ContactInformation: &contact})
		return err
	}
	for _, row := range fixture.Observations {
		t.Run(row.Case, func(t *testing.T) {
			if err := put(original); err != nil {
				t.Fatal(err)
			}
			input := maps.Clone(original)
			switch {
			case strings.HasPrefix(row.Case, "whitespace_"):
				field := strings.TrimPrefix(row.Case, "whitespace_")
				input[field] = " " + input[field] + " "
			case strings.HasPrefix(row.Case, "blank_"):
				input[strings.TrimPrefix(row.Case, "blank_")] = " "
			case row.Case == "trailing_whitespace_PhoneNumber":
				input["PhoneNumber"] += " "
			case row.Case == "lowercase_country":
				input["CountryCode"] = strings.ToLower(input["CountryCode"])
			case row.Case == "omit_state_or_region":
				delete(input, "StateOrRegion")
			default:
				t.Fatalf("unknown native probe case %q", row.Case)
			}
			err := put(input)
			if row.Code == "Success" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				assertAPIError(t, err, row.Code)
				var invalid *accounttypes.ValidationException
				if !errors.As(err, &invalid) || invalid.Reason != "" || len(invalid.FieldList) != 0 {
					t.Fatalf("AWS validation envelope: %v", err)
				}
				if strings.HasPrefix(row.Message, "the argument ") && invalid.ErrorMessage() != row.Message {
					t.Fatalf("AWS contact validation message differs: %v", err)
				}
			}
			current, err := client.GetContactInformation(t.Context(), &account.GetContactInformationInput{})
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(current.ContactInformation)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]*string
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatal(err)
			}
			fields := []string{}
			for field, value := range got {
				if value != nil {
					fields = append(fields, field)
				}
			}
			slices.Sort(fields)
			if !slices.Equal(fields, row.ResponseFields) {
				t.Fatalf("AWS field presence differs: %v != %v", fields, row.ResponseFields)
			}
			for field, matched := range row.MatchesOriginal {
				if (got[field] != nil && *got[field] == original[field]) != matched {
					t.Errorf("%s: original-value comparison differs from AWS", field)
				}
			}
			for field, matched := range row.MatchesInput {
				if (got[field] != nil && *got[field] == input[field]) != matched {
					t.Errorf("%s: input-value comparison differs from AWS", field)
				}
			}
		})
	}
}
