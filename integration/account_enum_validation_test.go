package stackd_test

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/smithy-go"
)

func TestAccountLegacyEnumErrorsMatchAWS(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/account/validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Operation, Code string
			Input                 json.RawMessage
			Error                 struct {
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
		t.Run(row.Case, func(t *testing.T) {
			var err error
			switch row.Operation {
			case "get-alternate-contact":
				var input account.GetAlternateContactInput
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				_, err = client.GetAlternateContact(t.Context(), &input)
			case "list-regions":
				var input account.ListRegionsInput
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				_, err = client.ListRegions(t.Context(), &input)
			}
			if row.Code == "Success" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			assertAPIError(t, err, row.Code)
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) {
				t.Fatal(err)
			}
			want, got := row.Error.Message, apiErr.ErrorMessage()
			if row.Code == "AccessDeniedException" {
				_, want, _ = strings.Cut(want, " is not authorized")
				_, got, _ = strings.Cut(got, " is not authorized")
			} else {
				var invalid *accounttypes.ValidationException
				if !errors.As(err, &invalid) || invalid.Reason != "" || len(invalid.FieldList) != 0 {
					t.Fatal("invented validation details", err)
				}
			}
			if got != want {
				t.Fatalf("AWS enum error differs: %q != %q", got, want)
			}
		})
	}
}
