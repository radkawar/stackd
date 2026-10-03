package stackd_test

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
)

func TestAccountRegionValidationMatchesAWS(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/account/regions.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Case, Operation, Code string
			Input                 json.RawMessage
			Error                 struct {
				Message string                                 `json:"message"`
				Reason  accounttypes.ValidationExceptionReason `json:"reason"`
				Fields  []struct{ Name, Message string }       `json:"fieldList"`
			}
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	c := newCloudClients(t)
	client := c.account("test", "test", "")
	for _, row := range capture.Observations {
		if row.Case != "member_get_unknown-region" && row.Case != "member_get_cn-north-1" && row.Case != "invalid_token" && row.Case != "disable_again_disabled" {
			continue
		}
		t.Run(row.Case, func(t *testing.T) {
			var err error
			switch row.Operation {
			case "get-region-opt-status":
				var input account.GetRegionOptStatusInput
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				_, err = client.GetRegionOptStatus(t.Context(), &input)
			case "list-regions":
				var input account.ListRegionsInput
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				_, err = client.ListRegions(t.Context(), &input)
			case "disable-region":
				var input account.DisableRegionInput
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				_, err = client.DisableRegion(t.Context(), &input)
			}
			assertAPIError(t, err, row.Code)
			var invalid *accounttypes.ValidationException
			if !errors.As(err, &invalid) || aws.ToString(invalid.Message) != row.Error.Message || invalid.Reason != row.Error.Reason {
				t.Fatalf("AWS error details differ: %v", err)
			}
			fields := make([]struct{ Name, Message string }, len(invalid.FieldList))
			for i, field := range invalid.FieldList {
				fields[i].Name, fields[i].Message = aws.ToString(field.Name), aws.ToString(field.Message)
			}
			if !reflect.DeepEqual(fields, row.Error.Fields) {
				t.Fatalf("AWS validation fields differ: %+v != %+v", fields, row.Error.Fields)
			}
		})
	}
}
