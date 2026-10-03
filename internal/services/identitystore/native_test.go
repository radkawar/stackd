package identitystore_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/identitystore"
	"stackd/internal/awsctx"
	service "stackd/internal/services/identitystore"
)

func TestNativeAbsentUserAndGroupMembership(t *testing.T) {
	raw, e := os.ReadFile("../../../testdata/aws/identitystore/read_only.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Account, Region string
		StoreID         string `json:"identity_store_id"`
		Calls           []struct {
			Operation     string
			Input, Output json.RawMessage
			Error         struct{ Code string }
		}
	}
	if e := json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	scope := service.Scope{Partition: "aws", AccountID: fixture.Account, Region: fixture.Region}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::" + scope.AccountID + ":root"})
	s := service.NewWithConfig(service.Config{})
	if e := s.EnsureStore(ctx, scope, fixture.StoreID); e != nil {
		t.Fatal(e)
	}
	for _, call := range fixture.Calls {
		t.Run(call.Operation, func(t *testing.T) {
			request, e := api.DecodeRequest(call.Operation, awsapi.Request{JSON: call.Input})
			if e != nil {
				t.Fatal(e)
			}
			output, rejected := s.ExecuteCommand(ctx, request)
			if call.Error.Code != "" {
				if rejected == nil || rejected.Code != call.Error.Code {
					t.Fatalf("expected native modeled %s, got %v", call.Error.Code, rejected)
				}
				return
			}
			if rejected != nil {
				t.Fatal(rejected)
			}
			encoded, e := json.Marshal(output)
			if e != nil {
				t.Fatal(e)
			}
			var want, got any
			if e := json.Unmarshal(call.Output, &want); e != nil {
				t.Fatal(e)
			}
			if e := json.Unmarshal(encoded, &got); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("membership observation differs: got %s want %s", encoded, call.Output)
			}
		})
	}
}
