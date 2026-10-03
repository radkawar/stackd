package memorydb

import (
	"encoding/json"
	"os"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/memorydb"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"testing"
)

// Replay only the calibrated bounded controls, not AWS's full parameter catalog
// or its engine-version selection (the local runtime is explicitly pinned).
func TestNativeParameterMutationAndRollback(t *testing.T) {
	body, e := os.ReadFile("../../../testdata/aws/valkey/memorydb_controls.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Calls []struct {
			Case, Code string
			Input      json.RawMessage
		} `json:"calls"`
	}
	if e = json.Unmarshal(body, &fixture); e != nil {
		t.Fatal(e)
	}
	s := New(Config{Authorizer: &mutableAuthority{}, Runtime: heldEnsure{}})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
	model, _ := awscatalog.LookupService("memorydb")
	name := ""
	for _, call := range fixture.Calls {
		var action string
		var input any
		switch call.Case {
		case "memorydb-parameters-create", "memorydb-parameters-duplicate":
			action = "CreateParameterGroup"
			input = &api.CreateParameterGroupRequest{}
		case "memorydb-parameters-update", "memorydb-parameters-unknown":
			action = "UpdateParameterGroup"
			input = &api.UpdateParameterGroupRequest{}
		case "memorydb-parameters-reset":
			action = "ResetParameterGroup"
			input = &api.ResetParameterGroupRequest{}
		default:
			continue
		}
		if e = json.Unmarshal(call.Input, input); e != nil {
			t.Fatal(e)
		}
		if in, ok := input.(*api.CreateParameterGroupRequest); ok {
			name = value(in.ParameterGroupName)
		}
		operation, _ := model.Operation(action)
		_, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
		code := "Success"
		if rejected != nil {
			code = rejected.Code
		}
		if code != call.Code {
			t.Fatalf("%s: native=%s local=%s", call.Case, call.Code, code)
		}
		if call.Case == "memorydb-parameters-unknown" || call.Case == "memorydb-parameters-reset" {
			var output *api.DescribeParametersResponse
			e = s.repository.Attempt(ctx, func(tx Transaction) error {
				var err error
				output, err = s.describeParameters(tx.Context(), tx, &api.DescribeParametersRequest{ParameterGroupName: new(api.String(name))})
				return err
			})
			if e != nil {
				t.Fatal(e)
			}
			want := "37"
			if call.Case == "memorydb-parameters-reset" {
				want = "0"
			}
			found := false
			for _, parameter := range output.Parameters {
				if value(parameter.Name) == "timeout" {
					found = true
					if value(parameter.Value) != want {
						t.Fatalf("%s left timeout=%s, want %s", call.Case, value(parameter.Value), want)
					}
				}
			}
			if !found {
				t.Fatal("supported timeout disappeared")
			}
		}
	}
	if name == "" {
		t.Fatal("native fixture has no parameter lifecycle")
	}
}

func TestNativeUserFilterAndPagination(t *testing.T) {
	s := New(Config{Authorizer: &mutableAuthority{}})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
	model, _ := awscatalog.LookupService("memorydb")
	operation, _ := model.Operation("DescribeUsers")
	for _, file := range []string{"filters.json", "pagination.json"} {
		body, e := os.ReadFile("../../../testdata/aws/valkey/" + file)
		if e != nil {
			t.Fatal(e)
		}
		var fixture struct {
			Calls []struct {
				Case, Code string
				Input      json.RawMessage
			} `json:"calls"`
		}
		if e = json.Unmarshal(body, &fixture); e != nil {
			t.Fatal(e)
		}
		for _, call := range fixture.Calls {
			var input api.DescribeUsersRequest
			if e = json.Unmarshal(call.Input, &input); e != nil {
				t.Fatal(e)
			}
			output, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &input})
			code := "Success"
			if rejected != nil {
				code = rejected.Code
			}
			if code != call.Code {
				t.Fatalf("%s: native=%s local=%s", call.Case, call.Code, code)
			}
			if rejected == nil {
				result := output.(*api.DescribeUsersResponse)
				if len(result.Users) != 0 || result.NextToken != nil {
					t.Fatalf("missing-name filter returned %#v", result)
				}
				wire, err := awsapi.EncodeResponse(model, operation, result)
				if err != nil {
					t.Fatal(err)
				}
				var document map[string]json.RawMessage
				if err = json.Unmarshal(wire, &document); err != nil {
					t.Fatal(err)
				}
				var users []json.RawMessage
				if err = json.Unmarshal(document["Users"], &users); err != nil || users == nil || len(users) != 0 {
					t.Fatalf("missing-name filter must serialize Users as an empty array: %s (%v)", wire, err)
				}
			}
		}
	}
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		for _, name := range []string{"alpha", "beta", "excluded"} {
			if e := tx.PutUser(User{Key: Key{Scope: scopeFor(ctx), Kind: "user", Name: name}, Status: "active"}); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	var input api.DescribeUsersRequest
	if e := json.Unmarshal([]byte(`{"Filters":[{"Name":"user-name","Values":["alpha","beta"]}],"MaxResults":1}`), &input); e != nil {
		t.Fatal(e)
	}
	first, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &input})
	if rejected != nil {
		t.Fatal(rejected)
	}
	pageOne := first.(*api.DescribeUsersResponse)
	if len(pageOne.Users) != 1 || value(pageOne.Users[0].Name) != "alpha" || pageOne.NextToken == nil {
		t.Fatalf("bad first filtered page: %#v", pageOne)
	}
	input.NextToken = pageOne.NextToken
	second, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &input})
	if rejected != nil {
		t.Fatal(rejected)
	}
	pageTwo := second.(*api.DescribeUsersResponse)
	if len(pageTwo.Users) != 1 || value(pageTwo.Users[0].Name) != "beta" || pageTwo.NextToken != nil {
		t.Fatalf("bad second filtered page: %#v", pageTwo)
	}
	input.Filters = nil
	if _, rejected = s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &input}); rejected == nil {
		t.Fatal("pagination token accepted after filters changed")
	}
}
