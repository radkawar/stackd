package memorydb

import (
	"encoding/json"
	"maps"
	"os"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/memorydb"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"strconv"
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

func TestDefaultParameterGroupsUseCanonicalNamesAndNativeDefaults(t *testing.T) {
	s := New(Config{Authorizer: &mutableAuthority{}})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
	model, _ := awscatalog.LookupService("memorydb")
	want := map[string]string{
		"maxmemory":              "1073741824",
		"maxmemory-policy":       "noeviction",
		"notify-keyspace-events": "",
		"tcp-keepalive":          "300",
		"timeout":                "0",
	}
	for _, tc := range []struct {
		name, family string
	}{
		{"default.memorydb-valkey7", "memorydb_valkey7"},
		{"default.memorydb-redis7", "memorydb_redis7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			operation, _ := model.Operation("DescribeParameters")
			output, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &api.DescribeParametersRequest{ParameterGroupName: new(api.String(tc.name))}})
			if rejected != nil {
				t.Fatal(rejected)
			}
			result := output.(*api.DescribeParametersResponse)
			actual := map[string]string{}
			for _, parameter := range result.Parameters {
				actual[value(parameter.Name)] = value(parameter.Value)
			}
			if !maps.Equal(actual, want) || len(result.Parameters) != len(want) || result.NextToken != nil {
				t.Fatalf("default native baseline: %#v", result)
			}
			operation, _ = model.Operation("DescribeParameterGroups")
			output, rejected = s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &api.DescribeParameterGroupsRequest{ParameterGroupName: new(api.String(tc.name))}})
			if rejected != nil {
				t.Fatal(rejected)
			}
			groups := output.(*api.DescribeParameterGroupsResponse).ParameterGroups
			key := Key{Scope: scopeFor(ctx), Kind: "parametergroup", Name: tc.name}
			if len(groups) != 1 || value(groups[0].Name) != tc.name || value(groups[0].Family) != tc.family || value(groups[0].ARN) != key.ARN() {
				t.Fatalf("canonical parameter group identity: %#v", groups)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				spec, err := specification(r, Cluster{Key: Key{Scope: scopeFor(ctx)}, RuntimeID: "native", ACLName: "open-access", ParameterGroup: tc.name})
				if err != nil {
					return err
				}
				if len(spec.Parameters) != 0 || strconv.FormatInt(spec.MemoryBytes, 10) != actual["maxmemory"] {
					t.Fatalf("default read disagrees with native capacity or adds overrides: %#v", spec)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	operation, _ := model.Operation("DescribeParameterGroups")
	output, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &api.DescribeParameterGroupsRequest{}})
	if rejected != nil {
		t.Fatal(rejected)
	}
	groups := output.(*api.DescribeParameterGroupsResponse).ParameterGroups
	if len(groups) != 2 || value(groups[0].Name) != "default.memorydb-redis7" || value(groups[1].Name) != "default.memorydb-valkey7" {
		t.Fatalf("default listing retained noncanonical names: %#v", groups)
	}
}

func TestDefaultParameterReadsRequireAuthorityAndSupportedGroups(t *testing.T) {
	authority := &mutableAuthority{}
	s := New(Config{Authorizer: authority})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
	model, _ := awscatalog.LookupService("memorydb")
	for _, action := range []string{"DescribeParameters", "DescribeParameterGroups"} {
		operation, _ := model.Operation(action)
		for _, tc := range []struct {
			name, code string
			denied     bool
		}{
			{"default.memorydb-valkey7", "AccessDeniedException", true},
			{"default.memorydb-redis7", "AccessDeniedException", true},
			{"missing", "ParameterGroupNotFoundFault", false},
			{"default.memorydb-valkey8", "ParameterGroupNotFoundFault", false},
			{"default.memorydb-redis6", "ParameterGroupNotFoundFault", false},
			{"default.memorydb_valkey7", "InvalidParameterValueException", false},
			{"default.memorydb_redis7", "InvalidParameterValueException", false},
		} {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				authority.denied = tc.denied
				var input any = &api.DescribeParametersRequest{ParameterGroupName: new(api.String(tc.name))}
				if action == "DescribeParameterGroups" {
					input = &api.DescribeParameterGroupsRequest{ParameterGroupName: new(api.String(tc.name))}
				}
				if _, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input}); rejected == nil || rejected.Code != tc.code {
					t.Fatalf("expected %s, got %v", tc.code, rejected)
				}
			})
		}
	}
}

func TestCreateClusterUsesCanonicalDefaultParameterGroup(t *testing.T) {
	s := New(Config{Authorizer: &mutableAuthority{}, Runtime: heldEnsure{}})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
	for _, tc := range []struct {
		engine, version, group string
	}{
		{"valkey", "8.1.6", "default.memorydb-valkey7"},
		{"redis", "7.2", "default.memorydb-redis7"},
	} {
		t.Run(tc.engine, func(t *testing.T) {
			if err := s.repository.Attempt(ctx, func(tx Transaction) error {
				output, err := s.createCluster(tx.Context(), tx, &api.CreateClusterRequest{
					ClusterName:         new(api.String(tc.engine)),
					Engine:              new(api.String(tc.engine)),
					EngineVersion:       new(api.String(tc.version)),
					NodeType:            new(api.String("db.t4g.small")),
					ACLName:             new(api.ACLName("open-access")),
					NumReplicasPerShard: new(api.IntegerOptional(0)),
				})
				if err != nil {
					return err
				}
				if value(output.Cluster.ParameterGroupName) != tc.group || value(output.Cluster.EngineVersion) != tc.version {
					t.Fatalf("cluster default parameter group or version: %#v", output.Cluster)
				}
				cluster, err := tx.Cluster(Key{Scope: scopeFor(ctx), Kind: "cluster", Name: tc.engine})
				if err != nil {
					return err
				}
				_, err = specification(tx, cluster)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
