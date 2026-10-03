package memorydb

import (
	"encoding/json"
	"os"
	"reflect"
	api "stackd/internal/awsapi/memorydb"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"testing"
)

func TestExactNativeManagementProjection(t *testing.T) {
	body, err := os.ReadFile("../../../testdata/aws/valkey/memorydb_controls.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Calls []struct {
			Case, Code, Message string
			Input, Output       json.RawMessage
			RequestID           string `json:"request_id"`
		} `json:"calls"`
		History struct {
			Events []struct {
				Event struct {
					RequestID         string          `json:"requestID"`
					EventSource       string          `json:"eventSource"`
					EventName         string          `json:"eventName"`
					RequestParameters json.RawMessage `json:"requestParameters"`
					ResponseElements  json.RawMessage `json:"responseElements"`
					ReadOnly          bool            `json:"readOnly"`
				} `json:"event"`
			} `json:"events"`
		} `json:"history"`
	}
	if err = json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	recorder := &auditCapture{}
	s := New(Config{Recorder: recorder})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1"})
	for _, call := range fixture.Calls {
		var input, output any
		switch call.Case {
		case "memorydb-user-create", "memorydb-user-duplicate":
			input = &api.CreateUserRequest{}
			output = &api.CreateUserResponse{}
		case "memorydb-user-update":
			input = &api.UpdateUserRequest{}
			output = &api.UpdateUserResponse{}
		case "memorydb-parameters-create":
			input = &api.CreateParameterGroupRequest{}
			output = &api.CreateParameterGroupResponse{}
		case "memorydb-parameters-update", "memorydb-parameters-unknown":
			input = &api.UpdateParameterGroupRequest{}
			output = &api.UpdateParameterGroupResponse{}
		case "memorydb-parameters-reset":
			input = &api.ResetParameterGroupRequest{}
			output = &api.ResetParameterGroupResponse{}
		case "memorydb-user-describe":
			input = &api.DescribeUsersRequest{}
			output = &api.DescribeUsersResponse{}
		case "memorydb-parameters-user":
			input = &api.DescribeParametersRequest{}
			output = &api.DescribeParametersResponse{}
		case "memorydb-default-version":
			input = &api.DescribeEngineVersionsRequest{}
			output = &api.DescribeEngineVersionsResponse{}
		default:
			continue
		}
		if err = json.Unmarshal(call.Input, input); err != nil {
			t.Fatal(err)
		}
		var rejected *awswire.Error
		if call.Code != "Success" {
			rejected = failure(call.Code, call.Message)
		} else if err = json.Unmarshal(call.Output, output); err != nil {
			t.Fatal(err)
		}
		matched := false
		for _, row := range fixture.History.Events {
			native := row.Event
			if native.RequestID != call.RequestID {
				continue
			}
			matched = true
			recorder.calls = nil
			if err = s.recordCall(ctx, native.EventName, input, output, rejected); err != nil {
				t.Fatal(err)
			}
			if len(recorder.calls) != 1 {
				t.Fatalf("%s did not emit one management record", call.Case)
			}
			local := recorder.calls[0]
			if local.EventSource != native.EventSource || local.EventName != native.EventName || local.ReadOnly != native.ReadOnly {
				t.Fatalf("%s changed management classification", call.Case)
			}
			for _, field := range []struct {
				name             string
				actual, expected json.RawMessage
			}{{"requestParameters", local.RequestParameters, native.RequestParameters}, {"responseElements", local.ResponseElements, native.ResponseElements}} {
				var actual, expected any
				if len(field.actual) > 0 {
					if err = json.Unmarshal(field.actual, &actual); err != nil {
						t.Fatal(err)
					}
				}
				if len(field.expected) > 0 {
					if err = json.Unmarshal(field.expected, &expected); err != nil {
						t.Fatal(err)
					}
				}
				if !reflect.DeepEqual(actual, expected) {
					t.Fatalf("%s %s: actual=%s native=%s", call.Case, field.name, field.actual, field.expected)
				}
			}
			break
		}
		if !matched {
			t.Fatalf("%s lacks exact native request-ID management evidence", call.Case)
		}
	}
}
