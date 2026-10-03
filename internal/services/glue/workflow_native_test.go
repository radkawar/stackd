package glue_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/glue"
)

func TestNativeWorkflowTriggerSecurityAndTagControls(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "aws", "glue", "controls_native.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Label, Service, Operation string
			Input                     json.RawMessage
			Result                    struct {
				Code   string
				Output json.RawMessage
			}
		}
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	ctx := registryContext("123456789012", "us-east-1")
	s := glue.New(glue.Config{})
	t.Cleanup(func() { _ = s.Close() })
	for _, row := range fixture.Observations {
		if row.Service != "glue" {
			continue
		}
		switch row.Operation {
		case "create-workflow", "get-workflow", "update-workflow", "get-workflow-run-properties", "create-trigger", "get-trigger", "start-trigger", "stop-trigger", "create-security-configuration", "get-security-configuration", "tag-resource", "untag-resource", "get-tags":
		default:
			continue
		}
		t.Run(row.Label, func(t *testing.T) {
			var action strings.Builder
			for _, part := range strings.Split(row.Operation, "-") {
				action.WriteString(strings.ToUpper(part[:1]))
				action.WriteString(part[1:])
			}
			input, err := api.NewInput(action.String())
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(row.Input, input); err != nil {
				t.Fatal(err)
			}
			output, rejected := registryExecute(s, ctx, action.String(), input)
			if row.Result.Code != "Success" {
				if rejected == nil || rejected.Code != row.Result.Code {
					t.Fatalf("native %s, local %v", row.Result.Code, rejected)
				}
				return
			}
			if rejected != nil {
				t.Fatal(rejected)
			}
			switch actual := output.(type) {
			case *api.GetWorkflowOutput:
				var want api.GetWorkflowOutput
				if err = json.Unmarshal(row.Result.Output, &want); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(actual.Workflow.DefaultRunProperties, want.Workflow.DefaultRunProperties) || !reflect.DeepEqual(actual.Workflow.MaxConcurrentRuns, want.Workflow.MaxConcurrentRuns) {
					t.Fatalf("workflow update differs: local %+v native %+v", actual.Workflow, want.Workflow)
				}
			case *api.GetTriggerOutput:
				var want api.GetTriggerOutput
				if err = json.Unmarshal(row.Result.Output, &want); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(actual.Trigger, want.Trigger) {
					t.Fatalf("trigger lifecycle differs: local %+v native %+v", actual.Trigger, want.Trigger)
				}
			case *api.GetSecurityConfigurationOutput:
				var want api.GetSecurityConfigurationOutput
				if err = json.Unmarshal(row.Result.Output, &want); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(actual.SecurityConfiguration.EncryptionConfiguration, want.SecurityConfiguration.EncryptionConfiguration) {
					t.Fatalf("security modes differ: local %+v native %+v", actual.SecurityConfiguration, want.SecurityConfiguration)
				}
			case *api.GetTagsOutput:
				var want api.GetTagsOutput
				if err = json.Unmarshal(row.Result.Output, &want); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(actual.Tags, want.Tags) {
					t.Fatalf("tag merge/removal differs: local %v native %v", actual.Tags, want.Tags)
				}
			}
		})
	}
}
