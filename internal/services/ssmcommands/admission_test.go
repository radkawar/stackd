package ssmcommands_test

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awscatalog"
)

func TestEmptyTagValueDoesNotSelectUntaggedNodes(t *testing.T) {
	fixtures(t, func(t *testing.T, f *fixture) {
		const tagged = "i-00000000000000001"
		const other = "i-00000000000000002"
		const absent = "i-00000000000000003"
		f.instances[tagged].Tags["Maintenance"] = ""
		f.instances[other].Tags["Maintenance"] = "scheduled"
		command := call(t, f, "SendCommand", &api.SendCommandRequest{
			DocumentName: new(api.DocumentARN("AWS-RunShellScript")),
			Parameters:   api.Parameters{"commands": {"printf intended-node-only"}},
			Targets:      []api.Target{{Key: new(api.TargetKey("tag:Maintenance")), Values: []api.TargetValue{""}}},
		}).(*api.SendCommandResult).Command
		if *command.TargetCount != 1 {
			t.Errorf("empty-valued tag selected %d nodes, want only the explicitly tagged node", *command.TargetCount)
		}
		for _, id := range []string{other, absent} {
			if messages := pending(t, f, id); len(messages) != 0 {
				t.Errorf("node %s received %d unintended commands", id, len(messages))
			}
		}
		if messages := pending(t, f, tagged); len(messages) != 1 {
			t.Errorf("the empty-valued tag must remain selectable: %+v", messages)
		}
		fleet := call(t, f, "DescribeInstanceInformation", &api.DescribeInstanceInformationRequest{
			Filters: []api.InstanceInformationStringFilter{{Key: new(api.InstanceInformationStringFilterKey("tag-key")), Values: []api.InstanceInformationFilterValue{"Maintenance"}}},
		}).(*api.DescribeInstanceInformationResult).InstanceInformationList
		if len(fleet) != 2 || string(*fleet[0].InstanceId) != tagged || string(*fleet[1].InstanceId) != other {
			t.Fatalf("tag-key must include empty and nonempty present values, never the untagged node: %+v", fleet)
		}
	})
}

func TestOversizedNativeParametersCannotBlockFollowingCommands(t *testing.T) {
	var native struct {
		Calls []struct {
			Label, Code string
			Input       api.SendCommandRequest
		}
	}
	file, err := os.Open("../../../testdata/aws/ssm/managed_execution_admission.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	if err := json.NewDecoder(compressed).Decode(&native); err != nil {
		t.Fatal(err)
	}
	var input *api.SendCommandRequest
	for _, row := range native.Calls {
		if row.Label == "empty-list-210000" {
			if row.Code != "MaxDocumentSizeExceeded" {
				t.Fatalf("native oversized result: %s", row.Code)
			}
			input = &row.Input
			break
		}
	}
	if input == nil {
		t.Fatal("native oversized request missing")
	}
	fixtures(t, func(t *testing.T, f *fixture) {
		const node = "i-00000000000000001"
		request := *input
		request.Targets = nil
		request.InstanceIds = []api.InstanceId{node}
		model, _ := awscatalog.LookupService("ssm")
		op, _ := model.Operation("SendCommand")
		_, rejected := f.s.ExecuteCommand(f.root, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: &request})
		if rejected == nil {
			messages := pending(t, f, node)
			bytes := 0
			for _, message := range messages {
				bytes += len(message.Payload)
			}
			t.Fatalf("native-oversized input was admitted: %d queued envelope bytes", bytes)
		}
		if rejected.Code != "MaxDocumentSizeExceeded" {
			t.Fatalf("oversized result: %v", rejected)
		}
		retained := call(t, f, "ListCommands", &api.ListCommandsRequest{}).(*api.ListCommandsResult)
		if len(retained.Commands) != 0 {
			t.Fatal("rejected oversize command retained delivery state")
		}
		command := send(t, f, "1", "0", node)
		messages := pending(t, f, node)
		if len(messages) != 1 {
			t.Fatalf("ordinary command has no exclusive delivery after rejection: %d", len(messages))
		}
		var job struct {
			JobID string `json:"JobId"`
		}
		if err := json.Unmarshal(messages[0].Payload, &job); err != nil {
			t.Fatal(err)
		}
		if job.JobID != "aws.ssm."+command+"."+node {
			t.Fatalf("wrong command delivery after oversized rejection: %s", job.JobID)
		}
	})
}
