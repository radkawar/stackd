package iam

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	iamapi "stackd/internal/awsapi/iam"
)

func TestSimulationContextEntriesAWSReplay(t *testing.T) {
	cases := 0
	for _, name := range []string{"simulation.json", "simulation_inputs.json"} {
		data, err := os.ReadFile("../../../testdata/aws/iam/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Observations []struct {
				Case  string `json:"case"`
				Code  string `json:"code"`
				Input struct{ ContextEntries iamapi.ContextEntryListType }
			}
		}
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		for _, observation := range fixture.Observations {
			if !strings.HasPrefix(observation.Case, "context_") && !strings.HasPrefix(observation.Case, "input_context_") || observation.Code == "CLIValidationError" {
				continue
			}
			cases++
			t.Run(observation.Case, func(t *testing.T) {
				values, types, err := simulationContextEntries(observation.Input.ContextEntries)
				if observation.Code == "Success" {
					if err != nil {
						t.Fatalf("valid AWS input rejected: %v", err)
					}
					if len(values) != len(types) {
						t.Fatalf("values/types lost alignment: %v, %v", values, types)
					}
				} else if err == nil || err.Code != observation.Code || values != nil || types != nil {
					t.Fatalf("invalid input = %v, %v, %v; want %s", values, types, err, observation.Code)
				}
			})
		}
	}
	if cases < 40 {
		t.Fatalf("only %d context validation cases replayed", cases)
	}
}

func TestSimulationContextEntriesNormalizeAndDetach(t *testing.T) {
	entries := iamapi.ContextEntryListType{
		{ContextKeyName: wirePointer(iamapi.ContextKeyNameType("TEST:Number")), ContextKeyType: wirePointer(iamapi.ContextKeyTypeEnumNUMERIC_LIST), ContextKeyValues: iamapi.ContextKeyValueListType{"01.00", "+010", "1e9999"}},
		{ContextKeyName: wirePointer(iamapi.ContextKeyNameType("TEST:Date")), ContextKeyType: wirePointer(iamapi.ContextKeyTypeEnumDATE), ContextKeyValues: iamapi.ContextKeyValueListType{"2035-01-02"}},
		{ContextKeyName: wirePointer(iamapi.ContextKeyNameType("TEST:Bool")), ContextKeyType: wirePointer(iamapi.ContextKeyTypeEnumBOOLEAN_LIST), ContextKeyValues: iamapi.ContextKeyValueListType{"TRUE", "yes", "1", "false"}},
		{ContextKeyName: wirePointer(iamapi.ContextKeyNameType("TEST:IP")), ContextKeyType: wirePointer(iamapi.ContextKeyTypeEnumIP), ContextKeyValues: iamapi.ContextKeyValueListType{"192.000.002.1"}},
	}
	before, _ := json.Marshal(entries)
	values, types, err := simulationContextEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"test:number": {"1.00", "10", "1E+9999"}, "test:date": {"2035-01-02T00:00:00.000Z"}, "test:bool": {"true", "false", "false", "false"}, "test:ip": {"192.000.002.1"}}
	if !reflect.DeepEqual(values, want) || types["test:number"] != "numericList" || types["test:date"] != "date" {
		t.Fatalf("normalized = %v / %v", values, types)
	}
	values["test:number"][0] = "mutated"
	types["test:number"] = "modified"
	after, _ := json.Marshal(entries)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("normalization or caller mutation changed generated inputs")
	}
	values, types, err = simulationContextEntries(entries)
	if err != nil || !reflect.DeepEqual(values, want) || types["test:number"] != "numericList" {
		t.Fatalf("second call observed prior result mutation: %v / %v, %v", values, types, err)
	}
}

func TestSimulationContextEntriesRejectUnknownType(t *testing.T) {
	entries := iamapi.ContextEntryListType{{ContextKeyName: wirePointer(iamapi.ContextKeyNameType("aws:userid")), ContextKeyType: wirePointer(iamapi.ContextKeyTypeEnum("unknown")), ContextKeyValues: iamapi.ContextKeyValueListType{"not-known"}}}
	values, types, err := simulationContextEntries(entries)
	if err == nil || err.Code != "ValidationError" || values != nil || types != nil {
		t.Fatalf("public input accepted an unknown context kind: %v, %v, %v", values, types, err)
	}
}
