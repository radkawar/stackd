package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// The service reference describes resource types. Simulator scenario names
// instead come from actual SimulateCustomPolicy responses.
func resourceHandlingMetadata(source []byte) ([]byte, error) {
	var capture struct {
		Simulation []struct {
			Input struct {
				ActionNames            []string
				ResourceHandlingOption string
			}
			Code string
		}
	}
	if err := json.Unmarshal(source, &capture); err != nil {
		return nil, err
	}
	if len(capture.Simulation) == 0 {
		return nil, fmt.Errorf("resource-handling capture has no observations")
	}
	options := make(map[string][]string)
	for _, row := range capture.Simulation {
		if len(row.Input.ActionNames) != 1 || row.Input.ResourceHandlingOption == "" {
			return nil, fmt.Errorf("resource-handling observation has no single action and option")
		}
		if row.Code == "InvalidInput" {
			continue
		}
		if row.Code != "Success" {
			return nil, fmt.Errorf("resource-handling observation is unresolved: %s", row.Code)
		}
		action := strings.ToLower(row.Input.ActionNames[0])
		options[action] = append(options[action], row.Input.ResourceHandlingOption)
	}
	var actions []string
	for action := range options {
		actions = append(actions, action)
	}
	slices.Sort(actions)
	var out bytes.Buffer
	fmt.Fprintln(&out, "// Source: testdata/aws/iam/service_reference.json (AWS SimulateCustomPolicy).")
	fmt.Fprintln(&out, "var resourceHandlingOptions = map[string][]string{")
	for _, action := range actions {
		slices.Sort(options[action])
		fmt.Fprintf(&out, "%q: {", action)
		for _, option := range slices.Compact(options[action]) {
			fmt.Fprintf(&out, "%q,", option)
		}
		fmt.Fprintln(&out, "},")
	}
	fmt.Fprintln(&out, "}")
	return out.Bytes(), nil
}
