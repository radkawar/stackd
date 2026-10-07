package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"

	"stackd/internal/integrations"
)

func observeCloudFormation(inventory *Inventory) error {
	const source = "testdata/aws/cloudformation/resource_schemas_public.json"
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read CloudFormation registry: %w", err)
	}
	var registry struct {
		Types map[string]json.RawMessage `json:"types"`
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		return fmt.Errorf("decode CloudFormation registry: %w", err)
	}
	digest := sha256.Sum256(data)
	inventory.CloudFormation = CloudFormationInventory{
		SchemaSource:   source,
		SchemaSHA256:   hex.EncodeToString(digest[:]),
		Interpretation: "Built-in native resource adapter registration against the pinned official AWS CloudFormation registry. Each adapter invokes an existing native owner; registration and schema presence do not establish complete property, lifecycle, runtime, authorization or workflow semantics.",
	}
	handlers := integrations.CloudFormationHandlers(integrations.StepFunctionsCommands{}, nil)
	for _, name := range slices.Sorted(maps.Keys(handlers)) {
		if _, exists := registry.Types[name]; !exists {
			return fmt.Errorf("built-in CloudFormation type %s has no pinned official schema", name)
		}
		inventory.CloudFormation.Resources = append(inventory.CloudFormation.Resources, CloudFormationResource{TypeName: name, Adapter: fmt.Sprintf("%T", handlers[name])})
	}
	return nil
}
