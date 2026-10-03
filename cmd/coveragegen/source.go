package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"stackd/internal/smithy"
)

type selection struct {
	ID       string `json:"id"`
	Model    string `json:"model"`
	Revision string `json:"revision,omitempty"`
}

func readCoverage(checkout, selectionPath string) (Inventory, error) {
	inventory := Inventory{
		Target:               "Every Smithy operation of the explicitly selected AWS services.",
		Interpretation:       "This is an API inventory and default-stack registration report, not behavioral coverage. Status partial means registered; unimplemented means unregistered. Generated decoding followed by a protocol error contributes no implemented resource behavior. Native workflow behavior requires separate fixture evidence; registration never implies completeness. All modeled operations are listed, including intentionally unsupported APIs. CloudTrail Lake is excluded from implementation; SMTP delivery, hardware MFA and specialty KMS remain deferred. Additional registrations are outside the selected models.",
		Evidence:             []string{"docs/architecture.md", "docs/behavior-references.md", "docs/verification-kernel.md"},
		Services:             []Service{},
		AdditionalRegistered: []Registered{},
	}
	data, err := os.ReadFile(selectionPath)
	if err != nil {
		return inventory, err
	}
	var selected []selection
	if err := json.Unmarshal(data, &selected); err != nil {
		return inventory, fmt.Errorf("read service selection: %w", err)
	}
	if len(selected) == 0 {
		return inventory, fmt.Errorf("%s: no selected services", selectionPath)
	}
	revision, err := exec.Command("git", "-C", checkout, "rev-parse", "HEAD").Output()
	if err != nil {
		return inventory, fmt.Errorf("read SDK checkout revision: %w", err)
	}
	inventory.Source = Source{
		Repository: "https://github.com/aws/aws-sdk-go-v2",
		Path:       "codegen/sdk-codegen/aws-models",
		Revision:   strings.TrimSpace(string(revision)),
		Selection:  filepath.ToSlash(selectionPath),
	}
	namePattern := regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	revisionPattern := regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	seen := make(map[string]bool, len(selected))
	seenModels := make(map[string]bool, len(selected))
	for _, target := range selected {
		if !namePattern.MatchString(target.ID) || !namePattern.MatchString(target.Model) {
			return inventory, fmt.Errorf("invalid service selection %q / %q", target.ID, target.Model)
		}
		if seen[target.ID] {
			return inventory, fmt.Errorf("duplicate service selection %q", target.ID)
		}
		seen[target.ID] = true
		if seenModels[target.Model] {
			return inventory, fmt.Errorf("duplicate selected model %q", target.Model)
		}
		seenModels[target.Model] = true
		path := inventory.Source.Path + "/" + target.Model + ".json"
		var modelData []byte
		if target.Revision == "" {
			modelData, err = os.ReadFile(filepath.Join(checkout, filepath.FromSlash(path)))
		} else {
			// Retired services can retain an explicit historical AWS model instead
			// of silently disappearing when the SDK removes their current model.
			if !revisionPattern.MatchString(target.Revision) {
				return inventory, fmt.Errorf("%s: invalid model revision %q", target.ID, target.Revision)
			}
			modelData, err = exec.Command("git", "-C", checkout, "show", target.Revision+":"+path).Output()
		}
		if err != nil {
			return inventory, fmt.Errorf("read %s model: %w", target.ID, err)
		}
		service, err := inventoryService(target, modelData)
		if err != nil {
			return inventory, fmt.Errorf("%s: %w", target.ID, err)
		}
		inventory.Services = append(inventory.Services, service)
		inventory.Source.Totals.Operations += len(service.Operations)
	}
	slices.SortFunc(inventory.Services, func(a, b Service) int { return strings.Compare(a.ID, b.ID) })
	inventory.Source.Totals.Services = len(inventory.Services)
	inventory.Totals.TargetOperations = inventory.Source.Totals.Operations
	return inventory, nil
}

func inventoryService(target selection, data []byte) (Service, error) {
	service := Service{ID: target.ID, Model: target.Model, Revision: target.Revision, Evidence: evidence[target.ID], Operations: []Operation{}}
	var model smithy.Model
	if err := json.Unmarshal(data, &model); err != nil {
		return service, fmt.Errorf("decode Smithy model: %w", err)
	}
	if model.Smithy != "2.0" {
		return service, fmt.Errorf("unsupported Smithy version %q", model.Smithy)
	}
	var root smithy.Shape
	for _, shape := range model.Shapes {
		if shape.Type != "service" {
			continue
		}
		if root.Type != "" {
			return service, fmt.Errorf("expected exactly one service")
		}
		root = shape
	}
	if root.Type == "" {
		return service, fmt.Errorf("missing service shape")
	}
	if raw := root.Traits["smithy.api#title"]; raw != nil {
		if err := json.Unmarshal(raw, &service.Name); err != nil {
			return service, fmt.Errorf("decode service title: %w", err)
		}
	}
	if service.Name == "" {
		var trait struct {
			SDKID string `json:"sdkId"`
		}
		if err := json.Unmarshal(root.Traits["aws.api#service"], &trait); err != nil {
			return service, fmt.Errorf("decode AWS service trait: %w", err)
		}
		service.Name = trait.SDKID
	}
	operations, err := smithy.OperationTargets(model, root)
	if err != nil {
		return service, err
	}
	seen := make(map[string]bool, len(operations))
	for _, ref := range operations {
		shape, ok := model.Shapes[string(ref.Target)]
		if !ok || shape.Type != "operation" {
			return service, fmt.Errorf("invalid operation target %q", ref.Target)
		}
		_, name, found := strings.Cut(string(ref.Target), "#")
		if !found || name == "" || seen[name] {
			return service, fmt.Errorf("invalid or conflicting operation name %q", ref.Target)
		}
		seen[name] = true
		service.Operations = append(service.Operations, Operation{Name: name, Status: "unimplemented"})
	}
	slices.SortFunc(service.Operations, func(a, b Operation) int { return strings.Compare(a.Name, b.Name) })
	return service, nil
}
