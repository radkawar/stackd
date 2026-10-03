package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"

	"stackd"
	"stackd/internal/awscatalog"
	"stackd/internal/gateway"
)

func observeStack(inventory *Inventory) (err error) {
	if err := validateCatalogSelection(inventory.Services); err != nil {
		return err
	}
	stack, err := stackd.New(stackd.Config{})
	if err != nil {
		return fmt.Errorf("create default local stack: %w", err)
	}
	defer func() { err = errors.Join(err, stack.Close()) }()
	recorder := httptest.NewRecorder()
	stack.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/_stackd/health", nil))
	if recorder.Code != http.StatusOK {
		return fmt.Errorf("read default local stack health: HTTP %d", recorder.Code)
	}
	var health struct {
		Status   string               `json:"status"`
		Services []gateway.Capability `json:"services"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &health); err != nil {
		return fmt.Errorf("decode default local stack health: %w", err)
	}
	if health.Status != "available" {
		return fmt.Errorf("default local stack health status is %q", health.Status)
	}
	registered := make(map[string]map[string]bool, len(health.Services))
	for _, service := range health.Services {
		operations := make(map[string]bool, len(service.Operations))
		for _, operation := range service.Operations {
			operations[operation] = true
		}
		registered[service.Name] = operations
	}
	for i := range inventory.Services {
		service := &inventory.Services[i]
		operations := registered[service.ID]
		for j := range service.Operations {
			operation := &service.Operations[j]
			if operations[operation.Name] {
				operation.Status = "partial"
				inventory.Totals.Partial++
				delete(operations, operation.Name)
			} else {
				inventory.Totals.Unimplemented++
			}
		}
	}
	for service, operations := range registered {
		if len(operations) == 0 {
			continue
		}
		extra := Registered{Service: service, Operations: make([]ExtraOperation, 0, len(operations))}
		for name := range operations {
			extra.Operations = append(extra.Operations, ExtraOperation{Name: name, Status: "partial"})
		}
		slices.SortFunc(extra.Operations, func(a, b ExtraOperation) int { return strings.Compare(a.Name, b.Name) })
		inventory.AdditionalRegistered = append(inventory.AdditionalRegistered, extra)
		inventory.Totals.AdditionalRegistered += len(extra.Operations)
	}
	slices.SortFunc(inventory.AdditionalRegistered, func(a, b Registered) int { return strings.Compare(a.Service, b.Service) })
	return nil
}

// A selected model must use the generated provider's identity. Otherwise its
// real operations silently appear unimplemented and become extra registrations.
func validateCatalogSelection(selected []Service) error {
	catalog := awscatalog.Services()
	for _, target := range selected {
		modelPath := "codegen/sdk-codegen/aws-models/" + target.Model + ".json"
		for _, generated := range catalog {
			sameName := target.ID == generated.Name
			sameModel := modelPath == generated.Source.Path
			if sameName != sameModel {
				return fmt.Errorf("service selection %q / %q conflicts with generated service %q / %q",
					target.ID, target.Model, generated.Name, generated.Source.Path)
			}
		}
	}
	return nil
}
