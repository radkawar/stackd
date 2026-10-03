package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

func TestAWSReferenceConversion(t *testing.T) {
	source, err := readSource("../../internal/iam/catalog/data/service_reference.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	services, err := convert(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range services {
		if service.Prefix != "iam" {
			continue
		}
		for _, action := range service.Actions {
			if action.Name == "iam:GetUser" && (!slices.Contains(action.Resources, "user") || !slices.Contains(action.ConditionKeys, "aws:ResourceTag/${TagKey}") || !slices.Contains(action.ConditionKeys, "iam:ResourceTag/${TagKey}")) {
				t.Fatal("action lost resource-specific conditions", action)
			}
			if action.Name == "iam:CreateUser" && (!slices.Contains(action.ConditionKeys, "aws:RequestTag/${TagKey}") || !slices.Contains(action.ConditionKeys, "iam:PermissionsBoundary")) {
				t.Fatal("creation lost its action conditions", action)
			}
		}
	}
	first, err := render(services)
	if err != nil {
		t.Fatal(err)
	}
	// Source ordering is not semantically significant. Regeneration must not
	// churn the embedded snapshot when AWS reorders its collections.
	slices.Reverse(source.Services)
	for i := range source.Services {
		slices.Reverse(source.Services[i].Actions)
		slices.Reverse(source.Services[i].Resources)
	}
	reordered, err := convert(source)
	if err != nil {
		t.Fatal(err)
	}
	second, err := render(reordered)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("generation changed with source order", err)
	}
}

func TestUnknownResourceReferenceRejectsRefresh(t *testing.T) {
	var service sourceService
	if err := json.Unmarshal([]byte(`{"Name":"iam","Version":"v1.4","Actions":[{"Name":"GetUser","Resources":[{"Name":"missing"}]}]}`), &service); err != nil {
		t.Fatal(err)
	}
	if _, err := convert(sourceSnapshot{Services: []sourceService{service}}); err == nil {
		t.Fatal("undefined resource would silently remove authorization scope")
	}
}
