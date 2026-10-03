package main

import "testing"

func TestObserveStackSelectedServiceIdentity(t *testing.T) {
	inventory := Inventory{Services: []Service{
		{ID: "cognitoidentity", Model: "cognito-identity", Operations: []Operation{{Name: "CreateIdentityPool", Status: "unimplemented"}}},
		{ID: "configservice", Model: "config-service", Operations: []Operation{{Name: "PutConfigurationRecorder", Status: "unimplemented"}}},
		{ID: "ssoadmin", Model: "sso-admin", Operations: []Operation{{Name: "CreatePermissionSet", Status: "unimplemented"}}},
	}}
	if err := observeStack(&inventory); err != nil {
		t.Fatal(err)
	}
	for _, service := range inventory.Services {
		if got := service.Operations[0].Status; got != "partial" {
			t.Errorf("%s %s status = %s, want partial", service.ID, service.Operations[0].Name, got)
		}
		for _, extra := range inventory.AdditionalRegistered {
			if extra.Service != service.ID {
				continue
			}
			for _, operation := range extra.Operations {
				if operation.Name == service.Operations[0].Name {
					t.Errorf("selected %s %s also counted outside the selection", service.ID, operation.Name)
				}
			}
		}
	}
	if inventory.Totals.Partial != 3 || inventory.Totals.Unimplemented != 0 {
		t.Errorf("registration totals = %+v", inventory.Totals)
	}
}

func TestRejectMismatchedCatalogIdentity(t *testing.T) {
	for _, service := range []Service{
		{ID: "cognito-identity", Model: "cognito-identity"},
		{ID: "config", Model: "config-service"},
		{ID: "sso-admin", Model: "sso-admin"},
		{ID: "configservice", Model: "cognito-identity"},
	} {
		t.Run(service.ID+"/"+service.Model, func(t *testing.T) {
			inventory := Inventory{Services: []Service{service}}
			if err := observeStack(&inventory); err == nil {
				t.Fatal("mismatched service identity produced a misleading registration report")
			}
		})
	}
}
