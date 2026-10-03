package catalog

import (
	"reflect"
	"slices"
	"sync"
	"testing"
)

func TestCatalogReturnsDetachedState(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := c.LookupService("iam")
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			service, _ := c.LookupService("iam")
			for i := range service.Actions {
				service.Actions[i].Name = "changed"
				for j := range service.Actions[i].Resources {
					service.Actions[i].Resources[j] = "changed"
				}
				for j := range service.Actions[i].ConditionKeys {
					service.Actions[i].ConditionKeys[j] = "changed"
				}
			}
			for i := range service.Resources {
				for j := range service.Resources[i].ARNTemplates {
					service.Resources[i].ARNTemplates[j] = "changed"
				}
			}
			action, _ := c.LookupAction("IAM:GETUSER")
			action.Resources[0] = "changed"
			resource, _ := c.LookupResource("iam", "user")
			resource.ARNTemplates[0] = "changed"
		})
	}
	workers.Wait()
	got, _ := c.LookupService("iam")
	if !reflect.DeepEqual(got, want) {
		t.Fatal("caller mutation changed shared authorization metadata")
	}
	if action, ok := c.LookupAction("IAM:GETUSER"); !ok || action.Name != "iam:GetUser" || !slices.Contains(action.Resources, "user") {
		t.Fatal("case-insensitive permission lookup failed")
	}
}
