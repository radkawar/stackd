package lambda

import (
	"stackd/internal/apievents"
	"stackd/journal"
)

// Native event-name/version and sensitive-field calibration remains separate
// from generated operation ownership. No guest credentials enter these shapes.
func addCapacityAuditProjections(projections map[string]apievents.Projection) {
	for _, name := range []string{"CreateCapacityProvider", "UpdateCapacityProvider", "DeleteCapacityProvider", "PutFunctionScalingConfig", "PutResourcePolicy", "DeleteResourcePolicy"} {
		projections[name] = apievents.Projection{Category: journal.CategoryManagement}
	}
	for _, name := range []string{"GetCapacityProvider", "ListCapacityProviders", "ListFunctionVersionsByCapacityProvider", "GetFunctionScalingConfig", "GetResourcePolicy"} {
		projections[name] = apievents.Projection{Category: journal.CategoryManagement, ReadOnly: true}
	}
}
