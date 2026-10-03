package smithy

import (
	"fmt"
	"slices"
	"strings"

	"stackd/internal/awsschema"
)

// OperationTargets follows Smithy's service/resource operation closure.
// Resource identifiers describe model ownership, not additional wire members;
// operation input/output shapes remain authoritative for transport bindings.
func OperationTargets(model Model, service Shape) ([]Reference, error) {
	operations := slices.Clone(service.Operations)
	pending := slices.Clone(service.Resources)
	visited := make(map[awsschema.ShapeID]bool)
	for len(pending) > 0 {
		ref := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if visited[ref.Target] {
			continue
		}
		visited[ref.Target] = true
		resource, ok := model.Shapes[string(ref.Target)]
		if !ok || resource.Type != "resource" {
			return nil, fmt.Errorf("invalid resource target %q", ref.Target)
		}
		pending = append(pending, resource.Resources...)
		operations = append(operations, resource.Operations...)
		operations = append(operations, resource.CollectionOperations...)
		for _, operation := range []Reference{resource.Create, resource.Put, resource.Read, resource.Update, resource.Delete, resource.List} {
			if operation.Target != "" {
				operations = append(operations, operation)
			}
		}
	}
	slices.SortFunc(operations, func(a, b Reference) int { return strings.Compare(string(a.Target), string(b.Target)) })
	return slices.CompactFunc(operations, func(a, b Reference) bool { return a.Target == b.Target }), nil
}
