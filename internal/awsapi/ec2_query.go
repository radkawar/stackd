package awsapi

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	"stackd/internal/awscatalog"
)

// EC2 rejects unknown query names instead of ignoring them as AWS Query does.
// Recognize names through the generated structure hierarchy; value admission
// remains in the shared binder and each operation's owning service.
func checkEC2QueryParameters(service awscatalog.Service, input awscatalog.ShapeID, query url.Values) error {
	for _, key := range slices.Sorted(maps.Keys(query)) {
		switch key {
		case "Action", "Version", "X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature", "X-Amz-Security-Token":
			continue
		}
		if err := checkEC2QueryPath(service, input, key); err != nil {
			return err
		}
	}
	return nil
}

func checkEC2QueryPath(service awscatalog.Service, id awscatalog.ShapeID, path string) error {
	if path == "" {
		return nil
	}
	shape, ok := service.Shape(id)
	if !ok {
		return fmt.Errorf("missing generated shape %s", id)
	}
	switch shape.Kind {
	case "structure", "union":
		name, rest, _ := strings.Cut(path, ".")
		for _, member := range shape.Members {
			if member.EC2QueryName == name {
				return checkEC2QueryPath(service, member.Target, rest)
			}
		}
		return &ValidationError{Path: name, Reason: "unrecognized query parameter", Constraint: "query.unknown"}
	case "list", "set":
		index, rest, _ := strings.Cut(path, ".")
		if decimalIndex(index) || strings.HasPrefix(index, "-") {
			path = rest
		}
		return checkEC2QueryPath(service, shape.Member.Target, path)
	default:
		return nil
	}
}
