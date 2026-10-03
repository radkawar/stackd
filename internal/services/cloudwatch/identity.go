package cloudwatch

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}

func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}

func metricIdentity(scope Scope, namespace, name string, dimensions []api.Dimension) (MetricKey, []Dimension, *awswire.Error) {
	key := MetricKey{Scope: scope, Namespace: namespace, Name: name}
	if namespace == "" || name == "" {
		return key, nil, failure("MissingParameter", "A namespace and metric name are required.")
	}
	ordered := make([]Dimension, len(dimensions))
	for i, dimension := range dimensions {
		if dimension.Name == nil || dimension.Value == nil {
			return key, nil, failure("MissingParameter", "Each dimension requires a name and value.")
		}
		ordered[i] = Dimension{value(dimension.Name), value(dimension.Value)}
	}
	slices.SortFunc(ordered, func(a, b Dimension) int { return cmp.Compare(a.Name, b.Name) })
	var encoded strings.Builder
	for i, dimension := range ordered {
		if i > 0 && ordered[i-1].Name == dimension.Name {
			return key, nil, invalid("No metric may specify the same dimension name twice.")
		}
		encoded.WriteString(strconv.Itoa(len(dimension.Name)))
		encoded.WriteByte(':')
		encoded.WriteString(dimension.Name)
		encoded.WriteString(strconv.Itoa(len(dimension.Value)))
		encoded.WriteByte(':')
		encoded.WriteString(dimension.Value)
	}
	key.Dimensions = encoded.String()
	return key, ordered, nil
}

func (s *Service) authorize(r Reader, action, namespace string) *awswire.Error {
	m := awsctx.FromContext(r.Context())
	var conditions map[string][]string
	if action == "PutMetricData" {
		conditions = map[string][]string{"cloudwatch:namespace": {namespace}}
	}
	return s.authorizer.Authorize(r.Context(), authorization.Request{
		Action: "cloudwatch:" + action, ResourceARN: "*", ResourceAccountID: m.AccountID, Context: conditions,
	})
}
