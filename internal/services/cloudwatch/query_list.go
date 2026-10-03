package cloudwatch

import (
	"encoding/base64"
	"encoding/json"
	"time"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

type metricListCursor struct {
	Selection string
	After     MetricKey
}

func (s *Service) listMetrics(r Transaction, in *api.ListMetricsInput) (*api.ListMetricsOutput, *awswire.Error) {
	if w := s.authorize(r, "ListMetrics", value(in.Namespace)); w != nil {
		return nil, w
	}
	if in.RecentlyActive != nil && value(in.RecentlyActive) != "PT3H" {
		return nil, invalid("Request parameter recentlyActive value is invalid")
	}
	scope := scopeFor(r.Context())
	selectionInput := *in
	selectionInput.NextToken = nil
	selection, _ := json.Marshal(struct {
		Scope Scope
		Input api.ListMetricsInput
	}{scope, selectionInput})
	query := MetricQuery{Scope: scope, Namespace: value(in.Namespace), Name: value(in.MetricName), Limit: 501, PublishedAfter: s.clock.Now().Add(-14 * 24 * time.Hour)}
	if in.RecentlyActive != nil {
		query.PublishedAfter = s.clock.Now().Add(-3 * time.Hour)
	}
	for _, dimension := range in.Dimensions {
		filter := DimensionFilter{Name: value(dimension.Name)}
		if dimension.Value != nil {
			filter.Value = new(value(dimension.Value))
		}
		query.Dimensions = append(query.Dimensions, filter)
	}
	if in.NextToken != nil {
		bytes, err := base64.RawURLEncoding.DecodeString(value(in.NextToken))
		var cursor metricListCursor
		if err != nil || json.Unmarshal(bytes, &cursor) != nil || cursor.Selection != string(selection) || cursor.After.Scope != scope || cursor.After.Name == "" {
			return nil, invalid("Request parameter NextToken is invalid")
		}
		query.After = &cursor.After
	}
	out := &api.ListMetricsOutput{Metrics: api.Metrics{}}
	linked := in.IncludeLinkedAccounts != nil && bool(*in.IncludeLinkedAccounts)
	if linked {
		out.OwningAccounts = api.OwningAccounts{}
	}
	// Only the current account is available without an observability link. An
	// owning-account filter never grants authority to read that account's metrics.
	if in.OwningAccount != nil && value(in.OwningAccount) != scope.AccountID {
		return out, nil
	}
	records, err := r.Metrics(query)
	if err != nil {
		return nil, wireError(err)
	}
	if len(records) > 500 {
		bytes, _ := json.Marshal(metricListCursor{Selection: string(selection), After: records[499].Key})
		out.NextToken = new(api.NextToken(base64.RawURLEncoding.EncodeToString(bytes)))
		records = records[:500]
	}
	for _, record := range records {
		metric := api.Metric{Namespace: new(api.Namespace(record.Key.Namespace)), MetricName: new(api.MetricName(record.Key.Name)), Dimensions: api.Dimensions{}}
		for _, dimension := range record.Dimensions {
			metric.Dimensions = append(metric.Dimensions, api.Dimension{Name: new(api.DimensionName(dimension.Name)), Value: new(api.DimensionValue(dimension.Value))})
		}
		out.Metrics = append(out.Metrics, metric)
		if linked {
			out.OwningAccounts = append(out.OwningAccounts, api.AccountId(scope.AccountID))
		}
	}
	return out, nil
}
