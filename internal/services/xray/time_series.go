package xray

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/xray"
)

// This is a local response bound, not AWS's unpublished index page size.
const timeSeriesPageSize = 1000

type timeSeriesCursor struct {
	Query  string `json:"q"`
	Before int64  `json:"b"`
}

func timeSeriesSelector(source string) (*traceSelector, error) {
	tokens, err := traceLex(source)
	if err != nil {
		return nil, failure("InvalidRequestException", "Invalid entity selector: "+err.Error())
	}
	p := traceFilterParser{tokens: tokens}
	kind := strings.ToLower(p.take().text)
	invalid := func() (*traceSelector, error) {
		return nil, failure("InvalidRequestException", "Invalid entity selector expression")
	}
	if kind != "service" && kind != "edge" || p.require("(") != nil {
		return invalid()
	}
	selector := &traceSelector{kind: kind}
	selector.source, err = p.parseID()
	if err != nil {
		return invalid()
	}
	if kind == "edge" {
		if p.require(",") != nil {
			return invalid()
		}
		selector.destination, err = p.parseID()
		if err != nil {
			return invalid()
		}
	}
	if p.require(")") != nil || p.peek().kind != "eof" {
		return invalid()
	}
	return selector, nil
}

func (s *Service) getTimeSeriesServiceStatistics(tx Transaction, in *api.GetTimeSeriesServiceStatisticsRequest) (*api.GetTimeSeriesServiceStatisticsResult, error) {
	if err := s.authorizeResource(tx, authorization.Request{Action: "xray:GetTimeSeriesServiceStatistics", ResourceARN: "*"}); err != nil {
		return nil, err
	}
	window, err := queryWindow(in.StartTime, in.EndTime)
	if err != nil {
		return nil, err
	}
	period := time.Minute
	if in.Period != nil {
		if *in.Period != 60 && *in.Period != 300 {
			return nil, failure("InvalidRequestException", "Time period must be one of [60, 300]")
		}
		period = time.Duration(*in.Period) * time.Second
	}
	if in.ForecastStatistics != nil && bool(*in.ForecastStatistics) {
		// TODO: Comeback implement forecasts through the X-Ray Insights owner;
		// historical observations are not a forecast model.
		return nil, failure("NotImplementedException", "X-Ray forecast statistics are not implemented", 501)
	}
	var selector *traceSelector
	if in.EntitySelectorExpression != nil {
		selector, err = timeSeriesSelector(string(*in.EntitySelectorExpression))
		if err != nil {
			return nil, err
		}
	}
	group := defaultGroup(scopeFor(tx.Context()))
	if in.GroupName != nil || in.GroupARN != nil {
		group, err = resolveGroup(tx, value(in.GroupName), value(in.GroupARN))
		if errors.Is(err, ErrNotFound) {
			return nil, failure("InvalidRequestException", "Group not found.")
		}
		if err != nil {
			return nil, err
		}
	}
	request := *in
	request.NextToken = nil
	identity, err := json.Marshal(struct {
		Group   GroupKey
		Request api.GetTimeSeriesServiceStatisticsRequest
	}{group.Key, request})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(identity)
	query := base64.RawURLEncoding.EncodeToString(digest[:])
	cursor := timeSeriesCursor{Query: query}
	if in.NextToken != nil {
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(string(*in.NextToken))
		if decodeErr != nil || json.Unmarshal(decoded, &cursor) != nil || cursor.Query != query || cursor.Before == 0 {
			return nil, failure("InvalidRequestException", "Invalid token "+string(*in.NextToken))
		}
	}
	// Native selects one-minute bucket endpoints in [StartTime, EndTime),
	// truncating request fractions to seconds. A five-minute period then merges
	// those selected minute buckets; it does not widen the selection window.
	receipts := traceWindow{Start: window.Start.Truncate(time.Minute).Add(-time.Minute), End: window.End.Truncate(time.Minute)}
	views, oldVersions, err := s.serviceGraphViews(tx, group, receipts)
	if err != nil {
		return nil, err
	}
	buckets := map[int64]*traceGraphStats{}
	service := selector != nil && selector.kind == "service"
	for _, view := range views {
		selected := timeSeriesEntities(view, selector)
		for _, entity := range view.entities {
			view.visitGraphObservations(entity, func(at time.Time, observation traceGraphObservation) {
				minute := at.Truncate(time.Minute).Add(time.Minute).Unix()
				if minute < window.Start.Unix() || minute >= window.End.Unix() {
					return
				}
				stamp := time.Unix(minute, 0).Add(-time.Second).Truncate(period).Add(period).Unix()
				stats := buckets[stamp]
				if stats == nil {
					stats = &traceGraphStats{}
					buckets[stamp] = stats
				}
				if selected[entity] {
					stats.addResponse(entity, observation, service)
				}
			})
		}
	}
	// Native selector reads of named groups report old-group statistics even
	// before a filter replacement; see time_series_west.json. Default-group
	// selectors do not set this flag (time_series_settled.json).
	oldVersions = oldVersions || selector != nil && group.Key.Name != "Default" && len(buckets) > 0
	out := &api.GetTimeSeriesServiceStatisticsResult{ContainsOldGroupVersions: new(api.Boolean(oldVersions)), TimeSeriesServiceStatistics: api.TimeSeriesServiceStatisticsList{}}
	stamps := make([]int64, 0, len(buckets))
	for stamp := range buckets {
		if in.NextToken == nil || stamp < cursor.Before {
			stamps = append(stamps, stamp)
		}
	}
	sort.Slice(stamps, func(i, j int) bool { return stamps[i] > stamps[j] })
	for _, stamp := range stamps[:min(len(stamps), timeSeriesPageSize)] {
		stats := buckets[stamp]
		point := api.TimeSeriesServiceStatistics{Timestamp: new(time.Unix(stamp, 0).UTC()), ServiceForecastStatistics: &api.ForecastStatistics{}}
		if stats.total > 0 {
			if service {
				point.ServiceSummaryStatistics = stats.serviceAPI()
			} else {
				point.EdgeSummaryStatistics = stats.edgeAPI()
			}
			point.ResponseTimeHistogram = stats.histogramAPI()
		}
		out.TimeSeriesServiceStatistics = append(out.TimeSeriesServiceStatistics, point)
	}
	if len(stamps) > timeSeriesPageSize {
		encoded, err := json.Marshal(timeSeriesCursor{Query: query, Before: stamps[timeSeriesPageSize-1]})
		if err != nil {
			return nil, err
		}
		out.NextToken = traceString(base64.RawURLEncoding.EncodeToString(encoded))
	}
	return out, nil
}

func timeSeriesEntities(view *traceView, selector *traceSelector) map[*traceEntity]bool {
	selected := make(map[*traceEntity]bool)
	if selector != nil && selector.kind == "service" {
		for _, node := range view.nodes {
			if selector.source.matches(node) {
				for _, entity := range node.entities {
					selected[entity] = true
				}
				if node.client {
					for _, edge := range view.edges {
						if edge.source == node {
							selected[edge.entity] = true
						}
					}
				}
			}
		}
	} else {
		for _, edge := range view.edges {
			if selector == nil && edge.source.client || selector != nil && selector.source.matches(edge.source) && selector.destination.matches(edge.destination) {
				selected[edge.entity] = true
			}
		}
	}
	return selected
}
