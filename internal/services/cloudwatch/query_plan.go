package cloudwatch

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

var metricQueryID = regexp.MustCompile(`^[a-z][a-zA-Z0-9_]*$`)

type metricQueryPlan struct {
	indices       map[string]int
	nodes         []*mathNode
	compiled      []queryMetric
	defaultPeriod int64
	insights      *insightsQuery
	insightsIndex int
	searches      []*mathNode
}

// Each consumer owns its native time window. Statistics and expression execution
// are shared; alarm rolling windows do not inherit GetMetricData end rounding.
type metricQueryBounds struct {
	start, end int64
	available  bool
}
type metricQueryWindow func(period int64, insights bool) metricQueryBounds

type metricBucketReader func(Reader, string, int64, int64, int64, string, bool) ([]*metricBucket, *awswire.Error)

func compileMetricQueryPlan(scope Scope, queries api.MetricDataQueries) (*metricQueryPlan, *awswire.Error) {
	indices := make(map[string]int, len(queries))
	nodes := make([]*mathNode, len(queries))
	compiled := make([]queryMetric, len(queries))
	defaultPeriod := int64(0)
	for i, q := range queries {
		id := value(q.Id)
		if !metricQueryID.MatchString(id) {
			return nil, mathValidation(fmt.Sprintf("The value for parameter MetricDataQueries.member.%d.Id is not matching the expected pattern ^[a-z][a-zA-Z0-9_]*$.", i+1))
		}
		if _, exists := indices[id]; exists {
			return nil, mathValidation("The values for parameter id in MetricDataQueries are not unique.")
		}
		indices[id] = i
		if q.Expression != nil && q.MetricStat != nil {
			return nil, mathValidation(fmt.Sprintf("The parameters MetricDataQueries.member.%d.Expression and MetricDataQueries.member.%d.MetricStat are mutually exclusive and you have specified both.", i+1, i+1))
		}
		if q.Expression == nil && q.MetricStat == nil {
			return nil, mathValidation("Each MetricDataQuery must specify Expression or MetricStat.")
		}
		if q.Period != nil && !validPeriod(int64(*q.Period)) {
			return nil, mathValidation("Invalid query Period.")
		}
		if q.MetricStat != nil {
			stat := q.MetricStat
			if stat.Metric == nil || stat.Period == nil || !validPeriod(int64(*stat.Period)) {
				return nil, mathValidation("MetricStat requires a metric and a valid period.")
			}
			spec, ok := parseStatistic(value(stat.Stat))
			if !ok {
				return nil, mathValidation(fmt.Sprintf("The value for parameter MetricDataQueries.member.%d.MetricStat.Stat is not a valid statistic.", i+1))
			}
			if defaultPeriod == 0 || int64(*stat.Period) < defaultPeriod {
				defaultPeriod = int64(*stat.Period)
			}
			key, dimensions, w := metricIdentity(scope, value(stat.Metric.Namespace), value(stat.Metric.MetricName), stat.Metric.Dimensions)
			if w != nil {
				return nil, w
			}
			if q.AccountId != nil {
				key.AccountID = value(q.AccountId)
			}
			compiled[i] = queryMetric{key: key, dimensions: dimensions, statistic: spec, period: int64(*stat.Period)}
		}
	}
	if defaultPeriod == 0 {
		defaultPeriod = 60
	}
	plan := &metricQueryPlan{indices: indices, nodes: nodes, compiled: compiled, defaultPeriod: defaultPeriod, insightsIndex: -1}
	for i, q := range queries {
		if q.Expression != nil {
			if isInsightsExpression(value(q.Expression)) {
				if plan.insights != nil {
					return nil, mathValidation("Maximum number of queries (1) exceeded")
				}
				if q.Period == nil {
					return nil, expressionError(value(q.Id), mathValidation("Period is a required field when using query within an expression"))
				}
				query, w := parseInsights(value(q.Expression))
				if w != nil {
					return nil, expressionError(value(q.Id), w)
				}
				if query.usesTags() && strings.HasPrefix(query.namespace, "AWS/") {
					// TODO: Comeback: retain resource-associated metric tag versions
					// with their actual service producers before admitting these queries.
					return nil, expressionError(value(q.Id), unsupported("Metrics Insights resource-tag associations are not implemented for AWS service metrics."))
				}
				plan.insights, plan.insightsIndex = query, i
				continue
			}
			node, w := parseMath(value(q.Expression))
			if w != nil {
				return nil, expressionError(value(q.Id), w)
			}
			nodes[i] = node
			inheritedPeriod := int64(0)
			if q.Period != nil {
				inheritedPeriod = int64(*q.Period)
			}
			if w := compileMetricSearches(node, inheritedPeriod, &plan.searches); w != nil {
				return nil, expressionError(value(q.Id), w)
			}
		}
	}

	return plan, nil
}

func evaluateMetricQueryPlan(r Reader, scope Scope, queries api.MetricDataQueries, plan *metricQueryPlan, now time.Time, window metricQueryWindow, readBuckets metricBucketReader, page *metricQueryPage) ([]evaluatedQuery, api.MetricDataResultMessages, *awswire.Error) {
	sources, w := prepareMetricSources(r, scope, queries, plan, now, window)
	if w != nil {
		return nil, nil, w
	}
	if w := sources.read(r, page, readBuckets); w != nil {
		return nil, nil, w
	}
	evaluated := make([]evaluatedQuery, len(queries))
	var resolve func(string) (mathValue, *awswire.Error)
	resolve = func(id string) (mathValue, *awswire.Error) {
		index, exists := plan.indices[id]
		if !exists {
			return mathValue{}, mathValidation("ID '" + id + "' not found")
		}
		result := &evaluated[index]
		if result.state == 2 {
			return result.value, nil
		}
		if result.state == 1 {
			return mathValue{}, mathValidation("Circular dependency involving '" + id + "'.")
		}
		result.state = 1
		result.status = "Complete"
		q := queries[index]
		if index == plan.insightsIndex {
			period := max(int64(*q.Period), 60)
			var w *awswire.Error
			*result, w = evaluateInsights(r, scope, plan.insights, now, period, window(period, true), readBuckets)
			if w != nil {
				return mathValue{}, expressionError(id, w)
			}
			if !result.value.array {
				result.value.series[0].label = id
			}
		} else if q.MetricStat != nil {
			source := sources.direct[index]
			result.value = mathValue{series: []*mathSeries{source.series}}
			result.messages = source.messages
			if q.AccountId != nil && value(q.AccountId) != scope.AccountID {
				result.status = "Forbidden"
				result.messages = api.MetricDataResultMessages{dataMessage("Forbidden", "Access denied when getting data - please check that this account and the requested metric account are linked")}
			}
		} else {
			period := plan.defaultPeriod
			if q.Period != nil {
				period = int64(*q.Period)
			}
			bounds := window(period, false)
			environment := mathEnvironment{start: bounds.start, end: bounds.end, period: period}
			environment.resolve = func(dependency string) (mathValue, *awswire.Error) {
				v, w := resolve(dependency)
				if w == nil {
					dep := evaluated[plan.indices[dependency]]
					if dep.status != "Complete" {
						result.status, result.messages = dep.status, dep.messages
					}
				}
				return v, w
			}
			environment.metrics = func(filter string) (mathValue, *awswire.Error) {
				all := mathValue{array: true, series: []*mathSeries{}}
				for _, metricQuery := range queries {
					if metricQuery.MetricStat == nil || !strings.Contains(value(metricQuery.Id), filter) {
						continue
					}
					v, w := environment.resolve(value(metricQuery.Id))
					if w != nil {
						return all, w
					}
					all.series = append(all.series, v.series...)
				}
				return all, nil
			}
			environment.search = func(node *mathNode) (mathValue, *awswire.Error) {
				found := sources.searches[node]
				all := mathValue{array: true, series: make([]*mathSeries, len(found))}
				for i, source := range found {
					all.series[i] = source.series
				}
				return all, nil
			}
			v, w := environment.evaluate(plan.nodes[index])
			if w != nil {
				return v, expressionError(id, w)
			}
			if v.scalar != nil || v.series == nil {
				return v, mathValidation("The expression '" + id + "' must return a time series or array of time series.")
			}
			if result.status == "Forbidden" || result.status == "InternalError" {
				v = mathValue{series: []*mathSeries{{period: period, values: map[int64]float64{}}}}
			}
			expressionSeries := make([]*mathSeries, len(v.series))
			for i, source := range v.series {
				if !v.array && q.Period != nil && source.period != period {
					// TODO: Comeback: expression-level period resampling needs native
					// alignment/aggregation semantics; never silently ignore the requested period.
					return mathValue{}, unsupported("Changing the period of a metric math result is not implemented.")
				}
				copy := *source
				copy.metric = false
				if !v.array {
					copy.label = id
				}
				expressionSeries[i] = &copy
			}
			v.series = expressionSeries
			result.value = v
		}
		result.state = 2
		return result.value, nil
	}
	messages := sources.messages
	for _, q := range queries {
		if _, w := resolve(value(q.Id)); w != nil {
			return nil, nil, w
		}
		messages = append(messages, evaluated[plan.indices[value(q.Id)]].topMessages...)
	}
	return evaluated, messages, nil
}
