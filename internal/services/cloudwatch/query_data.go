package cloudwatch

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

type dataCursor struct {
	Selection string
	Offsets   []int64
}
type evaluatedQuery struct {
	value       mathValue
	status      string
	messages    api.MetricDataResultMessages
	topMessages api.MetricDataResultMessages
	state       uint8
}

func dataMessage(code, message string) api.MessageData {
	return api.MessageData{Code: new(api.MessageDataCode(code)), Value: new(api.MessageDataValue(message))}
}

func (s *Service) getMetricData(r Transaction, in *api.GetMetricDataInput) (*api.GetMetricDataOutput, *awswire.Error) {
	if w := s.authorize(r, "GetMetricData", ""); w != nil {
		return nil, w
	}
	if in.StartTime == nil || in.EndTime == nil {
		return nil, mathValidation("StartTime and EndTime are required.")
	}
	if in.StartTime.Equal(*in.EndTime) {
		return nil, mathValidation("The parameter StartTime must not equal parameter EndTime.")
	}
	if in.StartTime.After(*in.EndTime) {
		return nil, mathValidation("The parameter EndTime must be greater than StartTime.")
	}
	if len(in.MetricDataQueries) == 0 || len(in.MetricDataQueries) > 500 {
		return nil, mathValidation("MetricDataQueries must contain between 1 and 500 queries.")
	}
	limit := int64(100800)
	if in.MaxDatapoints != nil {
		limit = int64(*in.MaxDatapoints)
	}
	if limit < 1 || limit > 100800 {
		return nil, mathValidation("MaxDatapoints must be between 1 and 100800.")
	}
	descending := value(in.ScanBy) != "TimestampAscending"
	if in.ScanBy != nil && value(in.ScanBy) != "TimestampAscending" && value(in.ScanBy) != "TimestampDescending" {
		return nil, mathValidation("Invalid ScanBy value.")
	}
	scope := scopeFor(r.Context())
	plan, w := compileMetricQueryPlan(scope, in.MetricDataQueries)
	if w != nil {
		return nil, w
	}
	selectionInput := *in
	selectionInput.NextToken = nil
	selection, _ := json.Marshal(struct {
		Scope Scope
		Input api.GetMetricDataInput
	}{scope, selectionInput})
	page := &metricQueryPage{limit: limit, descending: descending}
	if in.NextToken != nil && plan.insights == nil {
		var cursor dataCursor
		bytes, err := base64.RawURLEncoding.DecodeString(value(in.NextToken))
		if err != nil || json.Unmarshal(bytes, &cursor) != nil || cursor.Selection != string(selection) || cursor.Offsets == nil {
			return nil, failure("InvalidNextToken", "")
		}
		page.offsets = cursor.Offsets
	}
	now := s.clock.Now()
	evaluated, messages, w := evaluateMetricQueryPlan(r, scope, in.MetricDataQueries, plan, now, func(period int64, insights bool) metricQueryBounds {
		if insights {
			return metricQueryBounds{start: floorTime(in.StartTime.Unix(), 60), end: floorTime(in.EndTime.Unix(), 60), available: true}
		}
		start, end, available := metricWindow(*in.StartTime, *in.EndTime, now, period)
		return metricQueryBounds{start: start, end: end, available: available}
	}, s.readMetricPointBuckets, page)
	if w != nil {
		return nil, w
	}
	out := &api.GetMetricDataOutput{MetricDataResults: api.MetricDataResults{}, Messages: append(api.MetricDataResultMessages{}, messages...)}
	expressions := false
	// Direct metrics precede expressions; order within each partition is the
	// request order, including expressions that depend on a later query.
	for _, direct := range [...]bool{true, false} {
		for i, q := range in.MetricDataQueries {
			if (q.MetricStat != nil) != direct {
				continue
			}
			expressions = expressions || q.Expression != nil
			if q.ReturnData != nil && !bool(*q.ReturnData) {
				continue
			}
			result := evaluated[i]
			for _, series := range result.value.series {
				if series.omitted {
					continue
				}
				label := series.label
				if q.Expression != nil && !result.value.array {
					label = value(q.Id)
				}
				if q.Label != nil {
					label = value(q.Label)
					if result.value.array && !strings.Contains(label, "${LABEL}") {
						if label != "" && series.label != "" {
							label += " "
						}
						label += series.label
					}
				}
				var outputLabel *api.MetricLabel
				if result.status != "InternalError" {
					expanded, w := s.metricDataLabel(label, series, in.LabelOptions, scope)
					if w != nil {
						return nil, w
					}
					outputLabel = new(api.MetricLabel(expanded))
				}
				status, messages := result.status, result.messages
				if status == "Complete" && series.partial {
					status = "PartialData"
					if q.Expression != nil {
						messages = append(messages, dataMessage("PartialData", "The expression may contain partial data as one or more metrics have StatusCode 'Paginated'"))
					}
				}
				times := seriesTimes(series)
				if descending {
					slices.Reverse(times)
				}
				projected := api.MetricDataResult{Id: q.Id, Label: outputLabel, StatusCode: new(api.StatusCode(status)), Messages: messages, Timestamps: make(api.Timestamps, 0, len(times)), Values: make(api.DatapointValues, 0, len(times))}
				for _, at := range times {
					projected.Timestamps = append(projected.Timestamps, time.Unix(at, 0).UTC())
					projected.Values = append(projected.Values, api.DatapointValue(series.values[at]))
				}
				out.MetricDataResults = append(out.MetricDataResults, projected)
			}
		}
	}
	if page.more && !expressions {
		bytes, _ := json.Marshal(dataCursor{Selection: string(selection), Offsets: page.offsets})
		out.NextToken = new(api.NextToken(base64.RawURLEncoding.EncodeToString(bytes)))
	}
	return out, nil
}

func (s *Service) metricDataLabel(label string, series *mathSeries, options *api.LabelOptions, scope Scope) (string, *awswire.Error) {
	if !strings.Contains(label, "${") {
		return label, nil
	}
	zone := time.UTC
	if options != nil && options.Timezone != nil {
		text := value(options.Timezone)
		parsed, err := time.Parse("-0700", text)
		if err != nil {
			return "", mathValidation("Invalid label timezone.")
		}
		_, offset := parsed.Zone()
		zone = time.FixedZone(text, offset)
	}
	times := seriesTimes(series)
	values := make([]float64, 0, len(times))
	for _, at := range times {
		values = append(values, series.values[at])
	}
	number := func(n float64) string { return strconv.FormatFloat(n, 'g', -1, 64) }
	formatTime := func(at int64) string { return time.Unix(at, 0).In(zone).Format("2006-01-02 15:04:05") }
	replace := map[string]string{"LABEL": series.label, "DATAPOINT_COUNT": strconv.Itoa(len(values)), "PROP('AccountId')": scope.AccountID, "PROP('Region')": scope.Region, "PROP('Period')": strconv.FormatInt(series.period, 10)}
	if metric := series.identity; metric != nil {
		replace["PROP('AccountId')"] = metric.key.AccountID
		replace["PROP('Region')"] = metric.key.Region
		replace["PROP('MetricName')"] = metric.key.Name
		replace["PROP('Namespace')"] = metric.key.Namespace
		replace["PROP('Stat')"] = metric.statistic.name
		for _, dimension := range metric.dimensions {
			replace["PROP('Dim."+dimension.Name+"')"] = dimension.Value
		}
	}
	if len(values) > 0 {
		for _, stat := range []string{"SUM", "AVG", "MIN", "MAX"} {
			replace[stat] = number(mathReduce(stat, values, len(values)))
		}
		first, last := times[0], times[len(times)-1]
		minimum, maximum := first, first
		for _, at := range times {
			if series.values[at] < series.values[minimum] {
				minimum = at
			}
			if series.values[at] > series.values[maximum] {
				maximum = at
			}
		}
		for name, at := range map[string]int64{"FIRST": first, "LAST": last, "MIN": minimum, "MAX": maximum} {
			replace[name] = number(series.values[at])
			replace[name+"_TIME"] = formatTime(at)
			replace[name+"_TIME_RELATIVE"] = strconv.FormatInt(int64(math.Abs(float64(s.clock.Now().Unix()-at))), 10) + "s"
		}
		replace["FIRST_LAST_RANGE"] = number(series.values[last] - series.values[first])
		replace["MIN_MAX_RANGE"] = number(series.values[maximum] - series.values[minimum])
		replace["FIRST_LAST_TIME_RANGE"] = strconv.FormatInt(last-first, 10) + "s"
		replace["MIN_MAX_TIME_RANGE"] = strconv.FormatInt(int64(math.Abs(float64(maximum-minimum))), 10) + "s"
	}
	var result strings.Builder
	for {
		start := strings.Index(label, "${")
		if start < 0 {
			result.WriteString(label)
			break
		}
		result.WriteString(label[:start])
		label = label[start+2:]
		end := strings.IndexByte(label, '}')
		if end < 0 {
			return "", mathValidation("Unterminated dynamic label.")
		}
		key := label[:end]
		text, ok := replace[key]
		if !ok && strings.HasPrefix(key, "PROP('Dim.") && strings.HasSuffix(key, "')") {
			text, ok = "--", true
		}
		if !ok {
			if len(values) == 0 {
				switch key {
				case "SUM", "AVG", "MIN", "MAX", "FIRST", "LAST", "FIRST_TIME", "LAST_TIME", "MIN_TIME", "MAX_TIME":
					ok = true
				}
			}
			if !ok {
				return "", unsupported("Dynamic label property " + key + " is not implemented.")
			}
		}
		result.WriteString(text)
		label = label[end+1:]
	}
	return result.String(), nil
}
