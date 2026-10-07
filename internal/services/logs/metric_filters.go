package logs

import (
	"errors"
	"math"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/logs"
	"stackd/internal/awswire"
	"stackd/internal/services/logs/filterpattern"
)

const maxMetricFilters = 100
const maxRegexMetricFilters = 5

func metricIdentity(name string) bool {
	return utf8.ValidString(name) && utf8.RuneCountInString(name) <= 255 && !strings.ContainsAny(name, ":*$")
}

func metricTransformation(v *MetricFilterRecord, p *filterpattern.Pattern, in api.MetricTransformation) *awswire.Error {
	if in.MetricName == nil || in.MetricNamespace == nil || !metricIdentity(value(in.MetricName)) || !metricIdentity(value(in.MetricNamespace)) {
		return invalid("The metric name and namespace must be valid and specified.")
	}
	v.MetricName, v.MetricNamespace, v.MetricValue, v.Unit = value(in.MetricName), value(in.MetricNamespace), value(in.MetricValue), value(in.Unit)
	if in.MetricValue == nil || !utf8.ValidString(v.MetricValue) || utf8.RuneCountInString(v.MetricValue) > 100 {
		return invalid("A valid metric value is required.")
	}
	if strings.HasPrefix(v.MetricValue, "$") {
		if _, err := p.Extractor(v.MetricValue); err != nil {
			return invalid("Invalid metric transformation: " + err.Error())
		}
	} else if _, ok := metricNumber(v.MetricValue); !ok {
		return invalid("Invalid metric transformation: metric value must be a valid number")
	}
	if in.Unit != nil {
		switch *in.Unit {
		case api.StandardUnitSeconds, api.StandardUnitMicroseconds, api.StandardUnitMilliseconds,
			api.StandardUnitBytes, api.StandardUnitKilobytes, api.StandardUnitMegabytes, api.StandardUnitGigabytes, api.StandardUnitTerabytes,
			api.StandardUnitBits, api.StandardUnitKilobits, api.StandardUnitMegabits, api.StandardUnitGigabits, api.StandardUnitTerabits,
			api.StandardUnitPercent, api.StandardUnitCount, api.StandardUnitBytesSecond, api.StandardUnitKilobytesSecond,
			api.StandardUnitMegabytesSecond, api.StandardUnitGigabytesSecond, api.StandardUnitTerabytesSecond,
			api.StandardUnitBitsSecond, api.StandardUnitKilobitsSecond, api.StandardUnitMegabitsSecond,
			api.StandardUnitGigabitsSecond, api.StandardUnitTerabitsSecond, api.StandardUnitCountSecond, api.StandardUnitNone:
		default:
			return invalid("The metric unit is invalid.")
		}
	}
	if len(in.Dimensions)+len(v.EmitSystemFieldDimensions) > 3 {
		return invalid("Number of dimensions exceeds the maximum number of dimensions supported per metric filter")
	}
	if in.DefaultValue != nil {
		if len(in.Dimensions)+len(v.EmitSystemFieldDimensions) != 0 {
			return invalid("Invalid metric transformation: dimensions and default value are mutually exclusive properties")
		}
		n := float64(*in.DefaultValue)
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return invalid("The default value must be finite.")
		}
		v.DefaultValue = &n
	}
	if in.Dimensions != nil {
		v.Dimensions = make(map[string]string, len(in.Dimensions))
	}
	for key, source := range in.Dimensions {
		if !utf8.ValidString(string(key)) || !utf8.ValidString(string(source)) || utf8.RuneCountInString(string(key)) > 255 || utf8.RuneCountInString(string(source)) > 255 {
			return invalid("The metric dimension name or selector is invalid.")
		}
		if _, err := p.Extractor(string(source)); err != nil {
			return invalid("Invalid metric transformation: dimension value must be valid selector")
		}
		v.Dimensions[string(key)] = string(source)
	}
	return nil
}

func (s *Service) putMetricFilter(tx Transaction, in *api.PutMetricFilterRequest) (*api.PutMetricFilterOutput, *awswire.Error) {
	if in == nil {
		return nil, invalid("A request is required.")
	}
	g, w := s.loadGroup(tx, value(in.LogGroupName), "PutMetricFilter", "")
	if w != nil {
		return nil, w
	}
	v := MetricFilterRecord{Key: MetricFilterKey{g.ID, value(in.FilterName)}, GroupName: g.Key.Name, Pattern: value(in.FilterPattern), ApplyOnTransformedLogs: enabled(in.ApplyOnTransformedLogs), FieldSelection: value(in.FieldSelectionCriteria)}
	if w := resourceName(v.Key.Name, "metric filter"); w != nil {
		return nil, w
	}
	if in.FilterPattern == nil {
		return nil, invalid("A filter pattern is required.")
	}
	p, err := filterpattern.Compile(v.Pattern)
	if err != nil {
		return nil, invalid(err.Error())
	}
	regexCount := p.RegexCount()
	if len(in.MetricTransformations) != 1 {
		return nil, invalid("Exactly one metric transformation is required.")
	}
	if _, err := filterpattern.CompileSelection(v.FieldSelection); err != nil {
		return nil, invalid(err.Error())
	}
	for _, field := range in.EmitSystemFieldDimensions {
		if field != "@aws.account" && field != "@aws.region" && field != "@source.log" {
			return nil, invalid("The provided system fields are invalid.")
		}
		// Native admits duplicates; retain their order and dimension count.
		v.EmitSystemFieldDimensions = append(v.EmitSystemFieldDimensions, string(field))
	}
	if w := metricTransformation(&v, p, in.MetricTransformations[0]); w != nil {
		return nil, w
	}
	rows, err := tx.MetricFilters(MetricFilterQuery{Scope: g.Key.Scope, GroupID: g.ID, Limit: maxMetricFilters + 1})
	if err != nil {
		return nil, wireError(err)
	}
	v.Created = s.clock.Now().UnixMilli()
	replacing, regexFilters := false, 0
	owner, w := cloudFormationClaim(tx.Context(), "", false)
	for _, old := range rows {
		if old.Key == v.Key {
			owner, w = cloudFormationClaim(tx.Context(), old.CFNOwner, true)
			v.Created, replacing = old.Created, true
			continue
		}
		if regexCount != 0 {
			compiled, err := filterpattern.Compile(old.Pattern)
			if err != nil {
				return nil, wireError(err)
			}
			if compiled.RegexCount() != 0 {
				regexFilters++
			}
		}
	}
	if w != nil {
		return nil, w
	}
	v.CFNOwner = owner
	if !replacing && len(rows) >= maxMetricFilters || regexCount != 0 && regexFilters >= maxRegexMetricFilters {
		return nil, failure("LimitExceededException", "Resource limit exceeded.")
	}
	return &api.PutMetricFilterOutput{}, wireError(tx.PutMetricFilter(v))
}

func metricFilterOutput(v MetricFilterRecord) api.MetricFilter {
	transformation := api.MetricTransformation{MetricName: new(api.MetricName(v.MetricName)), MetricNamespace: new(api.MetricNamespace(v.MetricNamespace)), MetricValue: new(api.MetricValue(v.MetricValue))}
	if v.DefaultValue != nil {
		transformation.DefaultValue = new(api.DefaultValue(*v.DefaultValue))
	}
	if v.Unit != "" {
		transformation.Unit = new(api.StandardUnit(v.Unit))
	}
	if len(v.Dimensions) > 0 {
		transformation.Dimensions = make(api.Dimensions, len(v.Dimensions))
		for key, source := range v.Dimensions {
			transformation.Dimensions[api.DimensionsKey(key)] = api.DimensionsValue(source)
		}
	}
	out := api.MetricFilter{FilterName: new(api.FilterName(v.Key.Name)), FilterPattern: new(api.FilterPattern(v.Pattern)), LogGroupName: new(api.LogGroupName(v.GroupName)), CreationTime: new(api.Timestamp(v.Created)), ApplyOnTransformedLogs: new(api.ApplyOnTransformedLogs(v.ApplyOnTransformedLogs)), MetricTransformations: api.MetricTransformations{transformation}}
	if v.FieldSelection != "" {
		out.FieldSelectionCriteria = new(api.FieldSelectionCriteria(v.FieldSelection))
	}
	for _, field := range v.EmitSystemFieldDimensions {
		out.EmitSystemFieldDimensions = append(out.EmitSystemFieldDimensions, api.SystemField(field))
	}
	return out
}

func (s *Service) describeMetricFilters(tx Transaction, in *api.DescribeMetricFiltersRequest) (*api.DescribeMetricFiltersResponse, *awswire.Error) {
	if in == nil {
		return nil, invalid("A request is required.")
	}
	if (in.MetricName == nil) != (in.MetricNamespace == nil) || in.LogGroupName != nil && (in.MetricName != nil || in.MetricNamespace != nil) {
		return nil, invalid("Describe Metric Filters request must contain either logGroupName or metricName and metricNamespace")
	}
	if in.FilterNamePrefix != nil {
		if w := resourceName(value(in.FilterNamePrefix), "metric filter"); w != nil {
			return nil, w
		}
	}
	if !metricIdentity(value(in.MetricName)) || !metricIdentity(value(in.MetricNamespace)) {
		return nil, invalid("The metric name or namespace is invalid.")
	}
	limit, w := pageLimit(in.Limit, 50, 50)
	if w != nil {
		return nil, w
	}
	q := MetricFilterQuery{Scope: scopeFor(tx.Context()), MetricName: value(in.MetricName), MetricNamespace: value(in.MetricNamespace), Limit: limit + 1}
	if in.LogGroupName != nil {
		g, w := s.loadGroup(tx, value(in.LogGroupName), "DescribeMetricFilters", "")
		if w != nil {
			return nil, w
		}
		q.GroupID, q.Prefix = g.ID, value(in.FilterNamePrefix)
	} else if w := s.authorize(tx, "DescribeMetricFilters", GroupRecord{Key: GroupKey{Scope: q.Scope}}, "", nil, nil); w != nil {
		return nil, w
	}
	identity := queryIdentity("DescribeMetricFilters", q.Scope, q.GroupID, q.Prefix, q.MetricName, q.MetricNamespace)
	token, w := s.decodeToken(value(in.NextToken), identity)
	if w != nil {
		return nil, w
	}
	q.AfterName, q.AfterGroupName = token.Name, token.GroupName
	rows, err := tx.MetricFilters(q)
	if err != nil {
		return nil, wireError(err)
	}
	out := &api.DescribeMetricFiltersResponse{MetricFilters: api.MetricFilters{}}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	for _, row := range rows {
		out.MetricFilters = append(out.MetricFilters, metricFilterOutput(row))
	}
	if more {
		last := rows[len(rows)-1]
		token.Name, token.GroupName = last.Key.Name, last.GroupName
		out.NextToken = encodeToken(token)
	}
	return out, nil
}

func (s *Service) deleteMetricFilter(tx Transaction, in *api.DeleteMetricFilterRequest) (*api.DeleteMetricFilterOutput, *awswire.Error) {
	if in == nil {
		return nil, invalid("A request is required.")
	}
	g, w := s.loadGroup(tx, value(in.LogGroupName), "DeleteMetricFilter", "")
	if w != nil {
		return nil, w
	}
	key := MetricFilterKey{g.ID, value(in.FilterName)}
	if w := resourceName(key.Name, "metric filter"); w != nil {
		return nil, w
	}
	old, err := tx.MetricFilter(key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, failure("ResourceNotFoundException", "The specified metric filter does not exist.")
		}
		return nil, wireError(err)
	}
	if w := cloudFormationDelete(tx.Context(), old.CFNOwner); w != nil {
		return nil, w
	}
	return &api.DeleteMetricFilterOutput{}, wireError(tx.DeleteMetricFilter(key))
}

func (s *Service) testMetricFilter(tx Transaction, in *api.TestMetricFilterRequest) (*api.TestMetricFilterResponse, *awswire.Error) {
	if in == nil || in.FilterPattern == nil {
		return nil, invalid("A filter pattern is required.")
	}
	if w := s.authorize(tx, "TestMetricFilter", GroupRecord{Key: GroupKey{Scope: scopeFor(tx.Context())}}, "", nil, nil); w != nil {
		return nil, w
	}
	p, err := filterpattern.Compile(value(in.FilterPattern))
	if err != nil {
		return nil, invalid(err.Error())
	}
	if len(in.LogEventMessages) < 1 || len(in.LogEventMessages) > 50 {
		return nil, invalid("Specify between 1 and 50 log event messages.")
	}
	out := &api.TestMetricFilterResponse{Matches: api.MetricFilterMatches{}}
	for i, message := range in.LogEventMessages {
		if message == "" || !utf8.ValidString(string(message)) {
			return nil, invalid("Log event messages must be nonempty valid strings.")
		}
		matched, ok := p.Evaluate(string(message))
		if !ok {
			continue
		}
		extracted := api.ExtractedValues{}
		for key, value := range matched.ExtractedValues() {
			extracted[api.Token(key)] = api.Value(value)
		}
		// Native event numbers are one-based, unlike the API reference examples.
		out.Matches = append(out.Matches, api.MetricFilterMatchRecord{EventNumber: new(api.EventNumber(i + 1)), EventMessage: new(api.EventMessage(message)), ExtractedValues: extracted})
	}
	return out, nil
}
