package wafv2

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	api "stackd/internal/awsapi/wafv2"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// Sampled requests are retained for the three hours GetSampledRequests can
// query; AWS WAF samples from the first 5,000 requests in a time window.
const (
	sampleRetention  = 3 * time.Hour
	maxSamplesPerKey = 5000
)

func registerObservations(s *Service) {
	register(s, "GetSampledRequests", s.sampledRequests)
	register(s, "GetRateBasedStatementManagedKeys", s.managedKeys)
}

func enabled(v *api.Boolean) bool { return v != nil && bool(*v) }

func actionMetric(action string) string {
	if action == "BLOCK" {
		return "BlockedRequests"
	}
	if action == "COUNT" {
		return "CountedRequests"
	}
	return "AllowedRequests"
}

// observe records AWS/WAFV2 metrics and sampled requests for one evaluation
// according to each rule's and the web ACL's VisibilityConfig.
func (s *Service) observe(ctx context.Context, e *evaluation, result outcome, verdict Verdict) error {
	acl := e.acl
	minute := e.now.Truncate(time.Minute)
	type metric struct {
		rule, name string
	}
	var metrics []metric
	type sample struct {
		metric, action string
	}
	var samples []sample
	for _, rule := range result.counted {
		if enabled(rule.VisibilityConfig.CloudWatchMetricsEnabled) {
			metrics = append(metrics, metric{value(rule.VisibilityConfig.MetricName), "CountedRequests"})
		}
		if enabled(rule.VisibilityConfig.SampledRequestsEnabled) {
			samples = append(samples, sample{value(rule.VisibilityConfig.MetricName), "COUNT"})
		}
	}
	if rule := result.rule; rule != nil {
		if enabled(rule.VisibilityConfig.CloudWatchMetricsEnabled) {
			metrics = append(metrics, metric{value(rule.VisibilityConfig.MetricName), actionMetric(result.action)})
		}
		if enabled(rule.VisibilityConfig.SampledRequestsEnabled) {
			samples = append(samples, sample{value(rule.VisibilityConfig.MetricName), result.action})
		}
	}
	visibility := acl.Definition.VisibilityConfig
	if enabled(visibility.CloudWatchMetricsEnabled) {
		metrics = append(metrics, metric{"ALL", actionMetric(result.action)})
		if result.rule == nil {
			metrics = append(metrics, metric{"Default_Action", actionMetric(result.action)})
		}
	}
	if result.rule == nil && enabled(visibility.SampledRequestsEnabled) {
		samples = append(samples, sample{value(visibility.MetricName), result.action})
	}
	if len(metrics) == 0 || s.metrics == nil {
		metrics = nil
	}
	if len(metrics) == 0 && len(samples) == 0 {
		return nil
	}
	request := e.sampledRequest()
	err := s.repository.Update(ctx, func(t Transaction) error {
		for _, m := range metrics {
			key := MetricKey{Scope: acl.Scope, WebACL: value(visibility.MetricName), Rule: m.rule, Minute: minute}
			if err := t.AddMetricSample(key, MetricSample{Name: m.name, Count: 1}); err != nil {
				return err
			}
		}
		if len(samples) == 0 {
			return nil
		}
		if err := t.PruneSamples(e.now.Add(-sampleRetention)); err != nil {
			return err
		}
		for _, x := range samples {
			if err := t.AddSamplePopulation(acl.Scope, acl.ARN, x.metric, minute, 1); err != nil {
				return err
			}
			n, err := t.SampleCount(acl.Scope, acl.ARN, x.metric, e.now.Add(-sampleRetention))
			if err != nil {
				return err
			}
			if n >= maxSamplesPerKey {
				continue
			}
			record := request
			record.Action = new(api.Action(x.action))
			if verdict.Custom && x.action == "BLOCK" {
				record.ResponseCodeSent = new(api.ResponseStatusCode(verdict.Status))
			}
			if x.action != "BLOCK" {
				for name, values := range verdict.InsertHeaders {
					for _, v := range values {
						record.RequestHeadersInserted = append(record.RequestHeadersInserted, api.HTTPHeader{Name: new(api.HeaderName(strings.ToLower(name))), Value: new(api.HeaderValue(v))})
					}
				}
			}
			if err := t.PutSampledRequest(SampledRequest{Scope: acl.Scope, WebACLARN: acl.ARN, MetricName: x.metric, At: e.now, Sequence: e.now.UnixNano(), Sample: record}); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil && len(metrics) > 0 {
		s.jobs.Wake()
	}
	return err
}

func (e *evaluation) sampledRequest() api.SampledHTTPRequest {
	uri := e.req.URI
	if e.req.RawQuery != "" {
		uri += "?" + e.req.RawQuery
	}
	request := &api.HTTPRequest{ClientIP: new(api.IPString(e.req.SourceIP)), Method: new(api.HTTPMethod(e.req.Method)), URI: new(api.URIString(uri)), HTTPVersion: new(api.HTTPVersion(e.req.HTTPVersion)), Headers: api.HTTPHeaders{}}
	for _, name := range slices.Sorted(maps.Keys(e.req.Header)) {
		for _, v := range e.req.Header[name] {
			request.Headers = append(request.Headers, api.HTTPHeader{Name: new(api.HeaderName(name)), Value: new(api.HeaderValue(v))})
		}
	}
	out := api.SampledHTTPRequest{Request: request, Weight: new(api.SampleWeight(1)), Timestamp: new(e.now)}
	for _, label := range e.labels {
		out.Labels = append(out.Labels, api.Label{Name: new(api.LabelName(label))})
	}
	return out
}

type metricJobs struct{ s *Service }

func (j metricJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	if j.s.metrics == nil {
		return
	}
	err = j.s.repository.View(ctx, func(r Reader) error {
		key, err := r.NextMetricPublication()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(key)
		if err != nil {
			return err
		}
		// AWS WAF reports metrics once a minute; publish completed minutes.
		job, found = scheduler.Job{Key: string(encoded), Due: key.Minute.Add(time.Minute)}, true
		return nil
	})
	return
}

func (j metricJobs) Run(ctx context.Context, job scheduler.Job) error {
	var key MetricKey
	if err := json.Unmarshal([]byte(job.Key), &key); err != nil {
		return err
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region})
	return j.s.repository.Update(ctx, func(t Transaction) error {
		samples, err := t.MetricSamples(key)
		if err != nil || len(samples) == 0 {
			return err
		}
		dimensions := metricsapi.Dimensions{
			{Name: new(metricsapi.DimensionName("Region")), Value: new(metricsapi.DimensionValue(key.Region))},
			{Name: new(metricsapi.DimensionName("Rule")), Value: new(metricsapi.DimensionValue(key.Rule))},
			{Name: new(metricsapi.DimensionName("WebACL")), Value: new(metricsapi.DimensionValue(key.WebACL))},
		}
		unit := metricsapi.StandardUnitCount
		data := make([]metricsapi.MetricDatum, 0, len(samples))
		for _, sample := range samples {
			data = append(data, metricsapi.MetricDatum{MetricName: new(metricsapi.MetricName(sample.Name)), Dimensions: dimensions,
				Timestamp: new(metricsapi.Timestamp(key.Minute)), Unit: &unit, Value: new(metricsapi.DatapointValue(float64(sample.Count)))})
		}
		if err := j.s.metrics.Publish(t.Context(), "AWS/WAFV2", data); err != nil {
			return err
		}
		return t.DeleteMetricPublication(key)
	})
}

func (s *Service) sampledRequests(ctx context.Context, t Transaction, in *api.GetSampledRequestsInput) (*api.GetSampledRequestsOutput, error) {
	if err := requireRegional(in.Scope); err != nil {
		return nil, err
	}
	acl, err := s.webACLByARN(ctx, t, value(in.WebAclArn), "GetSampledRequests")
	if err != nil {
		return nil, err
	}
	if in.MaxItems == nil || *in.MaxItems < 1 || *in.MaxItems > 500 {
		return nil, invalidParameter("MAX_ITEMS", "MaxItems", "MaxItems must be between 1 and 500")
	}
	metric := value(in.RuleMetricName)
	if !metricName.MatchString(metric) {
		return nil, invalidParameter("METRIC_NAME", metric, "RuleMetricName is not valid")
	}
	if in.TimeWindow == nil || in.TimeWindow.StartTime == nil || in.TimeWindow.EndTime == nil || !in.TimeWindow.StartTime.Before(*in.TimeWindow.EndTime) {
		return nil, invalidParameter("TIME_WINDOW", "TimeWindow", "TimeWindow requires a StartTime before its EndTime")
	}
	now := s.clock.Now().UTC()
	start, end := in.TimeWindow.StartTime.UTC(), in.TimeWindow.EndTime.UTC()
	if start.Before(now.Add(-sampleRetention)) {
		return nil, invalidParameter("TIME_WINDOW", "StartTime", "StartTime must be within the previous three hours")
	}
	rows, err := t.SampledRequests(acl.Scope, acl.ARN, metric, start, end, int(*in.MaxItems))
	if err != nil {
		return nil, err
	}
	population, err := t.SamplePopulation(acl.Scope, acl.ARN, metric, start, end)
	if err != nil {
		return nil, err
	}
	out := &api.GetSampledRequestsOutput{SampledRequests: api.SampledHTTPRequests{}, PopulationSize: new(api.PopulationSize(population)), TimeWindow: &api.TimeWindow{StartTime: new(start), EndTime: new(end)}}
	for _, row := range rows {
		out.SampledRequests = append(out.SampledRequests, row.Sample)
	}
	return out, nil
}

func (s *Service) managedKeys(ctx context.Context, t Transaction, in *api.GetRateBasedStatementManagedKeysInput) (*api.GetRateBasedStatementManagedKeysOutput, error) {
	if err := requireRegional(in.Scope); err != nil {
		return nil, err
	}
	if in.RuleGroupRuleName != nil {
		return nil, unsupported("RuleGroupRuleName", "rule groups are not implemented")
	}
	acl, err := s.loadWebACL(ctx, t, value(in.WebACLName), value(in.WebACLId), "GetRateBasedStatementManagedKeys")
	if err != nil {
		return nil, err
	}
	var rule *api.Rule
	for i := range acl.Definition.Rules {
		if value(acl.Definition.Rules[i].Name) == value(in.RuleName) {
			rule = &acl.Definition.Rules[i]
		}
	}
	if rule == nil || rule.Statement.RateBasedStatement == nil {
		return nil, nonexistent("The web ACL has no rate-based rule named " + value(in.RuleName))
	}
	v := rule.Statement.RateBasedStatement
	if k := value(v.AggregateKeyType); k != "IP" && k != "FORWARDED_IP" {
		return nil, failure("WAFUnsupportedAggregateKeyTypeException", "Managed keys are available only for IP and FORWARDED_IP aggregation", 400)
	}
	window := 300 * time.Second
	if v.EvaluationWindowSec != nil {
		window = time.Duration(*v.EvaluationWindowSec) * time.Second
	}
	config, _ := json.Marshal(v)
	v4 := &api.RateBasedStatementManagedKeysIPSet{IPAddressVersion: new(api.IPAddressVersion("IPV4")), Addresses: api.IPAddresses{}}
	v6 := &api.RateBasedStatementManagedKeysIPSet{IPAddressVersion: new(api.IPAddressVersion("IPV6")), Addresses: api.IPAddresses{}}
	keys := s.rates.limited(acl.ARN, value(rule.Name), string(config), s.clock.Now().UTC(), window, int64(*v.Limit))
	slices.Sort(keys)
	for _, key := range keys {
		addr, err := netip.ParseAddr(key)
		if err != nil {
			continue
		}
		if addr.Is4() {
			v4.Addresses = append(v4.Addresses, api.IPAddress(netip.PrefixFrom(addr, 32).String()))
		} else {
			v6.Addresses = append(v6.Addresses, api.IPAddress(netip.PrefixFrom(addr, 128).String()))
		}
	}
	return &api.GetRateBasedStatementManagedKeysOutput{ManagedKeysIPV4: v4, ManagedKeysIPV6: v6}, nil
}
