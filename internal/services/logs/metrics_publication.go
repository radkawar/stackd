package logs

import (
	"math"
	"strconv"
	"strings"
	"time"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awswire"
	"stackd/internal/services/logs/filterpattern"
)

type metricDimension struct {
	name, literal string
	extractor     *filterpattern.Extractor
}

func metricNumber(text string) (float64, bool) {
	n, err := strconv.ParseFloat(text, 64)
	return n, err == nil && !math.IsNaN(n) && !math.IsInf(n, 0)
}

func (s *Service) publishMetrics(tx Transaction, g GroupRecord, events api.InputLogEvents) *awswire.Error {
	if len(events) == 0 {
		return nil
	}
	filters, err := tx.MetricFilters(MetricFilterQuery{Scope: g.Key.Scope, GroupID: g.ID, Limit: maxMetricFilters})
	if err != nil {
		return wireError(err)
	}
	if len(filters) == 0 {
		return nil
	}
	if s.metrics == nil {
		return unsupported("No CloudWatch metric publisher is configured.")
	}
	for _, filter := range filters {
		if filter.ApplyOnTransformedLogs {
			// TODO: Comeback: transformer commands must produce transformed events for
			// this configured selector; never substitute original content for them.
			continue
		}
		selection, err := filterpattern.CompileSelection(filter.FieldSelection)
		if err != nil {
			return storageFailure()
		}
		if !selection.Match(g.Key.AccountID, g.Key.Region) {
			continue
		}
		pattern, err := filterpattern.Compile(filter.Pattern)
		if err != nil {
			return storageFailure()
		}
		var extractor *filterpattern.Extractor
		constant := float64(0)
		if strings.HasPrefix(filter.MetricValue, "$") {
			extractor, err = pattern.Extractor(filter.MetricValue)
			if err != nil {
				return storageFailure()
			}
		} else {
			constant, _ = metricNumber(filter.MetricValue)
		}
		dimensions := make(map[string]metricDimension, len(filter.Dimensions)+len(filter.EmitSystemFieldDimensions))
		for name, source := range filter.Dimensions {
			field, err := pattern.Extractor(source)
			if err != nil {
				return storageFailure()
			}
			dimensions[name] = metricDimension{name: name, extractor: field}
		}
		for _, name := range filter.EmitSystemFieldDimensions {
			dimension := metricDimension{name: name}
			switch name {
			case "@aws.account":
				dimension.literal = g.Key.AccountID
			case "@aws.region":
				dimension.literal = g.Key.Region
			case "@source.log":
				dimension.literal = g.Key.Name
			}
			dimensions[name] = dimension
		}
		template := metricsapi.MetricDatum{MetricName: new(metricsapi.MetricName(filter.MetricName))}
		if filter.Unit != "" {
			template.Unit = new(metricsapi.StandardUnit(filter.Unit))
		}
		samples := make([]metricsapi.MetricDatum, 0, len(events))
		for _, event := range events {
			result, matched := pattern.Evaluate(string(*event.Message))
			number := constant
			if !matched {
				if filter.DefaultValue == nil {
					continue
				}
				// Native publishes the default per nonmatching event, not per minute.
				number = *filter.DefaultValue
			} else if extractor != nil {
				text, ok := extractor.Value(result)
				if !ok {
					continue
				}
				number, ok = metricNumber(text)
				if !ok {
					continue
				}
			}
			extracted := make(metricsapi.Dimensions, 0, len(dimensions))
			complete := true
			for _, dimension := range dimensions {
				text := dimension.literal
				if dimension.extractor != nil {
					var ok bool
					text, ok = dimension.extractor.Value(result)
					if !ok || text == "" {
						complete = false
						break
					}
				}
				extracted = append(extracted, metricsapi.Dimension{Name: new(metricsapi.DimensionName(dimension.name)), Value: new(metricsapi.DimensionValue(text))})
			}
			if !complete {
				continue
			}
			sample := template
			sample.Timestamp = new(time.UnixMilli(int64(*event.Timestamp)).UTC())
			sample.Value = new(metricsapi.DatapointValue(number))
			sample.Dimensions = extracted
			samples = append(samples, sample)
		}
		if len(samples) > 0 {
			if err := s.metrics.Publish(tx.Context(), filter.MetricNamespace, samples); err != nil {
				return wireError(err)
			}
		}
	}
	return nil
}
