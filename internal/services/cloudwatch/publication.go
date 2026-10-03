package cloudwatch

import (
	"errors"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

func (s *Service) putMetricData(tx Transaction, in *api.PutMetricDataInput) (*api.PutMetricDataOutput, *awswire.Error) {
	namespace := value(in.Namespace)
	if wire := s.authorize(tx, "PutMetricData", namespace); wire != nil {
		return nil, wire
	}
	if strings.HasPrefix(namespace, "AWS/") {
		return nil, invalid("The value AWS/ for parameter Namespace is invalid.")
	}
	if len(in.EntityMetricData) > 0 {
		// TODO: Comeback implement entity associations with the observability entity owner, rather than silently discarding accepted entity metadata.
		return nil, unsupported("Entity-associated metrics require the observability entity service.")
	}
	if len(in.MetricData) == 0 {
		return nil, failure("MissingParameter", "At least one MetricDatum object must be present in the request.")
	}
	if len(in.MetricData) > 1000 {
		return nil, invalid("A request may contain at most 1000 metrics.")
	}
	if err := s.publish(tx, namespace, in.MetricData, true); err != nil {
		return nil, wireError(err)
	}
	return &api.PutMetricDataOutput{}, nil
}

type metricPublication struct {
	key        MetricKey
	dimensions []Dimension
	points     []Point
}

func (s *Service) publish(tx Transaction, namespace string, data []api.MetricDatum, checkFreshness bool) error {
	now := s.clock.Now()
	scope := scopeFor(tx.Context())
	byKey := make(map[MetricKey]*metricPublication)
	var ordered []*metricPublication
	for _, datum := range data {
		key, dimensions, wire := metricIdentity(scope, namespace, value(datum.MetricName), datum.Dimensions)
		if wire != nil {
			return wire
		}
		points, wire := datumPoints(datum, now, checkFreshness)
		if wire != nil {
			return wire
		}
		publication := byKey[key]
		if publication == nil {
			publication = &metricPublication{key: key, dimensions: dimensions}
			byKey[key] = publication
			ordered = append(ordered, publication)
		}
		publication.points = append(publication.points, points...)
	}
	for _, publication := range ordered {
		metric, err := tx.Metric(publication.key)
		if errors.Is(err, ErrNotFound) {
			metric = MetricRecord{Key: publication.key, ID: uuid.NewString(), Dimensions: publication.dimensions, Created: now}
		} else if err != nil {
			return err
		}
		metric.PublishedAt = now
		if err := tx.PutMetric(metric); err != nil {
			return err
		}
		if err := tx.AppendPoints(metric.ID, publication.points); err != nil {
			return err
		}
	}
	return nil
}

func datumPoints(datum api.MetricDatum, now time.Time, checkFreshness bool) ([]Point, *awswire.Error) {
	if datum.Value != nil && (datum.Values != nil || datum.StatisticValues != nil) {
		return nil, failure("InvalidParameterCombination", "Value cannot be combined with Values or StatisticValues.")
	}
	if datum.Counts != nil && datum.Values == nil {
		return nil, failure("InvalidParameterCombination", "The parameter values must appears when the counts parameter is specified.")
	}
	if datum.Value == nil && len(datum.Values) == 0 && datum.StatisticValues == nil {
		return nil, failure("InvalidParameterCombination", "At least one of the parameters must be specified.")
	}
	if datum.Counts != nil && len(datum.Counts) != len(datum.Values) {
		return nil, invalid("Values and Counts must be of the same size.")
	}
	if len(datum.Values) > 150 {
		return nil, invalid("A Values array may contain at most 150 values.")
	}
	resolution := int32(60)
	if datum.StorageResolution != nil {
		resolution = int32(*datum.StorageResolution)
	}
	if resolution != 1 && resolution != 60 {
		return nil, invalid("StorageResolution must be a value in the set [ 1, 60 ].")
	}
	stamp := now
	if datum.Timestamp != nil {
		stamp = time.Time(*datum.Timestamp)
	}
	if checkFreshness && (stamp.Before(now.Add(-14*24*time.Hour)) || stamp.After(now.Add(2*time.Hour))) {
		return nil, invalid("Timestamp must be within the past two weeks and no more than two hours in the future.")
	}
	unit := value(datum.Unit)
	if unit == "" {
		unit = "None"
	}
	base := Point{Timestamp: stamp.Truncate(time.Duration(resolution) * time.Second).Unix(), Unit: unit, Resolution: resolution}
	for i, number := range datum.Values {
		if !metricNumber(float64(number)) {
			return nil, invalid("Values contains an invalid numeric value.")
		}
		if datum.Counts != nil {
			count := float64(datum.Counts[i])
			if math.IsNaN(count) || math.IsInf(count, 0) || count < 0 {
				return nil, invalid("Counts must contain finite nonnegative values.")
			}
		}
	}
	if set := datum.StatisticValues; set != nil {
		if set.SampleCount == nil || set.Sum == nil || set.Minimum == nil || set.Maximum == nil {
			return nil, failure("MissingParameter", "StatisticValues requires SampleCount, Sum, Minimum and Maximum.")
		}
		base.SampleCount, base.Sum, base.Minimum, base.Maximum = float64(*set.SampleCount), float64(*set.Sum), float64(*set.Minimum), float64(*set.Maximum)
		if math.IsNaN(base.SampleCount) || math.IsInf(base.SampleCount, 0) || base.SampleCount <= 0 {
			return nil, invalid("StatisticValues.SampleCount must be greater than 0.")
		}
		if !metricNumber(base.Sum) || !metricNumber(base.Minimum) || !metricNumber(base.Maximum) {
			return nil, invalid("StatisticValues contains an invalid numeric value.")
		}
		if base.Maximum < base.Minimum {
			return nil, invalid("StatisticValues.Maximum must be greater than or equal to Minimum.")
		}
		base.Raw = base.Minimum == base.Maximum && base.Sum == base.Minimum*base.SampleCount
		// AWS accepts inconsistent sums and gives StatisticValues precedence
		// over simultaneously supplied Values. Do not repair its statistics.
		return []Point{base}, nil
	}
	if datum.Value != nil {
		number := float64(*datum.Value)
		if !metricNumber(number) {
			return nil, invalid("Value is not a supported finite metric number.")
		}
		base.SampleCount, base.Sum, base.Minimum, base.Maximum, base.Raw = 1, number, number, number, true
		return []Point{base}, nil
	}
	points := make([]Point, len(datum.Values))
	for i, value := range datum.Values {
		number, count := float64(value), float64(1)
		if datum.Counts != nil {
			count = float64(datum.Counts[i])
		}
		point := base
		point.SampleCount, point.Sum, point.Minimum, point.Maximum, point.Raw = count, number*count, number, number, true
		points[i] = point
	}
	return points, nil
}

func metricNumber(number float64) bool {
	return !math.IsNaN(number) && !math.IsInf(number, 0) && math.Abs(number) <= 0x1p360
}
