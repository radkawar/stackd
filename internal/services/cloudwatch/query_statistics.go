package cloudwatch

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

type statisticSpec struct {
	name, kind string
	low, high  float64
	percent    bool
}

type metricBucket struct {
	at                      int64
	unit                    string
	count, sum, min, max    float64
	initialized, incomplete bool
	weights                 map[int]float64
}

func (b *metricBucket) addSummary(count, sum, minimum, maximum float64) {
	if !b.initialized {
		b.min, b.max, b.initialized = minimum, maximum, true
	} else {
		b.min = math.Min(b.min, minimum)
		b.max = math.Max(b.max, maximum)
	}
	b.count += count
	b.sum += sum
}

func validPeriod(period int64) bool {
	return period == 1 || period == 5 || period == 10 || period == 20 || period == 30 || period >= 60 && period%60 == 0
}

func floorTime(at, period int64) int64 {
	remainder := at % period
	if remainder < 0 {
		remainder += period
	}
	return at - remainder
}

func metricWindow(start, end, now time.Time, period int64) (int64, int64, bool) {
	age := now.Sub(start)
	rounding := int64(60)
	available := true
	switch {
	case age > 63*24*time.Hour:
		rounding = 3600
		available = period%3600 == 0
	case age > 15*24*time.Hour:
		rounding = 300
		available = period%300 == 0
	case age > 3*time.Hour:
		available = period%60 == 0
	case period < 60:
		rounding = period
	}
	return floorTime(start.Unix(), rounding), floorTime(end.Unix(), period), available
}

func parseStatistic(name string) (statisticSpec, bool) {
	spec := statisticSpec{name: name, kind: name}
	switch name {
	case "SampleCount", "Sum", "Average", "Minimum", "Maximum":
		return spec, true
	case "IQM":
		spec.kind, spec.low, spec.high, spec.percent = "TM", 25, 75, true
		return spec, true
	}
	number := func(text string) (float64, bool) {
		if text == "" {
			return 0, false
		}
		if dot := strings.IndexByte(text, '.'); dot >= 0 && len(text)-dot-1 > 10 {
			return 0, false
		}
		for _, c := range text {
			if c != '.' && c != '-' && (c < '0' || c > '9') {
				return 0, false
			}
		}
		v, err := strconv.ParseFloat(text, 64)
		return v, err == nil && v >= 0
	}
	if strings.HasPrefix(name, "p") {
		n, ok := number(name[1:])
		spec.kind, spec.high = "p", n
		return spec, ok && n <= 100
	}
	for _, kind := range []string{"TM", "TC", "TS", "WM", "PR"} {
		if kind != "PR" && strings.HasPrefix(name, strings.ToLower(kind)) {
			n, ok := number(name[2:])
			spec.kind, spec.high, spec.percent = kind, n, true
			return spec, ok && n > 0 && n <= 100
		}
		if !strings.HasPrefix(name, kind+"(") || !strings.HasSuffix(name, ")") {
			continue
		}
		halves := strings.Split(name[3:len(name)-1], ":")
		if len(halves) != 2 || halves[0] == "" && halves[1] == "" {
			return spec, false
		}
		spec.kind = kind
		spec.percent = strings.HasSuffix(halves[0], "%") || strings.HasSuffix(halves[1], "%")
		if kind == "PR" && spec.percent {
			return spec, false
		}
		spec.low, spec.high = math.Inf(-1), math.Inf(1)
		if spec.percent {
			spec.low, spec.high = 0, 100
		}
		for i, text := range halves {
			if text == "" {
				continue
			}
			if strings.HasSuffix(text, "%") != spec.percent {
				return spec, false
			}
			n, ok := number(strings.TrimSuffix(text, "%"))
			if !ok || spec.percent && n > 100 {
				return spec, false
			}
			if i == 0 {
				spec.low = n
			} else {
				spec.high = n
			}
		}
		return spec, spec.low <= spec.high
	}
	return spec, false
}

func basicStatistic(name string) bool {
	switch name {
	case "SampleCount", "Sum", "Average", "Minimum", "Maximum":
		return true
	}
	return false
}

func (s *Service) metricBuckets(r Reader, key MetricKey, start, end time.Time, period int64, unit string, distribution bool) ([]*metricBucket, *awswire.Error) {
	from, to, available := metricWindow(start, end, s.clock.Now(), period)
	if !available {
		return nil, nil
	}
	return s.readMetricBuckets(r, key, from, to, period, unit, distribution)
}

func (s *Service) readMetricBuckets(r Reader, key MetricKey, from, to, period int64, unit string, distribution bool) ([]*metricBucket, *awswire.Error) {
	record, err := r.Metric(key)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, wireError(err)
	}
	return s.readMetricPointBuckets(r, record.ID, from, to, period, unit, distribution)
}

func (s *Service) readMetricPointBuckets(r Reader, metricID string, from, to, period int64, unit string, distribution bool) ([]*metricBucket, *awswire.Error) {
	from = max(from, s.clock.Now().Add(-455*24*time.Hour).Unix())
	if to <= from {
		return nil, nil
	}
	type bucketKey struct {
		at   int64
		unit string
	}
	buckets := make(map[bucketKey]*metricBucket)
	err := r.Points(PointQuery{MetricID: metricID, Start: from, End: to}, func(p Point) error {
		if unit != "" && p.Unit != unit {
			return nil
		}
		at := from + (p.Timestamp-from)/period*period
		k := bucketKey{at, p.Unit}
		b := buckets[k]
		if b == nil {
			b = &metricBucket{at: at, unit: p.Unit}
			buckets[k] = b
		}
		b.addSummary(p.SampleCount, p.Sum, p.Minimum, p.Maximum)
		if distribution {
			raw, v := p.Raw, p.Minimum
			// Native admission retains inconsistent statistic sets. A single sample
			// whose Sum lies in its supplied extrema still contributes a distribution.
			if p.SampleCount == 1 && p.Sum >= p.Minimum && p.Sum <= p.Maximum {
				raw, v = true, p.Sum
			}
			if !raw && p.Minimum == p.Maximum && p.Sum == p.Minimum*p.SampleCount {
				raw = true
			}
			if raw && v >= 0 {
				if b.weights == nil {
					b.weights = make(map[int]float64)
				}
				b.weights[histogramIndex(v)] += p.SampleCount
			} else if !raw {
				b.incomplete = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	out := make([]*metricBucket, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].at == out[j].at {
			return out[i].unit < out[j].unit
		}
		return out[i].at < out[j].at
	})
	return out, nil
}

func (s *Service) getMetricStatistics(r Transaction, in *api.GetMetricStatisticsInput) (*api.GetMetricStatisticsOutput, *awswire.Error) {
	if w := s.authorize(r, "GetMetricStatistics", value(in.Namespace)); w != nil {
		return nil, w
	}
	if in.StartTime == nil || in.EndTime == nil || in.Period == nil {
		return nil, failure("MissingParameter", "StartTime, EndTime and Period are required.")
	}
	if !in.StartTime.Before(*in.EndTime) {
		return nil, invalid("The parameter StartTime must be less than the parameter EndTime.")
	}
	period := int64(*in.Period)
	if !validPeriod(period) {
		return nil, invalid("The parameter Period must be a value in the set [1, 5, 10, 20, 30] or a multiple of 60.")
	}
	start, end, _ := metricWindow(*in.StartTime, *in.EndTime, s.clock.Now(), period)
	count := (end - start + period - 1) / period
	if count > 1440 {
		return nil, failure("InvalidParameterCombination", fmt.Sprintf("You have requested up to %d datapoints, which exceeds the limit of 1440. You may reduce the datapoints requested by increasing Period, or decreasing the time range.", count))
	}
	if len(in.Statistics)+len(in.ExtendedStatistics) == 0 {
		return nil, failure("InvalidParameterCombination", "You must specify Statistics or ExtendedStatistics.")
	}
	specs := make([]statisticSpec, 0, len(in.Statistics)+len(in.ExtendedStatistics))
	for i, name := range in.Statistics {
		if !basicStatistic(string(name)) {
			return nil, invalid(fmt.Sprintf("The parameter Statistics.member.%d.<list element> must be a value in the set [SampleCount, Average, Sum, Minimum, Maximum].", i+1))
		}
		specs = append(specs, statisticSpec{name: string(name), kind: string(name)})
	}
	for i, name := range in.ExtendedStatistics {
		spec, ok := parseStatistic(string(name))
		if !ok || basicStatistic(string(name)) {
			return nil, invalid(fmt.Sprintf("The value %s for parameter ExtendedStatistics.member.%d.<list element> is not supported.", name, i+1))
		}
		specs = append(specs, spec)
	}
	key, _, w := metricIdentity(scopeFor(r.Context()), value(in.Namespace), value(in.MetricName), in.Dimensions)
	if w != nil {
		return nil, w
	}
	buckets, w := s.metricBuckets(r, key, *in.StartTime, *in.EndTime, period, value(in.Unit), len(in.ExtendedStatistics) > 0)
	if w != nil {
		return nil, w
	}
	out := &api.GetMetricStatisticsOutput{Label: new(api.MetricLabel(value(in.MetricName))), Datapoints: api.Datapoints{}}
	for _, b := range buckets {
		point := api.Datapoint{Timestamp: new(time.Unix(b.at, 0).UTC()), Unit: new(api.StandardUnit(b.unit))}
		hasValue := false
		for _, spec := range specs {
			v, ok, w := b.statistic(spec)
			if w != nil {
				return nil, w
			}
			if !ok {
				continue
			}
			hasValue = true
			n := new(api.DatapointValue(v))
			switch spec.kind {
			case "SampleCount":
				point.SampleCount = n
			case "Sum":
				point.Sum = n
			case "Minimum":
				point.Minimum = n
			case "Maximum":
				point.Maximum = n
			case "Average":
				point.Average = n
			default:
				if point.ExtendedStatistics == nil {
					point.ExtendedStatistics = api.DatapointValueMap{}
				}
				point.ExtendedStatistics[api.ExtendedStatistic(spec.name)] = *n
			}
		}
		if hasValue {
			out.Datapoints = append(out.Datapoints, point)
		}
	}
	return out, nil
}

func (b *metricBucket) statistic(spec statisticSpec) (float64, bool, *awswire.Error) {
	switch spec.kind {
	case "SampleCount":
		return b.count, true, nil
	case "Sum":
		return b.sum, true, nil
	case "Minimum":
		return b.min, true, nil
	case "Maximum":
		return b.max, true, nil
	case "Average":
		return b.sum / b.count, true, nil
	case "p":
		if spec.high == 0 {
			return b.min, true, nil
		}
		if spec.high == 100 {
			return b.max, true, nil
		}
		if b.min < 0 {
			return 0, false, nil
		}
		if b.min == b.max {
			return b.min, true, nil
		}
	}
	if b.min < 0 && spec.percent {
		return 0, false, nil
	}
	if spec.percent && spec.low == spec.high {
		if len(b.weights) == 0 || b.count == 0 && b.min == b.max {
			return 0, false, nil
		}
		switch spec.kind {
		case "TC", "TS":
			return 0, true, nil
		case "WM":
			return 0 / b.count, true, nil
		default:
			return 0, false, nil
		}
	}
	if spec.kind == "p" || spec.percent {
		if b.incomplete || b.count < 1 {
			return 0, false, nil
		}
	}
	rawCount := float64(0)
	for _, count := range b.weights {
		rawCount += count
	}
	if !spec.percent && spec.low == spec.high {
		switch spec.kind {
		case "PR", "TC", "TS":
			return 0, true, nil
		case "WM":
			return spec.low * rawCount / b.count, true, nil
		default:
			return 0, false, nil
		}
	}
	if b.count == 0 && b.min != b.max && len(b.weights) > 0 && !spec.percent {
		switch spec.kind {
		case "PR", "TC":
			return 0, true, nil
		case "TS", "WM":
			return math.NaN(), true, nil
		}
	}
	if b.count <= 0 || rawCount == 0 {
		return 0, false, nil
	}
	bins := b.histogram()
	if spec.kind == "p" {
		target, prior := spec.high/100*b.count, float64(0)
		for _, bin := range bins {
			if target <= prior+bin.count {
				if bin.low == bin.high {
					return bin.low, true, nil
				}
				v := math.Exp(math.Log(bin.low) + math.Log(bin.high/bin.low)*(target-prior)/bin.count)
				return math.Max(b.min, math.Min(b.max, v)), true, nil
			}
			prior += bin.count
		}
		return 0, false, nil
	}
	rank := func(threshold float64) float64 {
		count := float64(0)
		for _, bin := range bins {
			if threshold >= bin.high {
				count += bin.count
			} else if threshold > bin.low {
				count += bin.count * (threshold - bin.low) / (bin.high - bin.low)
			}
		}
		return count
	}
	if spec.kind == "PR" {
		return (rank(spec.high) - rank(spec.low)) / b.count * 100, true, nil
	}
	type piece struct{ low, high, left, right, count float64 }
	pieces := make([]piece, 0, len(bins))
	prior := float64(0)
	low, high := spec.low/100*b.count, spec.high/100*b.count
	for _, bin := range bins {
		if spec.percent {
			left, right := math.Max(prior, low), math.Min(prior+bin.count, high)
			if right > left {
				pieces = append(pieces, piece{bin.low, bin.high, bin.low + (bin.high-bin.low)*(left-prior)/bin.count, bin.low + (bin.high-bin.low)*(right-prior)/bin.count, right - left})
			}
		} else if bin.low == bin.high {
			if bin.low > spec.low && bin.high <= spec.high {
				pieces = append(pieces, piece{bin.low, bin.high, bin.low, bin.high, bin.count})
			}
		} else {
			// The native bottom bin can have reversed extrema-clipped endpoints.
			// Fixed ranges select its span; percentage trims retain its direction.
			binLow, binHigh := bin.low, bin.high
			if binLow > binHigh {
				binLow, binHigh = binHigh, binLow
			}
			left, right := math.Max(binLow, spec.low), math.Min(binHigh, spec.high)
			if right > left {
				pieces = append(pieces, piece{bin.low, bin.high, left, right, bin.count * (right - left) / (binHigh - binLow)})
			}
		}
		prior += bin.count
	}
	firstPositive, lastPositive := -1, -1
	for i, p := range pieces {
		if p.high > 0 {
			if firstPositive < 0 {
				firstPositive = i
			}
			lastPositive = i
		}
	}
	count, total := float64(0), float64(0)
	for i, p := range pieces {
		midpoint := math.Sqrt(p.low) * math.Sqrt(p.high)
		if i == firstPositive || i == lastPositive {
			midpoint = (p.left + p.right) / 2
		}
		total += p.count * midpoint
		count += p.count
	}
	if spec.percent {
		count = high - low
	}
	if spec.kind == "TC" {
		return count, true, nil
	}
	singleFixedBin := false
	if !spec.percent {
		empty, outside := b.fixedTrimEdges(spec.low, spec.high)
		if outside || empty && firstPositive < 0 {
			total = math.NaN()
			if spec.kind == "WM" {
				return total, true, nil
			}
		} else if empty && firstPositive == lastPositive {
			p := pieces[firstPositive]
			total = p.count * (p.low + p.high) / 2
			singleFixedBin = true
		}
	}
	switch spec.kind {
	case "TS":
		return total, true, nil
	case "TM":
		if count > 0 {
			return total / count, true, nil
		}
		return 0, false, nil
	case "WM":
		if spec.percent {
			// Independent weighted, scaled and asymmetric native captures distinguish
			// this count-dependent tail replacement from percentile clamping.
			replacement := func(target float64, lower bool) float64 {
				prior := float64(0)
				for _, bin := range bins {
					if target <= prior+bin.count {
						fraction := (target - prior) / bin.count
						exponent := bin.count - 1 + fraction
						if lower {
							exponent = bin.count - fraction
							if fraction == 1 {
								exponent = 1
							}
						}
						boundary := bin.low * math.Pow(1.1, math.Max(0, math.Min(1, exponent)))
						return math.Max(b.min, math.Min(b.max, boundary))
					}
					prior += bin.count
				}
				return b.max
			}
			return (total + low*replacement(low, true) + (b.count-high)*replacement(high, false)) / b.count, true, nil
		}
		lower, upper := math.Max(b.min, math.Min(b.max, spec.low)), math.Max(b.min, math.Min(b.max, spec.high))
		if !b.positiveBinBelow(spec.high, false) {
			return lower, true, nil
		}
		lowerCount := float64(0)
		if b.positiveBinBelow(spec.low, true) {
			lowerCount = rank(spec.low)
		}
		upperCount := rawCount - rank(spec.high)
		if singleFixedBin {
			lowerCount, upperCount = fixedWinsorTails(bins, pieces[firstPositive].low)
		}
		return (total + lowerCount*lower + upperCount*upper) / b.count, true, nil
	}
	return 0, false, invalid("Unknown statistic.")
}
