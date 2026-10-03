package cloudwatch

import (
	"math"
	"sort"
)

type distributionBin struct{ low, high, count float64 }

const (
	zeroHistogramBin = -1 << 31
	// Native tiny-value captures retain this bottom bin even when raw extrema
	// clipping reverses its endpoints.
	minimumHistogramIndex = -7000
)

func histogramIndex(value float64) int {
	if value == 0 {
		return zeroHistogramBin
	}
	return max(minimumHistogramIndex, int(math.Floor(math.Log(value)/math.Log(1.1))))
}

func (b *metricBucket) histogram() []distributionBin {
	bins := make([]distributionBin, 0, len(b.weights))
	for index, count := range b.weights {
		if count <= 0 {
			continue
		}
		if index == zeroHistogramBin {
			bins = append(bins, distributionBin{0, 0, count})
			continue
		}
		low, high := math.Max(b.min, math.Pow(1.1, float64(index))), math.Min(b.max, math.Pow(1.1, float64(index+1)))
		bins = append(bins, distributionBin{low, high, count})
	}
	sort.Slice(bins, func(i, j int) bool { return bins[i].low < bins[j].low })
	return bins
}

// fixedTrimEdges selects retained endpoints by their full logarithmic indices,
// not their extrema-clipped coordinates. Empty positive bins affect fixed trims
// without contributing any percentile mass. An explicit zero lower bound skips
// zero-valued mass; an omitted lower bound includes it.
func (b *metricBucket) fixedTrimEdges(low, high float64) (empty, outside bool) {
	minimum, maximum, firstPositive := math.MaxInt, math.MinInt, math.MaxInt
	hasEmpty := false
	for index, count := range b.weights {
		if index == zeroHistogramBin && count == 0 {
			continue
		}
		minimum, maximum = min(minimum, index), max(maximum, index)
		if index != zeroHistogramBin {
			firstPositive = min(firstPositive, index)
			hasEmpty = hasEmpty || count == 0
		}
	}
	if !hasEmpty {
		return false, false
	}
	lower, upper := math.Inf(-1), math.Inf(1)
	if low == 0 {
		lower = float64(firstPositive)
	} else if !math.IsInf(low, -1) {
		lower = float64(histogramIndex(low))
	}
	if !math.IsInf(high, 1) {
		upper = float64(histogramIndex(high))
	}
	first, last := maximum, minimum
	for index, count := range b.weights {
		if index == zeroHistogramBin && count == 0 {
			continue
		}
		if float64(index) >= lower {
			first = min(first, index)
		}
		if float64(index) <= upper {
			last = max(last, index)
		}
	}
	if first > last {
		return false, false
	}
	lowerEmpty, upperEmpty := b.weights[first] == 0, b.weights[last] == 0
	return lowerEmpty || upperEmpty, lowerEmpty && lower < float64(first) || upperEmpty && upper > float64(last)
}

func (b *metricBucket) positiveBinBelow(threshold float64, populatedOnly bool) bool {
	for index, count := range b.weights {
		if index == zeroHistogramBin || populatedOnly && count == 0 {
			continue
		}
		low, high := math.Max(b.min, math.Pow(1.1, float64(index))), math.Min(b.max, math.Pow(1.1, float64(index+1)))
		if low < threshold || low == high && low == threshold {
			return true
		}
	}
	return false
}

// fixedWinsorTails excludes partial mass in the single selected positive bin.
// Earlier zero-valued mass joins the lower tail only when a populated positive
// bin also precedes the selected bin.
func fixedWinsorTails(bins []distributionBin, selectedLow float64) (lower, upper float64) {
	positiveBelow := false
	for _, bin := range bins {
		if bin.low < selectedLow {
			lower += bin.count
			positiveBelow = positiveBelow || bin.high > 0
		} else if bin.low > selectedLow {
			upper += bin.count
		}
	}
	if !positiveBelow {
		lower = 0
	}
	return lower, upper
}
