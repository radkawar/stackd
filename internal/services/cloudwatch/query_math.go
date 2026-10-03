package cloudwatch

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"stackd/internal/awswire"
)

type mathSeries struct {
	values   map[int64]float64
	period   int64
	label    string
	metric   bool
	identity *queryMetric
	group    []insightsGroupValue
	window   *metricQueryBounds
	partial  bool
	omitted  bool
}

// Combined expressions retain the union of fetched input windows and report
// incomplete retrieval even when the points they did receive can be evaluated.
func (s *mathSeries) includeSource(other *mathSeries) {
	s.partial = s.partial || other.partial
	if other.window == nil {
		return
	}
	if s.window == nil {
		s.window = other.window
		return
	}
	if s.window.start != other.window.start || s.window.end != other.window.end {
		s.window = &metricQueryBounds{start: min(s.window.start, other.window.start), end: max(s.window.end, other.window.end), available: s.window.available || other.window.available}
	}
}

type mathValue struct {
	scalar *float64
	series []*mathSeries
	array  bool
	text   string
}

type mathNode struct {
	kind, text string
	number     float64
	args       []*mathNode
	search     *metricSearch
}
type mathParser struct {
	input       string
	at          int
	token, kind string
	err         *awswire.Error
}

func mathValidation(message string) *awswire.Error { return failure("ValidationError", message) }
func (p *mathParser) next() {
	for p.at < len(p.input) && unicode.IsSpace(rune(p.input[p.at])) {
		p.at++
	}
	if p.at == len(p.input) {
		p.token, p.kind = "", "end"
		return
	}
	start := p.at
	c := p.input[p.at]
	p.at++
	switch {
	case c == '\'' || c == '"':
		var text strings.Builder
		for p.at < len(p.input) {
			v := p.input[p.at]
			p.at++
			if v == c {
				p.token, p.kind = text.String(), "string"
				return
			}
			if v == '\\' && p.at < len(p.input) && p.input[p.at] == c {
				v = p.input[p.at]
				p.at++
			}
			text.WriteByte(v)
		}
		p.err = mathValidation("Unterminated string in metric expression.")
		p.kind = "end"
	case c >= '0' && c <= '9' || c == '.':
		for p.at < len(p.input) {
			v := p.input[p.at]
			if v >= '0' && v <= '9' || v == '.' {
				p.at++
				continue
			}
			if v == 'e' || v == 'E' {
				p.at++
				if p.at < len(p.input) && (p.input[p.at] == '+' || p.input[p.at] == '-') {
					p.at++
				}
				continue
			}
			break
		}
		p.token, p.kind = p.input[start:p.at], "number"
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_':
		for p.at < len(p.input) {
			v := p.input[p.at]
			if !(v >= 'a' && v <= 'z' || v >= 'A' && v <= 'Z' || v >= '0' && v <= '9' || v == '_') {
				break
			}
			p.at++
		}
		p.token, p.kind = p.input[start:p.at], "name"
	default:
		if p.at < len(p.input) {
			pair := p.input[start : p.at+1]
			switch pair {
			case "==", "!=", "<=", ">=", "&&", "||":
				p.at++
			}
		}
		p.token, p.kind = p.input[start:p.at], "operator"
	}
}

func mathPrecedence(operator string) int {
	switch operator {
	case "OR", "||":
		return 1
	case "AND", "&&":
		return 2
	case "==", "!=", "<", ">", "<=", ">=":
		return 3
	case "+", "-":
		return 4
	case "*", "/":
		return 5
	case "^":
		return 6
	}
	return 0
}

func parseMath(input string) (*mathNode, *awswire.Error) {
	p := mathParser{input: input}
	p.next()
	node := p.expression(1)
	if p.err != nil {
		return nil, p.err
	}
	if p.kind != "end" {
		return nil, mathValidation("Unexpected token in metric expression: " + p.token)
	}
	return node, nil
}

func (p *mathParser) expression(minimum int) *mathNode {
	if p.err != nil {
		return nil
	}
	var left *mathNode
	switch {
	case p.token == "-" || p.token == "+":
		operator := p.token
		p.next()
		left = &mathNode{kind: "unary", text: operator, args: []*mathNode{p.expression(6)}}
	case p.token == "(":
		p.next()
		left = p.expression(1)
		p.expect(")")
	case p.token == "[":
		p.next()
		left = &mathNode{kind: "array", args: p.arguments("]")}
	case p.kind == "number":
		v, err := strconv.ParseFloat(p.token, 64)
		if err != nil || math.IsInf(v, 0) {
			p.err = mathValidation("Invalid number in metric expression.")
		}
		left = &mathNode{kind: "number", number: v}
		p.next()
	case p.kind == "string":
		left = &mathNode{kind: "string", text: p.token}
		p.next()
	case p.kind == "name":
		name := p.token
		p.next()
		left = &mathNode{kind: "name", text: name}
		if p.token == "(" {
			p.next()
			left.kind = "call"
			left.args = p.arguments(")")
		}
	default:
		p.err = mathValidation("Expected a value in metric expression.")
		return nil
	}
	for p.err == nil {
		precedence := mathPrecedence(p.token)
		if precedence < minimum {
			break
		}
		operator := p.token
		p.next()
		next := precedence + 1
		if operator == "^" {
			next = precedence
		}
		left = &mathNode{kind: "binary", text: operator, args: []*mathNode{left, p.expression(next)}}
	}
	return left
}

func (p *mathParser) expect(token string) {
	if p.err != nil {
		return
	}
	if p.token != token {
		p.err = mathValidation("Expected " + token + " in metric expression.")
		return
	}
	p.next()
}
func (p *mathParser) arguments(close string) []*mathNode {
	args := []*mathNode{}
	if p.token == close {
		p.next()
		return args
	}
	for p.err == nil {
		args = append(args, p.expression(1))
		if p.token != "," {
			break
		}
		p.next()
	}
	p.expect(close)
	return args
}

type mathEnvironment struct {
	resolve            func(string) (mathValue, *awswire.Error)
	metrics            func(string) (mathValue, *awswire.Error)
	search             func(*mathNode) (mathValue, *awswire.Error)
	start, end, period int64
}

func (e *mathEnvironment) evaluate(node *mathNode) (mathValue, *awswire.Error) {
	switch node.kind {
	case "number":
		return mathValue{scalar: new(node.number)}, nil
	case "string":
		return mathValue{text: node.text}, nil
	case "name":
		switch node.text {
		case "REPEAT", "LINEAR", "ASC", "DESC", "AVG", "MIN", "MAX", "SUM":
			return mathValue{text: node.text}, nil
		}
		return e.resolve(node.text)
	case "array":
		out := mathValue{array: true, series: []*mathSeries{}}
		for _, child := range node.args {
			v, w := e.evaluate(child)
			if w != nil {
				return out, w
			}
			if v.scalar != nil || v.series == nil {
				return out, mathValidation("Metric arrays must contain time series.")
			}
			out.series = append(out.series, v.series...)
		}
		return out, nil
	case "unary":
		v, w := e.evaluate(node.args[0])
		if w != nil {
			return v, w
		}
		if node.text == "+" {
			return v, nil
		}
		return mathUnary(v, func(n float64) float64 { return -n })
	case "binary":
		a, w := e.evaluate(node.args[0])
		if w != nil {
			return a, w
		}
		b, w := e.evaluate(node.args[1])
		if w != nil {
			return b, w
		}
		return mathBinary(node.text, a, b)
	case "call":
		return e.call(node)
	}
	return mathValue{}, mathValidation("Invalid metric expression.")
}

func mathUnary(v mathValue, fn func(float64) float64) (mathValue, *awswire.Error) {
	if v.scalar != nil {
		return mathValue{scalar: new(fn(*v.scalar))}, nil
	}
	if v.series == nil {
		return mathValue{}, mathValidation("Expected a number or time series.")
	}
	out := mathValue{array: v.array, series: make([]*mathSeries, 0, len(v.series))}
	for _, series := range v.series {
		copy := *series
		copy.metric = false
		copy.values = make(map[int64]float64, len(series.values))
		result := &copy
		for at, value := range series.values {
			n := fn(value)
			if !math.IsNaN(n) && !math.IsInf(n, 0) {
				result.values[at] = n
			}
		}
		out.series = append(out.series, result)
	}
	return out, nil
}

func mathBinary(operator string, a, b mathValue) (mathValue, *awswire.Error) {
	fn := func(x, y float64) float64 {
		truth := false
		switch operator {
		case "+":
			return x + y
		case "-":
			return x - y
		case "*":
			return x * y
		case "/":
			return x / y
		case "^":
			return math.Pow(x, y)
		case "==":
			truth = x == y
		case "!=":
			truth = x != y
		case "<":
			truth = x < y
		case ">":
			truth = x > y
		case "<=":
			truth = x <= y
		case ">=":
			truth = x >= y
		case "AND", "&&":
			truth = x != 0 && y != 0
		case "OR", "||":
			truth = x != 0 || y != 0
		}
		if truth {
			return 1
		}
		return 0
	}
	if a.scalar != nil && b.scalar != nil {
		return mathValue{scalar: new(fn(*a.scalar, *b.scalar))}, nil
	}
	if a.scalar != nil {
		return mathUnary(b, func(y float64) float64 { return fn(*a.scalar, y) })
	}
	if b.scalar != nil {
		return mathUnary(a, func(x float64) float64 { return fn(x, *b.scalar) })
	}
	if a.series == nil || b.series == nil {
		return mathValue{}, mathValidation("Arithmetic requires numbers or time series.")
	}
	if a.array && b.array {
		return mathValue{}, mathValidation("Arithmetic between two arrays of time series is not supported.")
	}
	count := max(len(a.series), len(b.series))
	out := mathValue{array: a.array || b.array, series: make([]*mathSeries, 0, count)}
	if len(a.series) == 0 || len(b.series) == 0 {
		return out, nil
	}
	for i := range count {
		x, y := a.series[min(i, len(a.series)-1)], b.series[min(i, len(b.series)-1)]
		series := &mathSeries{period: min(x.period, y.period), values: make(map[int64]float64), label: x.label}
		series.includeSource(x)
		series.includeSource(y)
		for at, v := range x.values {
			n := fn(v, y.values[at])
			if !math.IsNaN(n) && !math.IsInf(n, 0) {
				series.values[at] = n
			}
		}
		for at, v := range y.values {
			if _, ok := x.values[at]; ok {
				continue
			}
			n := fn(0, v)
			if !math.IsNaN(n) && !math.IsInf(n, 0) {
				series.values[at] = n
			}
		}
		out.series = append(out.series, series)
	}
	return out, nil
}

func seriesTimes(series *mathSeries) []int64 {
	times := make([]int64, 0, len(series.values))
	for at := range series.values {
		times = append(times, at)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	return times
}

func mathReduce(name string, values []float64, denominator int) float64 {
	if name == "DATAPOINT_COUNT" {
		return float64(len(values))
	}
	if len(values) == 0 {
		return math.NaN()
	}
	sum, minValue, maxValue := float64(0), values[0], values[0]
	for _, v := range values {
		sum += v
		minValue = math.Min(minValue, v)
		maxValue = math.Max(maxValue, v)
	}
	switch name {
	case "SUM":
		return sum
	case "MIN":
		return minValue
	case "MAX":
		return maxValue
	case "AVG":
		return sum / float64(denominator)
	case "STDDEV":
		mean := sum / float64(denominator)
		variance := float64(denominator-len(values)) * mean * mean
		for _, v := range values {
			variance += (v - mean) * (v - mean)
		}
		return math.Sqrt(variance / float64(denominator))
	}
	return math.NaN()
}

func (e *mathEnvironment) call(node *mathNode) (mathValue, *awswire.Error) {
	name := node.text
	switch name {
	case "SEARCH":
		return e.search(node)
	case "ANOMALY_DETECTION_BAND", "DB_PERF_INSIGHTS", "INSIGHT_RULE_METRIC", "LAMBDA", "SERVICE_QUOTA":
		// TODO: Comeback: anomaly models and external-service metric math require
		// their actual owning integrations rather than synthetic series.
		return mathValue{}, unsupported("Metric math function " + name + " requires an unimplemented query or service integration.")
	case "METRICS", "ABS", "CEIL", "FLOOR", "LOG", "LOG10", "SUM", "AVG", "MIN", "MAX", "STDDEV", "DATAPOINT_COUNT", "METRIC_COUNT", "PERIOD", "RUNNING_SUM", "DIFF", "DIFF_TIME", "RATE", "FILL", "IF", "TIME_SERIES", "MINUTE", "HOUR", "DAY", "DATE", "MONTH", "YEAR", "EPOCH", "FIRST", "LAST", "REMOVE_EMPTY", "SORT", "SLICE":
	default:
		return mathValue{}, mathValidation("Function '" + name + "' not found")
	}
	args := make([]mathValue, 0, len(node.args))
	for _, child := range node.args {
		value, w := e.evaluate(child)
		if w != nil {
			return value, w
		}
		args = append(args, value)
	}
	bad := func() (mathValue, *awswire.Error) {
		return mathValue{}, mathValidation("Invalid arguments for " + name + ".")
	}
	if name == "METRICS" {
		if len(args) > 1 || len(args) == 1 && (args[0].series != nil || args[0].scalar != nil) {
			return bad()
		}
		filter := ""
		if len(args) == 1 {
			filter = args[0].text
		}
		return e.metrics(filter)
	}
	if len(args) == 0 {
		return bad()
	}
	a := args[0]
	switch name {
	case "ABS", "CEIL", "FLOOR", "LOG", "LOG10":
		if len(args) != 1 || a.series == nil {
			return bad()
		}
		fn := math.Abs
		switch name {
		case "CEIL":
			fn = math.Ceil
		case "FLOOR":
			fn = math.Floor
		case "LOG":
			fn = math.Log
		case "LOG10":
			fn = math.Log10
		}
		return mathUnary(a, fn)
	case "SUM", "AVG", "MIN", "MAX", "STDDEV", "DATAPOINT_COUNT":
		if len(args) != 1 || a.series == nil {
			return bad()
		}
		if !a.array {
			if len(a.series) != 1 {
				return bad()
			}
			series := a.series[0]
			times := seriesTimes(series)
			values := make([]float64, 0, len(times))
			for _, at := range times {
				values = append(values, series.values[at])
			}
			denominator := len(values)
			if name == "AVG" || name == "STDDEV" {
				denominator = int((e.end - e.start) / series.period)
			}
			return mathValue{scalar: new(mathReduce(name, values, denominator))}, nil
		}
		series := &mathSeries{period: e.period, values: map[int64]float64{}}
		if len(a.series) > 0 {
			series.period = a.series[0].period
		}
		allTimes := make(map[int64]struct{})
		for _, s := range a.series {
			series.period = min(series.period, s.period)
			series.includeSource(s)
			for at := range s.values {
				allTimes[at] = struct{}{}
			}
		}
		values := make([]float64, 0, len(a.series))
		for at := range allTimes {
			values = values[:0]
			for _, s := range a.series {
				if v, ok := s.values[at]; ok {
					values = append(values, v)
				}
			}
			n := mathReduce(name, values, len(a.series))
			if !math.IsNaN(n) && !math.IsInf(n, 0) {
				series.values[at] = n
			}
		}
		return mathValue{series: []*mathSeries{series}}, nil
	case "METRIC_COUNT":
		if len(args) != 1 || !a.array {
			return bad()
		}
		return mathValue{scalar: new(float64(len(a.series)))}, nil
	case "PERIOD":
		if len(args) != 1 || a.array || len(a.series) != 1 || !a.series[0].metric {
			return bad()
		}
		return mathValue{scalar: new(float64(a.series[0].period))}, nil
	case "TIME_SERIES":
		if len(args) != 1 || a.scalar == nil {
			return bad()
		}
		s := &mathSeries{period: e.period, values: map[int64]float64{}}
		if !math.IsNaN(*a.scalar) && !math.IsInf(*a.scalar, 0) {
			for at := e.start; at < e.end; at += e.period {
				s.values[at] = *a.scalar
			}
		}
		return mathValue{series: []*mathSeries{s}}, nil
	case "FIRST", "LAST":
		if len(args) != 1 || !a.array {
			return bad()
		}
		if len(a.series) == 0 {
			return mathValue{series: []*mathSeries{{period: e.period, values: map[int64]float64{}}}}, nil
		}
		index := 0
		if name == "LAST" {
			index = len(a.series) - 1
		}
		return mathValue{series: []*mathSeries{a.series[index]}}, nil
	case "REMOVE_EMPTY":
		if len(args) != 1 || !a.array {
			return bad()
		}
		out := mathValue{array: true, series: []*mathSeries{}}
		for _, s := range a.series {
			if len(s.values) > 0 {
				out.series = append(out.series, s)
			}
		}
		return out, nil
	case "SLICE":
		if !a.array || len(args) < 2 || len(args) > 3 || args[1].scalar == nil {
			return bad()
		}
		start := *args[1].scalar
		end := float64(len(a.series))
		if len(args) == 3 {
			if args[2].scalar == nil {
				return bad()
			}
			end = *args[2].scalar
		}
		if start < 0 || end < start || math.Trunc(start) != start || math.Trunc(end) != end {
			return bad()
		}
		return mathValue{array: true, series: a.series[min(int(start), len(a.series)):min(int(end), len(a.series))]}, nil
	case "SORT":
		if !a.array || len(args) < 3 || len(args) > 4 {
			return bad()
		}
		stat, order := args[1].text, args[2].text
		if stat != "SUM" && stat != "MIN" && stat != "MAX" && stat != "AVG" || order != "ASC" && order != "DESC" {
			return bad()
		}
		type ranked struct {
			s     *mathSeries
			value float64
		}
		rankedSeries := make([]ranked, 0, len(a.series))
		for _, s := range a.series {
			values := make([]float64, 0, len(s.values))
			for _, at := range seriesTimes(s) {
				values = append(values, s.values[at])
			}
			rankedSeries = append(rankedSeries, ranked{s, mathReduce(stat, values, len(values))})
		}
		sort.SliceStable(rankedSeries, func(i, j int) bool {
			if order == "ASC" {
				return rankedSeries[i].value < rankedSeries[j].value
			}
			return rankedSeries[i].value > rankedSeries[j].value
		})
		limit := len(rankedSeries)
		if len(args) == 4 {
			if args[3].scalar == nil || *args[3].scalar < 1 || math.Trunc(*args[3].scalar) != *args[3].scalar {
				return bad()
			}
			limit = min(limit, int(*args[3].scalar))
		}
		out := mathValue{array: true, series: make([]*mathSeries, 0, limit)}
		for _, rank := range rankedSeries[:limit] {
			out.series = append(out.series, rank.s)
		}
		return out, nil
	case "IF":
		return e.conditional(args)
	case "FILL":
		return e.fill(args)
	}
	if len(args) != 1 || a.series == nil {
		return bad()
	}
	out := mathValue{array: a.array, series: make([]*mathSeries, 0, len(a.series))}
	for _, s := range a.series {
		copy := *s
		copy.metric = false
		copy.values = make(map[int64]float64)
		result := &copy
		switch name {
		case "RUNNING_SUM", "DIFF", "DIFF_TIME", "RATE":
			times := seriesTimes(s)
			running := float64(0)
			for i, at := range times {
				v := s.values[at]
				running += v
				if name == "RUNNING_SUM" {
					result.values[at] = running
					continue
				}
				if i == 0 {
					continue
				}
				elapsed := float64(at - times[i-1])
				difference := v - s.values[times[i-1]]
				switch name {
				case "DIFF":
					result.values[at] = difference
				case "DIFF_TIME":
					result.values[at] = elapsed
				case "RATE":
					result.values[at] = difference / elapsed
				}
			}
		default:
			start, end := e.seriesWindow(s)
			for at := start; at < end; at += s.period {
				t := time.Unix(at, 0).UTC()
				v := 0
				switch name {
				case "MINUTE":
					v = t.Minute()
				case "HOUR":
					v = t.Hour()
				case "DAY":
					v = (int(t.Weekday())+6)%7 + 1
				case "DATE":
					v = t.Day()
				case "MONTH":
					v = int(t.Month())
				case "YEAR":
					v = t.Year()
				case "EPOCH":
					result.values[at] = float64(at)
					continue
				}
				result.values[at] = float64(v)
			}
		}
		out.series = append(out.series, result)
	}
	return out, nil
}

func (e *mathEnvironment) conditional(args []mathValue) (mathValue, *awswire.Error) {
	bad := func() (mathValue, *awswire.Error) { return mathValue{}, mathValidation("Invalid arguments for IF.") }
	if len(args) < 2 || len(args) > 3 {
		return bad()
	}
	for _, a := range args {
		if a.array || a.scalar == nil && len(a.series) != 1 {
			return bad()
		}
	}
	condition := args[0]
	if condition.scalar != nil {
		index := 1
		if *condition.scalar == 0 {
			index = 2
		}
		if index >= len(args) {
			return mathValue{series: []*mathSeries{{period: e.period, values: map[int64]float64{}}}}, nil
		}
		if args[index].scalar != nil {
			return bad()
		}
		return args[index], nil
	}
	s := condition.series[0]
	out := &mathSeries{period: s.period, values: map[int64]float64{}}
	out.includeSource(s)
	for _, branch := range args[1:] {
		if len(branch.series) == 1 {
			out.partial = out.partial || branch.series[0].partial
		}
	}
	for at, v := range s.values {
		index := 1
		if v == 0 {
			index = 2
		}
		if index >= len(args) {
			continue
		}
		branch := args[index]
		if branch.scalar != nil {
			out.values[at] = *branch.scalar
			continue
		}
		n, ok := branch.series[0].values[at]
		if !ok && index == 2 && args[1].scalar != nil {
			continue
		}
		out.values[at] = n
	}
	return mathValue{series: []*mathSeries{out}}, nil
}

func (e *mathEnvironment) fill(args []mathValue) (mathValue, *awswire.Error) {
	if len(args) != 2 || args[0].series == nil || args[1].array {
		return mathValue{}, mathValidation("Invalid arguments for FILL.")
	}
	filler := args[1]
	if filler.scalar == nil && len(filler.series) != 1 && filler.text != "REPEAT" && filler.text != "LINEAR" {
		return mathValue{}, mathValidation("Invalid fill value.")
	}
	out := mathValue{array: args[0].array, series: make([]*mathSeries, 0, len(args[0].series))}
	for _, s := range args[0].series {
		copy := *s
		copy.metric = false
		copy.values = make(map[int64]float64)
		result := &copy
		if len(filler.series) == 1 {
			result.partial = result.partial || filler.series[0].partial
		}
		times := seriesTimes(s)
		index := 0
		start, end := e.seriesWindow(s)
		for at := start; at < end; at += s.period {
			for index < len(times) && times[index] < at {
				index++
			}
			if v, ok := s.values[at]; ok {
				result.values[at] = v
				continue
			}
			switch {
			case filler.scalar != nil:
				result.values[at] = *filler.scalar
			case len(filler.series) == 1:
				if v, ok := filler.series[0].values[at]; ok {
					result.values[at] = v
				}
			case filler.text == "REPEAT" && index > 0:
				result.values[at] = s.values[times[index-1]]
			case filler.text == "LINEAR" && index > 0 && index < len(times):
				left, right := times[index-1], times[index]
				result.values[at] = s.values[left] + (s.values[right]-s.values[left])*float64(at-left)/float64(right-left)
			}
		}
		out.series = append(out.series, result)
	}
	return out, nil
}

func expressionError(id string, w *awswire.Error) *awswire.Error {
	if w == nil {
		return nil
	}
	if w.Code == "ValidationError" {
		return mathValidation(fmt.Sprintf("Error in expression '%s': %s", id, w.Message))
	}
	return w
}

func (e *mathEnvironment) seriesWindow(series *mathSeries) (int64, int64) {
	if series.window != nil {
		return series.window.start, series.window.end
	}
	return floorTime(e.start, series.period), e.end
}
