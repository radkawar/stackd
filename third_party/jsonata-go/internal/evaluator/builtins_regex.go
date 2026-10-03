package evaluator

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	jsonregex "github.com/tiaanduplessis/jsonata-go/internal/regex"
	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

// regexBuiltinSpecs owns the string-matching functions that share the
// evaluator's ECMAScript regular-expression boundary.
var regexBuiltinSpecs = []builtinSpec{
	{name: "contains", signature: "<s-(sf):b>", implementation: builtinContainsRegex},
	{name: "match", signature: "<s-fn?:a<o>>", implementation: builtinMatchRegex},
	{name: "replace", signature: "<s-(sf)(sf)n?:s>", implementation: builtinReplaceRegex},
	{name: "split", signature: "<s-(sf)n?:a<s>>", implementation: builtinSplitRegex},
}

func regexFromValue(v any) (regexValue, bool) {
	pattern, ok := collapse(v).(regexValue)
	return pattern, ok
}

func regexStringArgument(v any) (string, bool) {
	v = collapse(v)
	if text, ok := v.(string); ok {
		return text, true
	}
	switch items := v.(type) {
	case []any:
		if len(items) == 1 {
			return regexStringArgument(items[0])
		}
	case value.Array:
		if len(items.Items) == 1 {
			return regexStringArgument(items.Items[0])
		}
	}
	return "", false
}

func invokeRegexMatcher(st state, matcher callableValue, args []any) (map[string]any, bool, error) {
	if err := regexCheck(st); err != nil {
		return nil, false, err
	}
	result, err := matcher.invoke(st, args)
	if err != nil {
		return nil, false, err
	}
	result = collapse(result)
	if value.IsUndefined(result) {
		return nil, false, nil
	}
	object, ok := result.(map[string]any)
	if !ok || !validRegexMatcherObject(object) {
		return nil, false, runtimeError{code: "T1010", msg: "matcher function returned an invalid result"}
	}
	return object, true, nil
}

func validRegexMatcherObject(object map[string]any) bool {
	if _, ok := numeric(collapse(field(object, "start"))); ok {
		return true
	}
	if _, ok := numeric(collapse(field(object, "end"))); ok {
		return true
	}
	switch collapse(field(object, "groups")).(type) {
	case []any, value.Array, sequence:
		return true
	}
	_, ok := callable(collapse(field(object, "next")))
	return ok
}

func regexMatcherBounds(input string, object map[string]any) (int, int, error) {
	startNumber, startOK := numeric(collapse(field(object, "start")))
	endNumber, endOK := numeric(collapse(field(object, "end")))
	maximum := float64(jsonregex.UTF16Index(input, len(input)))
	if !startOK || !endOK || math.IsNaN(startNumber) || math.IsNaN(endNumber) ||
		math.IsInf(startNumber, 0) || math.IsInf(endNumber, 0) {
		return 0, 0, runtimeError{code: "T1010", msg: "matcher result must contain numeric start and end offsets"}
	}
	startNumber, endNumber = math.Trunc(startNumber), math.Trunc(endNumber)
	if startNumber < 0 || endNumber < startNumber || endNumber > maximum {
		return 0, 0, runtimeError{code: "T1010", msg: "matcher result contains invalid offsets"}
	}
	return int(startNumber), int(endNumber), nil
}

func regexMatcherGroups(object map[string]any) []any {
	switch groups := collapse(field(object, "groups")).(type) {
	case []any:
		return groups
	case value.Array:
		return groups.Items
	case sequence:
		return []any(groups)
	default:
		return nil
	}
}

func builtinContainsRegex(st state, args []any) (any, error) {
	if value.IsUndefined(args[0]) || value.IsUndefined(args[1]) {
		return value.Undefined, nil
	}
	if err := regexCheck(st); err != nil {
		return nil, err
	}
	input, ok := regexStringArgument(args[0])
	if !ok {
		return nil, regexTypeError("contains")
	}
	needle, ok := regexStringArgument(args[1])
	if ok {
		if err := regexConsumeBudget(st, len(input)+len(needle)+1); err != nil {
			return nil, err
		}
		return strings.Contains(input, needle), nil
	}
	if pattern, ok := regexFromValue(args[1]); ok {
		return regexMatches(st, pattern.pattern, input)
	}
	matcher, ok := callable(collapse(args[1]))
	if !ok {
		return nil, regexTypeError("contains")
	}
	_, matched, err := invokeRegexMatcher(st, matcher, []any{input})
	return matched, err
}

func builtinMatchRegex(st state, args []any) (any, error) {
	if value.IsUndefined(args[0]) || value.IsUndefined(args[1]) {
		return value.Undefined, nil
	}
	input, ok := regexStringArgument(args[0])
	if !ok {
		return nil, regexTypeError("match")
	}
	limit, err := regexLimit(args, 2, "match")
	if err != nil {
		return nil, err
	}
	if limit == 0 {
		return value.Undefined, nil
	}
	result := make([]any, 0, sequenceAllocationCapacity(1, st.runtime))
	matcher, ok := callable(collapse(args[1]))
	if !ok {
		return nil, regexTypeError("match")
	}
	current, found, err := invokeRegexMatcher(st, matcher, []any{input})
	if err != nil {
		return nil, err
	}
	for found && (limit < 0 || float64(len(result)) < limit) {
		if err := regexCheck(st); err != nil {
			return nil, err
		}
		if st.runtime != nil {
			if err := st.runtime.checkSequenceLength(len(result) + 1); err != nil {
				return nil, err
			}
		}
		result = append(result, matcherResultWithoutNext(current))
		next, ok := callable(field(current, "next"))
		if !ok {
			break
		}
		current, found, err = invokeRegexMatcher(st, next, nil)
		if err != nil {
			return nil, err
		}
	}
	if len(result) == 0 {
		return value.Undefined, nil
	}
	return value.Array{Items: result}, nil
}

func regexMatchObject(input string, indexes []int) (map[string]any, error) {
	start, end := indexes[0], indexes[1]
	matched, err := jsonregex.UTF16Slice(input, start, end)
	if err != nil {
		return nil, regexRepresentationError(err)
	}
	groups := make([]any, 0, (len(indexes)-2)/2)
	for i := 2; i+1 < len(indexes); i += 2 {
		if indexes[i] < 0 || indexes[i+1] < 0 {
			groups = append(groups, value.Undefined)
			continue
		}
		capture, err := jsonregex.UTF16Slice(input, indexes[i], indexes[i+1])
		if err != nil {
			return nil, regexRepresentationError(err)
		}
		groups = append(groups, capture)
	}
	return map[string]any{
		"match":  matched,
		"groups": value.Array{Items: groups},
	}, nil
}

func matcherResultWithoutNext(object map[string]any) map[string]any {
	result := make(map[string]any, len(object)-1)
	for key, item := range object {
		switch key {
		case "next", "start", "end":
			continue
		default:
			result[key] = item
		}
	}
	if _, ok := result["index"]; !ok {
		if start, ok := object["start"]; ok {
			result["index"] = start
		}
	}
	return result
}

func regexMatcherObject(pattern regexValue, input string, indexes []int) (map[string]any, error) {
	object, err := regexMatchObject(input, indexes)
	if err != nil {
		return nil, err
	}
	object["start"] = float64(indexes[0])
	object["end"] = float64(indexes[1])
	nextStart := indexes[1]
	if nextStart == indexes[0] {
		nextStart++
	}
	object["next"] = regexNextValue{pattern: pattern, input: input, start: nextStart}
	return object, nil
}

func builtinReplaceRegex(st state, args []any) (any, error) {
	if len(args) < 3 || len(args) > 4 {
		return nil, runtimeError{code: "T0410", msg: "function \"$replace\" received an invalid number of arguments"}
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	input, ok := regexStringArgument(args[0])
	if !ok {
		return nil, regexTypeError("replace")
	}
	limit, err := regexLimit(args, 3, "replace")
	if err != nil {
		return nil, err
	}
	if limit == 0 {
		return input, nil
	}
	var pattern regexValue
	if regex, ok := regexFromValue(args[1]); ok {
		pattern = regex
	} else {
		needle, ok := regexStringArgument(args[1])
		if !ok {
			matcher, callablePattern := callable(collapse(args[1]))
			if !callablePattern {
				return nil, regexTypeError("replace")
			}
			return replaceWithMatcher(st, input, matcher, args[2], limit)
		}
		if needle == "" {
			return nil, runtimeError{code: "D3010", msg: "regular expression cannot be empty"}
		}
		if replacement, stringReplacement := regexStringArgument(args[2]); stringReplacement {
			return replaceLiteralString(st, input, needle, replacement, limit)
		}
		compiled, compileErr := jsonregex.CompileLiteral("/" + regexEscapeLiteral(needle) + "/")
		if compileErr != nil {
			return nil, runtimeError{code: "T0410", msg: compileErr.Error(), cause: compileErr}
		}
		pattern = regexValue{pattern: compiled}
	}
	matches, matchErr := regexFindAll(st, pattern.pattern, input, regexMatchLimit(limit))
	if matchErr != nil {
		return "", matchErr
	}
	if len(matches) == 0 {
		return input, nil
	}
	inputUnits := jsonregex.UTF16Units(input)
	out := make([]uint16, 0, len(inputUnits))
	last := 0
	for _, indexes := range matches {
		if indexes[0] == indexes[1] {
			return "", runtimeError{code: "D1004", msg: "regular expression matched an empty string"}
		}
		if err := regexCheck(st); err != nil {
			return "", err
		}
		start, end := indexes[0], indexes[1]
		out = append(out, inputUnits[last:start]...)
		replacement, err := regexReplacement(st, args[2], input, inputUnits, indexes, pattern)
		if err != nil {
			return "", err
		}
		out = append(out, replacement...)
		last = end
	}
	out = append(out, inputUnits[last:]...)
	result, err := jsonregex.UTF16String(out)
	if err != nil {
		return "", regexRepresentationError(err)
	}
	return result, nil
}

func replaceLiteralString(st state, input, pattern, replacement string, limit float64) (string, error) {
	if err := regexConsumeBudget(st, len(input)+len(pattern)+1); err != nil {
		return "", err
	}
	var out strings.Builder
	last, count := 0, 0
	for limit < 0 || float64(count) < limit {
		if err := regexCheck(st); err != nil {
			return "", err
		}
		relative := strings.Index(input[last:], pattern)
		if relative < 0 {
			break
		}
		start := last + relative
		out.WriteString(input[last:start])
		out.WriteString(replacement)
		last = start + len(pattern)
		count++
	}
	out.WriteString(input[last:])
	return out.String(), nil
}

func regexReplacement(st state, replacement any, input string, inputUnits []uint16, indexes []int, pattern regexValue) ([]uint16, error) {
	if text, ok := regexStringArgument(replacement); ok {
		return expandRegexReplacementUnits(text, inputUnits, indexes), nil
	}
	fn, ok := callable(collapse(replacement))
	if !ok {
		return nil, regexTypeError("replace")
	}
	match, err := regexMatcherObject(pattern, input, indexes)
	if err != nil {
		return nil, err
	}
	result, err := fn.invoke(st, []any{match})
	if err != nil {
		return nil, err
	}
	text, ok := regexStringArgument(result)
	if !ok {
		return nil, runtimeError{code: "D3012", msg: "replacement function must return a string"}
	}
	return jsonregex.UTF16Units(text), nil
}

func replaceWithMatcher(st state, input string, matcher callableValue, replacement any, limit float64) (string, error) {
	current, found, err := invokeRegexMatcher(st, matcher, []any{input})
	if err != nil {
		return "", err
	}
	inputUnits := jsonregex.UTF16Units(input)
	out := make([]uint16, 0, len(inputUnits))
	last, count := 0, 0
	for found && (limit < 0 || float64(count) < limit) {
		start, end, boundsErr := regexMatcherBounds(input, current)
		if boundsErr != nil {
			return "", boundsErr
		}
		if start == end {
			return "", runtimeError{code: "D1004", msg: "regular expression matched an empty string"}
		}
		if start < last {
			return "", runtimeError{code: "T1010", msg: "matcher function returned overlapping results"}
		}
		out = append(out, inputUnits[last:start]...)
		replaced, replaceErr := matcherReplacement(st, replacement, current)
		if replaceErr != nil {
			return "", replaceErr
		}
		out = append(out, jsonregex.UTF16Units(replaced)...)
		last = end
		count++
		next, ok := callable(collapse(field(current, "next")))
		if !ok {
			break
		}
		current, found, err = invokeRegexMatcher(st, next, nil)
		if err != nil {
			return "", err
		}
	}
	out = append(out, inputUnits[last:]...)
	result, err := jsonregex.UTF16String(out)
	if err != nil {
		return "", regexRepresentationError(err)
	}
	return result, nil
}

func matcherReplacement(st state, replacement any, match map[string]any) (string, error) {
	if text, ok := regexStringArgument(replacement); ok {
		matched, _ := regexStringArgument(field(match, "match"))
		return expandRegexReplacementParts(text, matched, regexMatcherGroups(match)), nil
	}
	fn, ok := callable(collapse(replacement))
	if !ok {
		return "", regexTypeError("replace")
	}
	result, err := fn.invoke(st, []any{match})
	if err != nil {
		return "", err
	}
	text, ok := regexStringArgument(result)
	if !ok {
		return "", runtimeError{code: "D3012", msg: "replacement function must return a string"}
	}
	return text, nil
}

func expandRegexReplacementUnits(replacement string, input []uint16, indexes []int) []uint16 {
	runes := []rune(replacement)
	out := make([]uint16, 0, len(input))
	for index := 0; index < len(runes); index++ {
		if runes[index] != '$' || index+1 >= len(runes) {
			out = append(out, jsonregex.UTF16Units(string(runes[index]))...)
			continue
		}
		next := runes[index+1]
		switch next {
		case '$':
			out = append(out, '$')
			index++
		case '0':
			out = append(out, input[indexes[0]:indexes[1]]...)
			index++
		default:
			if next < '1' || next > '9' {
				out = append(out, '$')
				continue
			}
			group := int(next - '0')
			consumed := 1
			groupCount := len(indexes)/2 - 1
			if groupCount >= 10 && index+2 < len(runes) && runes[index+2] >= '0' && runes[index+2] <= '9' {
				candidate := group*10 + int(runes[index+2]-'0')
				if candidate <= groupCount {
					group = candidate
					consumed = 2
				}
			}
			if group <= groupCount {
				start, end := indexes[group*2], indexes[group*2+1]
				if start >= 0 && end >= 0 {
					out = append(out, input[start:end]...)
				}
			}
			index += consumed
		}
	}
	return out
}

func expandRegexReplacementParts(replacement, matched string, groups []any) string {
	var out strings.Builder
	for i := 0; i < len(replacement); i++ {
		if replacement[i] != '$' || i+1 >= len(replacement) {
			out.WriteByte(replacement[i])
			continue
		}
		next := replacement[i+1]
		switch next {
		case '$':
			out.WriteByte('$')
			i++
		case '0':
			out.WriteString(matched)
			i++
		default:
			if next < '1' || next > '9' {
				out.WriteByte('$')
				continue
			}
			group := int(next - '0')
			consumed := 1
			if len(groups) >= 10 && i+2 < len(replacement) && replacement[i+2] >= '0' && replacement[i+2] <= '9' {
				candidate := group*10 + int(replacement[i+2]-'0')
				if candidate <= len(groups) {
					group = candidate
					consumed = 2
				}
			}
			if group <= len(groups) && !value.IsUndefined(collapse(groups[group-1])) {
				if capture, ok := regexStringArgument(groups[group-1]); ok {
					out.WriteString(capture)
				}
			}
			i += consumed
		}
	}
	return out.String()
}

func builtinSplitRegex(st state, args []any) (any, error) {
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	input, ok := regexStringArgument(args[0])
	if !ok {
		return nil, regexTypeError("split")
	}
	limit, err := regexLimit(args, 2, "split")
	if err != nil {
		return nil, err
	}
	if limit == 0 {
		return value.Array{Items: []any{}}, nil
	}
	if separator, ok := regexStringArgument(args[1]); ok {
		if err := regexConsumeBudget(st, len(input)+len(separator)+1); err != nil {
			return nil, err
		}
		stringLimit := -1
		if limit >= 0 {
			stringLimit = int(math.Floor(limit))
		}
		return splitString(st, input, separator, stringLimit)
	}
	pattern, ok := regexFromValue(args[1])
	if !ok {
		if matcher, callableArgument := callable(collapse(args[1])); callableArgument {
			return splitWithMatcher(st, input, matcher, limit)
		}
		return nil, regexTypeError("split")
	}
	matches, matchErr := regexFindAll(st, pattern.pattern, input, regexMatchLimit(limit))
	if matchErr != nil {
		return nil, matchErr
	}
	parts := make([]any, 0, len(matches)+1)
	inputUnits := jsonregex.UTF16Units(input)
	last := 0
	for _, indexes := range matches {
		if err := regexCheck(st); err != nil {
			return nil, err
		}
		if indexes[0] == indexes[1] {
			return nil, runtimeError{code: "D1004", msg: "regular expression matched an empty string"}
		}
		if limit > 0 && float64(len(parts)) >= limit {
			return value.Array{Items: parts}, nil
		}
		part, err := jsonregex.UTF16String(inputUnits[last:indexes[0]])
		if err != nil {
			return nil, regexRepresentationError(err)
		}
		parts = append(parts, part)
		last = indexes[1]
		if limit > 0 && float64(len(parts)) >= limit {
			return value.Array{Items: parts}, nil
		}
	}
	if limit < 0 || float64(len(parts)) < limit {
		part, err := jsonregex.UTF16String(inputUnits[last:])
		if err != nil {
			return nil, regexRepresentationError(err)
		}
		parts = append(parts, part)
	}
	return value.Array{Items: parts}, nil
}

func splitWithMatcher(st state, input string, matcher callableValue, limit float64) (any, error) {
	current, found, err := invokeRegexMatcher(st, matcher, []any{input})
	if err != nil {
		return nil, err
	}
	parts := make([]any, 0)
	inputUnits := jsonregex.UTF16Units(input)
	last, count := 0, 0
	for found && (limit < 0 || float64(count) < limit) {
		start, end, boundsErr := regexMatcherBounds(input, current)
		if boundsErr != nil {
			return nil, boundsErr
		}
		if start == end {
			return nil, runtimeError{code: "D1004", msg: "regular expression matched an empty string"}
		}
		if start < last {
			return nil, runtimeError{code: "T1010", msg: "matcher function returned overlapping results"}
		}
		part, err := jsonregex.UTF16String(inputUnits[last:start])
		if err != nil {
			return nil, regexRepresentationError(err)
		}
		parts = append(parts, part)
		last = end
		count++
		next, ok := callable(collapse(field(current, "next")))
		if !ok {
			break
		}
		current, found, err = invokeRegexMatcher(st, next, nil)
		if err != nil {
			return nil, err
		}
	}
	if limit < 0 || float64(count) < limit {
		part, err := jsonregex.UTF16String(inputUnits[last:])
		if err != nil {
			return nil, regexRepresentationError(err)
		}
		parts = append(parts, part)
	}
	return value.Array{Items: parts}, nil
}

func splitString(st state, input, separator string, limit int) (value.Array, error) {
	if limit == 0 {
		return value.Array{Items: []any{}}, nil
	}
	if separator == "" {
		if !utf8.ValidString(input) {
			return value.Array{}, stringRepresentationError("split input contains invalid UTF-8")
		}
		if err := stringWorkPreflight(st, stringWorkSize(len(input)+1, 2)); err != nil {
			return value.Array{}, err
		}
		units := jsonregex.UTF16Units(input)
		if limit > 0 && len(units) > limit {
			units = units[:limit]
		}
		parts := make([]any, len(units))
		for index := range units {
			if err := regexCheck(st); err != nil {
				return value.Array{}, err
			}
			part, err := jsonregex.UTF16String(units[index : index+1])
			if err != nil {
				return value.Array{}, regexRepresentationError(err)
			}
			parts[index] = part
		}
		return value.Array{Items: parts}, nil
	}
	pieces := strings.Split(input, separator)
	if limit > 0 && len(pieces) > limit {
		pieces = pieces[:limit]
	}
	parts := make([]any, len(pieces))
	for i, piece := range pieces {
		parts[i] = piece
	}
	return value.Array{Items: parts}, nil
}

func regexLimit(args []any, index int, name string) (float64, error) {
	if len(args) <= index || value.IsUndefined(args[index]) {
		return -1, nil
	}
	number, ok := numeric(collapse(args[index]))
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, runtimeError{code: "T0410", msg: "limit argument to function $" + name + " must be a number"}
	}
	if number < 0 {
		code := "D3011"
		switch name {
		case "match":
			code = "D3040"
		case "split":
			code = "D3020"
		}
		return 0, runtimeError{code: code, msg: "limit argument must not be negative"}
	}
	return number, nil
}

func regexMatchLimit(limit float64) int {
	if limit < 0 {
		return -1
	}
	maximum := float64(int(^uint(0) >> 1))
	if limit >= maximum {
		return int(^uint(0) >> 1)
	}
	return int(math.Ceil(limit))
}

func regexCheck(st state) error {
	if st.runtime == nil {
		return nil
	}
	return st.runtime.check()
}

func regexTypeError(name string) error {
	return runtimeError{code: "T0410", msg: "argument to function $" + name + " does not match its signature"}
}

func regexRuntimeError(err error) error {
	return runtimeError{code: "U1001", msg: "regular expression evaluation exceeded the resource limit", cause: err}
}

func regexRepresentationError(err error) error {
	return runtimeError{code: "U1002", msg: err.Error(), cause: err}
}

func regexFindAll(st state, pattern jsonregex.Pattern, input string, limit int) ([][]int, error) {
	if err := regexConsumeBudget(st, len(input)+1); err != nil {
		return nil, err
	}
	ctx := context.Background()
	if st.runtime != nil && st.runtime.ctx != nil {
		ctx = st.runtime.ctx
	}
	deadline := regexAttemptDeadline(st, ctx)
	quantum := 10 * time.Millisecond
	for {
		if err := regexContextError(ctx); err != nil {
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, regexRuntimeError(context.DeadlineExceeded)
		}
		if quantum > remaining {
			quantum = remaining
		}
		matches, err := pattern.WithTimeout(quantum).FindAllStringSubmatchUTF16IndexContext(ctx, input, limit)
		if err == nil {
			return matches, nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		var representationErr *jsonregex.UTF16RepresentationError
		if errors.As(err, &representationErr) {
			return nil, regexRepresentationError(representationErr)
		}
		if !jsonregex.IsTimeout(err) {
			return nil, regexRuntimeError(err)
		}
		if err := regexCheck(st); err != nil {
			return nil, err
		}
		quantum *= 2
	}
}

func regexMatches(st state, pattern jsonregex.Pattern, input string) (bool, error) {
	if err := regexConsumeBudget(st, len(input)+1); err != nil {
		return false, err
	}
	ctx := context.Background()
	if st.runtime != nil && st.runtime.ctx != nil {
		ctx = st.runtime.ctx
	}
	deadline := regexAttemptDeadline(st, ctx)
	quantum := 10 * time.Millisecond
	for {
		if err := regexContextError(ctx); err != nil {
			return false, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, regexRuntimeError(context.DeadlineExceeded)
		}
		if quantum > remaining {
			quantum = remaining
		}
		matched, err := pattern.WithTimeout(quantum).MatchStringContext(ctx, input)
		if err == nil {
			return matched, nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}
		if !jsonregex.IsTimeout(err) {
			return false, regexRuntimeError(err)
		}
		if err := regexCheck(st); err != nil {
			return false, err
		}
		quantum *= 2
	}
}

func regexConsumeBudget(st state, units int) error {
	for index := 0; index < units; index++ {
		if err := regexCheck(st); err != nil {
			return err
		}
	}
	return nil
}

func regexAttemptDeadline(st state, ctx context.Context) time.Time {
	deadline := time.Now().Add(time.Second)
	if st.runtime != nil && !st.runtime.deadline.IsZero() && st.runtime.deadline.Before(deadline) {
		deadline = st.runtime.deadline
	}
	if ctx != nil {
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
	}
	return deadline
}

func regexContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func regexEscapeLiteral(input string) string {
	var out strings.Builder
	for _, r := range input {
		if strings.ContainsRune(`\\.+*?()|[]{}^$`, r) {
			out.WriteByte('\\')
		}
		out.WriteRune(r)
	}
	return out.String()
}
