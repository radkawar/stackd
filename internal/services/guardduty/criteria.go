package guardduty

//go:generate go run ./generatecriteria

import (
	"cmp"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	api "stackd/internal/awsapi/guardduty"
)

type findingKind uint8

const (
	findingString findingKind = iota
	findingNumber
	findingBool
	findingDynamic
	findingMissing
)

type findingValue struct {
	kind   findingKind
	text   string
	number float64
}
type findingSelector struct {
	kind  findingKind
	visit func(api.Finding, func(findingValue) bool) bool
}

func findingBoolean(v bool) findingValue {
	if v {
		return findingValue{kind: findingBool, text: "true"}
	}
	return findingValue{kind: findingBool, text: "false"}
}
func findingTimestamp(s string) findingValue {
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil {
		return findingValue{kind: findingMissing}
	}
	return findingValue{kind: findingNumber, number: float64(t.UnixMilli())}
}

// AdditionalInfo.Value is itself an opaque JSON string in the AWS model. Only
// that string needs decoding; all modeled Finding structure uses typed visitors.
func visitAdditionalInfo(f api.Finding, path string, visit func(findingValue) bool) bool {
	if f.Service == nil || f.Service.AdditionalInfo == nil || f.Service.AdditionalInfo.Value == nil {
		return false
	}
	var data any
	if json.Unmarshal([]byte(*f.Service.AdditionalInfo.Value), &data) != nil {
		return false
	}
	return visitAdditionalValue(data, path, visit)
}
func visitAdditionalValue(data any, path string, visit func(findingValue) bool) bool {
	if list, ok := data.([]any); ok {
		for _, v := range list {
			if visitAdditionalValue(v, path, visit) {
				return true
			}
		}
		return false
	}
	if path != "" {
		key, rest, _ := strings.Cut(path, ".")
		object, ok := data.(map[string]any)
		if !ok {
			return false
		}
		return visitAdditionalValue(object[key], rest, visit)
	}
	switch v := data.(type) {
	case string:
		return visit(findingValue{kind: findingString, text: v})
	case float64:
		return visit(findingValue{kind: findingNumber, number: v})
	case bool:
		return visit(findingBoolean(v))
	}
	return false
}

func validateCriteria(criteria *api.FindingCriteria) error {
	if criteria == nil {
		return nil
	}
	for field, c := range criteria.Criterion {
		selector, ok := findingSelectors[string(field)]
		if !ok {
			return invalid("Unsupported finding criterion: " + string(field))
		}
		count := 0
		for _, values := range [][]api.String{c.Eq, c.Equals, c.Neq, c.NotEquals} {
			if values != nil {
				count++
			}
			if len(values) > 50 {
				return invalid("A condition supports at most 50 values")
			}
			for _, v := range values {
				if selector.kind == findingNumber {
					n, e := strconv.ParseFloat(string(v), 64)
					if e != nil || math.IsInf(n, 0) || math.IsNaN(n) {
						return invalid("Numerical finding criterion requires numerical values")
					}
				}
				if selector.kind == findingBool && v != "true" && v != "false" {
					return invalid("Boolean finding criterion requires true or false")
				}
			}
		}
		if c.Matches != nil {
			count++
			if err := validateWildcards(c.Matches, selector.kind); err != nil {
				return err
			}
		}
		if c.NotMatches != nil {
			count++
			if err := validateWildcards(c.NotMatches, selector.kind); err != nil {
				return err
			}
		}
		numeric := c.Gt != nil || c.Gte != nil || c.Lt != nil || c.Lte != nil || c.GreaterThan != nil || c.GreaterThanOrEqual != nil || c.LessThan != nil || c.LessThanOrEqual != nil
		if numeric {
			count++
			if selector.kind != findingNumber && selector.kind != findingDynamic {
				return invalid("Range criteria require a numerical or timestamp field")
			}
		}
		if count == 0 {
			return invalid("A finding condition must contain an operator")
		}
	}
	return nil
}
func validateWildcards[T ~string](values []T, kind findingKind) error {
	if len(values) > 5 {
		return invalid("A wildcard condition supports at most 5 values")
	}
	for _, v := range values {
		if kind != findingString && kind != findingDynamic {
			return invalid("Wildcard criteria require a string field")
		}
		if len(v) == 0 || utf8.RuneCountInString(string(v)) > 512 || strings.Count(string(v), "*")+strings.Count(string(v), "?") > 5 {
			return invalid("Invalid wildcard criterion")
		}
	}
	return nil
}

func validateQueryCriteria(criteria *api.FindingCriteria) error {
	if err := validateCriteria(criteria); err != nil {
		return err
	}
	if criteria != nil {
		for _, c := range criteria.Criterion {
			if c.Matches != nil || c.NotMatches != nil {
				return invalid("Matches and NotMatches are only supported for saved filters")
			}
		}
	}
	return nil
}
func matchesFinding(f api.Finding, criteria *api.FindingCriteria) bool {
	if criteria == nil {
		return true
	}
	for name, c := range criteria.Criterion {
		s, ok := findingSelectors[string(name)]
		if !ok || !matchesCondition(f, s, c) {
			return false
		}
	}
	return true
}
func equalsFindingValue(v findingValue, want string) bool {
	if v.kind == findingMissing {
		return false
	}
	if v.kind == findingNumber {
		n, err := strconv.ParseFloat(want, 64)
		return err == nil && v.number == n
	}
	return v.text == want
}
func matchesCondition(f api.Finding, s findingSelector, c api.Condition) bool {
	if !matchesValues(f, s, c.Eq, false, false) || !matchesValues(f, s, c.Equals, false, false) ||
		!matchesValues(f, s, c.Neq, true, false) || !matchesValues(f, s, c.NotEquals, true, false) ||
		!matchesValues(f, s, c.Matches, false, true) || !matchesValues(f, s, c.NotMatches, true, true) {
		return false
	}
	if c.Gt != nil || c.Gte != nil || c.Lt != nil || c.Lte != nil || c.GreaterThan != nil || c.GreaterThanOrEqual != nil || c.LessThan != nil || c.LessThanOrEqual != nil {
		return s.visit(f, func(v findingValue) bool {
			if v.kind != findingNumber {
				return false
			}
			n := v.number
			return (c.Gt == nil || n > float64(*c.Gt)) && (c.GreaterThan == nil || n > float64(*c.GreaterThan)) && (c.Gte == nil || n >= float64(*c.Gte)) && (c.GreaterThanOrEqual == nil || n >= float64(*c.GreaterThanOrEqual)) && (c.Lt == nil || n < float64(*c.Lt)) && (c.LessThan == nil || n < float64(*c.LessThan)) && (c.Lte == nil || n <= float64(*c.Lte)) && (c.LessThanOrEqual == nil || n <= float64(*c.LessThanOrEqual))
		})
	}
	return true
}

func matchesValues[T ~string](f api.Finding, s findingSelector, values []T, negative, wildcard bool) bool {
	if values == nil {
		return true
	}
	found := s.visit(f, func(v findingValue) bool {
		for _, wanted := range values {
			if wildcard {
				if v.kind == findingString && wildcardMatch(string(wanted), v.text) {
					return true
				}
			} else if equalsFindingValue(v, string(wanted)) {
				return true
			}
		}
		return false
	})
	return found != negative
}

// wildcardMatch implements GuardDuty's * and ? operators, not shell character
// classes or path separators. Rune decoding avoids allocating a rune slice.
func wildcardMatch(pattern, input string) bool {
	p, i, star, retry := 0, 0, -1, 0
	for i < len(input) {
		if p < len(pattern) && pattern[p] == '*' {
			star = p
			p++
			retry = i
			continue
		}
		if p < len(pattern) {
			pr, ps := utf8.DecodeRuneInString(pattern[p:])
			ir, is := utf8.DecodeRuneInString(input[i:])
			if pr == '?' || pr == ir {
				p += ps
				i += is
				continue
			}
		}
		if star < 0 {
			return false
		}
		_, size := utf8.DecodeRuneInString(input[retry:])
		retry += size
		i = retry
		p = star + 1
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
func findingSortSettings(criteria *api.SortCriteria) (string, string) {
	field, order := "service.eventLastSeen", "DESC"
	if criteria != nil {
		if criteria.AttributeName != nil {
			field = value(criteria.AttributeName)
		}
		if criteria.OrderBy != nil {
			order = value(criteria.OrderBy)
		}
	}
	return field, order
}
func sortFindings(findings []api.Finding, criteria *api.SortCriteria) error {
	field, order := findingSortSettings(criteria)
	if criteria != nil && criteria.AttributeName != nil {
		switch field {
		case "accountId", "type", "severity", "createdAt", "updatedAt", "confidence", "service.eventFirstSeen", "service.eventLastSeen":
		default:
			return invalid("Unsupported finding sort attribute: " + field)
		}
	}
	if order != "ASC" && order != "DESC" {
		return invalid("Sort order must be ASC or DESC")
	}
	slices.SortStableFunc(findings, func(a, b api.Finding) int { return compareFindings(a, b, criteria) })
	return nil
}

// compareFindings is also the keyset boundary comparison. Callers validate the
// sort criteria first and retain the selected scalar plus Id in their cursor.
func compareFindings(a, b api.Finding, criteria *api.SortCriteria) int {
	field, order := findingSortSettings(criteria)
	selector, ok := findingSelectors[field]
	if !ok {
		return strings.Compare(value(a.Id), value(b.Id))
	}
	first := func(f api.Finding) findingValue {
		v := findingValue{kind: findingMissing}
		selector.visit(f, func(x findingValue) bool { v = x; return true })
		return v
	}
	av, bv := first(a), first(b)
	n := 0
	if av.kind == findingMissing || bv.kind == findingMissing {
		n = cmp.Compare(av.kind, bv.kind)
	} else if av.kind == findingNumber {
		n = cmp.Compare(av.number, bv.number)
	} else {
		n = strings.Compare(av.text, bv.text)
	}
	if order == "DESC" {
		n = -n
	}
	if n == 0 {
		n = strings.Compare(value(a.Id), value(b.Id))
	}
	return n
}
