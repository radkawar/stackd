package awsschedule

import (
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

type dialect uint8

const (
	backup dialect = iota
	eventBridge
	applicationAutoScaling
	eventBridgeScheduler
)

type calendar struct {
	seconds                []int
	location               *time.Location
	minutes, hours, months []int
	years                  []calendarSpan
	days                   []int
	weekdays               bool
	last, nearest          bool
	offset, ordinal        int
}

// Years remain arithmetic progressions: native admission extends to int32's
// maximum year, so materializing even one wildcard year field is not viable.
type calendarSpan struct {
	start, end, step int64
}

var monthNames = []string{"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"}
var weekdayNames = []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}

func parseCron(expression string, syntax dialect) (Schedule, error) {
	if !strings.HasPrefix(expression, "cron(") || !strings.HasSuffix(expression, ")") {
		return Schedule{}, errExpression
	}
	body := strings.ToUpper(expression[5 : len(expression)-1])
	var fields []string
	c := calendar{seconds: []int{0}, location: time.UTC}
	if syntax == eventBridge {
		fields = strings.Split(body, " ")
	} else {
		fields = strings.Fields(body)
	}
	if syntax == applicationAutoScaling && len(fields) == 7 {
		var ok bool
		c.seconds, ok = syntax.values(fields[0], 0, 59, nil)
		if !ok {
			return Schedule{}, errExpression
		}
		fields = fields[1:]
	}
	if syntax == backup {
		if len(fields) < 5 {
			return Schedule{}, errExpression
		}
		if len(fields) == 5 {
			fields = append(fields, "*")
		}
	} else {
		if len(fields) != 6 {
			return Schedule{}, errExpression
		}
		for _, field := range fields {
			if field == "" {
				return Schedule{}, errExpression
			}
			for i := range len(field) {
				if field[i] <= ' ' || field[i] > '~' {
					return Schedule{}, errExpression
				}
			}
		}
	}
	if (fields[2] == "?") == (fields[4] == "?") {
		return Schedule{}, errExpression
	}
	var ok bool
	if c.minutes, ok = syntax.values(fields[0], 0, 59, nil); !ok {
		return Schedule{}, errExpression
	}
	if c.hours, ok = syntax.values(fields[1], 0, 23, nil); !ok {
		return Schedule{}, errExpression
	}
	if c.months, ok = syntax.values(fields[3], 1, 12, monthNames); !ok {
		return Schedule{}, errExpression
	}
	minimum, maximum := 1970, 2199
	if syntax == eventBridge {
		minimum, maximum = 0, math.MaxInt32
	}
	for part := range strings.SplitSeq(fields[5], ",") {
		span, ok := syntax.span(part, minimum, maximum, nil, true)
		if !ok {
			return Schedule{}, errExpression
		}
		c.years = append(c.years, span)
	}
	if !c.parseDay(fields[2], fields[4], syntax) {
		return Schedule{}, errExpression
	}
	return Schedule{calendar: c}, nil
}

func (c *calendar) parseDay(monthDay, weekDay string, syntax dialect) bool {
	c.weekdays = monthDay == "?"
	day := monthDay
	var ok bool
	if c.weekdays {
		day = weekDay
		if syntax != backup && strings.Contains(day, "#") && (strings.Count(day, "#") != 1 || strings.Contains(day, ",")) {
			return false
		}
		if strings.HasSuffix(day, "L") {
			c.last = true
			day = strings.TrimSuffix(day, "L")
			if day == "" {
				day = "7"
				c.last = false // A bare weekday L means Saturday.
			}
		} else if before, after, hash := strings.Cut(day, "#"); hash {
			day = before
			ordinal, additional, listed := strings.Cut(after, ",")
			c.ordinal, ok = syntax.number(ordinal, 1, 5, nil)
			if !ok {
				return false
			}
			if listed {
				// Backup admits an ordinal followed by a weekday list.
				day += "," + additional
			}
		}
		c.days, ok = syntax.values(day, 1, 7, weekdayNames)
		return ok && (!c.last || len(c.days) == 1)
	}
	if strings.Contains(day, "W") {
		c.nearest = true
		day, _, _ = strings.Cut(day, "W")
		if !strings.HasPrefix(day, "L") {
			// Native W after a range is ignored; immediate W selects the
			// nearest weekday of its first date without crossing the month.
			c.nearest = !strings.Contains(day, "-")
		}
	}
	if strings.HasPrefix(day, "L") {
		c.last = true
		if day == "L" {
			return true
		}
		if !strings.HasPrefix(day, "L-") {
			return false
		}
		c.offset, ok = syntax.number(day[2:], 0, 30, nil)
		return ok
	}
	c.days, ok = syntax.values(day, 1, 31, nil)
	return ok && (!c.nearest || len(c.days) == 1)
}

func (syntax dialect) number(value string, minimum, maximum int, names []string) (int, bool) {
	for index, name := range names {
		if value == name || syntax == eventBridge && strings.HasPrefix(value, name) {
			return index + 1, true
		}
	}
	if syntax == eventBridge {
		// Native numeric and three-letter name tokens accept suffixes.
		end := 0
		for end < len(value) && value[end] >= '0' && value[end] <= '9' {
			end++
		}
		value = value[:end]
	}
	if !digits(value) {
		return 0, false
	}
	n, err := strconv.ParseInt(value, 10, 32)
	return int(n), err == nil && n >= int64(minimum) && n <= int64(maximum)
}

func (syntax dialect) span(part string, minimum, maximum int, names []string, year bool) (calendarSpan, bool) {
	base, stride, stepped := strings.Cut(part, "/")
	step := 1
	if stepped {
		lower, upper := 1, maximum
		if syntax == eventBridge {
			lower, upper = 0, math.MaxInt32
		}
		var ok bool
		step, ok = syntax.number(stride, lower, upper, nil)
		if !ok {
			return calendarSpan{}, false
		}
	}
	start, end := minimum, maximum
	if base != "*" {
		first, last, ranged := strings.Cut(base, "-")
		var ok bool
		start, ok = syntax.number(first, minimum, maximum, names)
		if !ok {
			return calendarSpan{}, false
		}
		if ranged {
			end, ok = syntax.number(last, minimum, maximum, names)
			if !ok || year && end < start {
				return calendarSpan{}, false
			}
		} else if !stepped {
			end = start
		}
	}
	if end < start {
		end += maximum - minimum + 1
	}
	if step == 0 {
		// Native zero increments select the start, not an infinite loop.
		end, step = start, 1
	}
	return calendarSpan{int64(start), int64(end), int64(step)}, true
}

func (syntax dialect) values(field string, minimum, maximum int, names []string) ([]int, bool) {
	var selected [60]bool
	width := int64(maximum - minimum + 1)
	for part := range strings.SplitSeq(field, ",") {
		span, ok := syntax.span(part, minimum, maximum, names, false)
		if !ok {
			return nil, false
		}
		for value := span.start; value <= span.end; value += span.step {
			selected[(value-int64(minimum))%width] = true
		}
	}
	var values []int
	for index, included := range selected[:width] {
		if included {
			values = append(values, minimum+index)
		}
	}
	return values, true
}

func (c calendar) matchesDay(year int, month time.Month, day, lastDay int) bool {
	weekday := int(time.Date(year, month, day, 0, 0, 0, 0, time.UTC).Weekday()) + 1
	if c.weekdays {
		if c.ordinal != 0 {
			// Ordinal selectors use the first selected weekday, including
			// Backup expressions that also contain a weekday list.
			return c.days[0] == weekday && (day-1)/7+1 == c.ordinal
		}
		return slices.Contains(c.days, weekday) && (!c.last || day+7 > lastDay)
	}
	if !c.last && !c.nearest {
		return slices.Contains(c.days, day)
	}
	wanted := lastDay - c.offset
	if !c.last {
		wanted = c.days[0]
	}
	if wanted < 1 || wanted > lastDay {
		return false
	}
	if c.nearest {
		switch time.Date(year, month, wanted, 0, 0, 0, 0, time.UTC).Weekday() {
		case time.Saturday:
			if wanted == 1 {
				wanted += 2
			} else {
				wanted--
			}
		case time.Sunday:
			if wanted == lastDay {
				wanted -= 2
			} else {
				wanted++
			}
		}
	}
	return day == wanted
}

func (c calendar) next(after time.Time) (time.Time, bool) {
	location := c.location
	if location == nil {
		location = time.UTC
	}
	after = after.In(location)
	var earliest time.Time
	found := false
	for _, span := range c.years {
		year := span.start
		if lower := int64(after.Year()); year < lower {
			year += ((lower-year-1)/span.step + 1) * span.step
		}
		// The Gregorian calendar repeats every 400 years. Along a fixed
		// progression, at most 400 residues are distinct. Include one
		// extra year because the first search may start partway through it.
		for tried := 0; tried <= 400 && year <= span.end; tried, year = tried+1, year+span.step {
			if found && year > int64(earliest.In(location).Year()) {
				break
			}
			if candidate, ok := c.nextInYear(int(year), after); ok {
				if !found || candidate.Before(earliest) {
					earliest, found = candidate, true
				}
				break
			}
		}
	}
	return earliest, found
}

func (c calendar) nextInYear(year int, after time.Time) (time.Time, bool) {
	for _, value := range c.months {
		month := time.Month(value)
		if year == after.Year() && month < after.Month() {
			continue
		}
		lastDay := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
		for day := 1; day <= lastDay; day++ {
			if year == after.Year() && month == after.Month() && day < after.Day() || !c.matchesDay(year, month, day, lastDay) {
				continue
			}
			for _, hour := range c.hours {
				for _, minute := range c.minutes {
					for _, second := range c.seconds {
						candidate, exists := calendarInstant(year, month, day, hour, minute, second, c.location)
						if exists && candidate.After(after) {
							return candidate.UTC(), true
						}
					}
				}
			}
		}
	}
	return time.Time{}, false
}

// calendarInstant skips a nonexistent wall time and selects the earlier instant
// when a clock rollback repeats it. One calendar occurrence is never delivered
// twice just because the local clock repeats an hour.
func calendarInstant(year int, month time.Month, day, hour, minute, second int, location *time.Location) (time.Time, bool) {
	if location == nil || location == time.UTC {
		return time.Date(year, month, day, hour, minute, second, 0, time.UTC), true
	}
	wall := time.Date(year, month, day, hour, minute, second, 0, time.UTC)
	guess := time.Date(year, month, day, hour, minute, second, 0, location)
	var earliest time.Time
	found := false
	// Inspect both sides of a transition, including zones whose offset changes
	// by a half-hour or a full day rather than the usual hour.
	for _, delta := range [...]time.Duration{-48 * time.Hour, 0, 48 * time.Hour} {
		_, offset := guess.Add(delta).Zone()
		candidate := wall.Add(-time.Duration(offset) * time.Second).In(location)
		if candidate.Year() == year && candidate.Month() == month && candidate.Day() == day &&
			candidate.Hour() == hour && candidate.Minute() == minute && candidate.Second() == second &&
			(!found || candidate.Before(earliest)) {
			earliest, found = candidate, true
		}
	}
	return earliest, found
}
