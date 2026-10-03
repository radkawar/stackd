// Package awsschedule parses AWS service schedules using a shared calendar.
package awsschedule

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// Schedule is an immutable parsed cron calendar or fixed-rate recurrence.
// Its zero value has no occurrences.
type Schedule struct {
	calendar calendar
	seconds  int64
	at       time.Time
}

var errExpression = errors.New("invalid schedule expression")

// ParseBackup parses the Backup policy cron dialect, including its optional
// year and ignored fields after the year. Policy interval limits belong to the
// caller, not to the calendar.
func ParseBackup(expression string) (Schedule, error) {
	return parseCron(expression, backup)
}

// ParseEventBridge parses a classic EventBridge scheduled rule expression.
func ParseEventBridge(expression string) (Schedule, error) {
	if !strings.HasPrefix(expression, "rate(") {
		return parseCron(expression, eventBridge)
	}
	return parseRate(expression, eventBridge)
}

func parseRate(expression string, syntax dialect) (Schedule, error) {
	if !strings.HasSuffix(expression, ")") {
		return Schedule{}, errExpression
	}
	value, unit, found := strings.Cut(expression[5:len(expression)-1], " ")
	if !found || !digits(value) {
		return Schedule{}, errExpression
	}
	n, err := strconv.ParseInt(value, 10, 32)
	if err != nil || n < 1 {
		return Schedule{}, errExpression
	}
	if syntax == applicationAutoScaling {
		unit = strings.TrimSuffix(unit, "s")
	} else if n != 1 {
		if !strings.HasSuffix(unit, "s") {
			return Schedule{}, errExpression
		}
		unit = strings.TrimSuffix(unit, "s")
	}
	var seconds int64
	switch unit {
	case "minute":
		seconds = 60
	case "hour":
		seconds = 60 * 60
	case "day":
		seconds = 24 * 60 * 60
	default:
		return Schedule{}, errExpression
	}
	return Schedule{seconds: n * seconds}, nil
}

// ParseApplicationAutoScaling accepts at, rate, and six/seven-field cron
// expressions. An empty timezone means the API's omitted UTC default; callers
// must distinguish that from an explicitly supplied empty timezone.
func ParseApplicationAutoScaling(expression, timezone string) (Schedule, error) {
	location := time.UTC
	if timezone != "" {
		if timezone == "Local" {
			return Schedule{}, errExpression
		}
		var err error
		location, err = time.LoadLocation(timezone)
		if err != nil {
			return Schedule{}, errExpression
		}
	}
	if strings.HasPrefix(expression, "rate(") {
		return parseRate(expression, applicationAutoScaling)
	}
	if strings.HasPrefix(expression, "at(") {
		if !strings.HasSuffix(expression, ")") {
			return Schedule{}, errExpression
		}
		text := expression[3 : len(expression)-1]
		const layout = "2006-01-02T15:04:05"
		wall, err := time.Parse(layout, text)
		if err != nil || wall.Format(layout) != text {
			return Schedule{}, errExpression
		}
		at, exists := calendarInstant(wall.Year(), wall.Month(), wall.Day(), wall.Hour(), wall.Minute(), wall.Second(), location)
		if !exists {
			return Schedule{}, errExpression
		}
		return Schedule{at: at.UTC()}, nil
	}
	schedule, err := parseCron(expression, applicationAutoScaling)
	if err != nil {
		return Schedule{}, err
	}
	schedule.calendar.location = location
	return schedule, nil
}

// ParseScheduler accepts Scheduler's six-field cron, at, and rate expressions.
// Local wall times use the same gap-skipping and first-fold calendar as scaling.
func ParseScheduler(expression, timezone string) (Schedule, error) {
	location := time.UTC
	if timezone != "" {
		if timezone == "Local" {
			return Schedule{}, errExpression
		}
		var err error
		location, err = time.LoadLocation(timezone)
		if err != nil {
			return Schedule{}, errExpression
		}
	}
	if strings.HasPrefix(expression, "rate(") {
		return parseRate(expression, applicationAutoScaling)
	}
	if strings.HasPrefix(expression, "at(") {
		if !strings.HasSuffix(expression, ")") {
			return Schedule{}, errExpression
		}
		text := expression[3 : len(expression)-1]
		const layout = "2006-01-02T15:04:05"
		wall, err := time.Parse(layout, text)
		if err != nil || wall.Format(layout) != text {
			return Schedule{}, errExpression
		}
		at, exists := calendarInstant(wall.Year(), wall.Month(), wall.Day(), wall.Hour(), wall.Minute(), wall.Second(), location)
		if !exists {
			// Native Scheduler admits at-expressions in DST gaps. Unlike
			// scaling, admission is separate from occurrence existence.
			// TODO: Comeback calibrate enabled at-in-gap execution; the native fixture proves admission only.
			return Schedule{}, nil
		}
		return Schedule{at: at.UTC()}, nil
	}
	schedule, err := parseCron(expression, eventBridgeScheduler)
	if err != nil {
		return Schedule{}, err
	}
	schedule.calendar.location = location
	return schedule, nil
}

// First anchors a rate at the current whole UTC service second. A cron's first
// occurrence is strictly after at. These are logical deadlines, not delivery
// jitter guarantees.
func (s Schedule) First(at time.Time) (time.Time, bool) {
	if s.seconds != 0 {
		return at.UTC().Truncate(time.Second), true
	}
	return s.Next(at)
}

// Next returns an occurrence strictly after after, or false for an exhausted
// calendar. Rate arithmetic uses integer seconds rather than time.Duration so
// even the admitted int32 maximum number of days cannot overflow a duration.
func (s Schedule) Next(after time.Time) (time.Time, bool) {
	if !s.at.IsZero() {
		return s.at, s.at.After(after)
	}
	if s.seconds != 0 {
		return time.Unix(after.Unix()+s.seconds, 0).UTC(), true
	}
	return s.calendar.next(after)
}

// NextAfter advances a retained occurrence past a horizon without replaying
// missed work. Rates retain their original phase rather than drifting to the
// drain time; calendar recurrences use the shared local-time calendar.
func (s Schedule) NextAfter(occurrence, horizon time.Time) (time.Time, bool) {
	if horizon.Before(occurrence) {
		horizon = occurrence
	}
	if s.seconds != 0 {
		elapsed := horizon.Unix() - occurrence.Unix()
		return time.Unix(occurrence.Unix()+(elapsed/s.seconds+1)*s.seconds, 0).UTC(), true
	}
	return s.Next(horizon)
}

func digits(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}
