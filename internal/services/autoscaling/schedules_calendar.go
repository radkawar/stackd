package autoscaling

import (
	"strconv"
	"strings"
	"time"

	"stackd/internal/awsschedule"
)

// EC2 Auto Scaling uses five-field Unix cron (Sunday 0), not the
// six-field AWS cron dialect (Sunday 1). Calendar traversal, timezone gaps and
// folds remain owned by awsschedule. Two calendars implement Unix's OR rule
// when both month-day and weekday are restricted.
type recurringSchedule struct {
	calendars    []awsschedule.Schedule
	intersection bool
}

func parseRecurrence(expression, zone string) (recurringSchedule, error) {
	fields := strings.Fields(expression)
	if len(fields) != 5 || strings.ContainsAny(expression, "?#()") {
		return recurringSchedule{}, invalid("Recurrence must be a valid five-field cron expression")
	}
	if strings.ContainsAny(fields[2], "LWlw") {
		return recurringSchedule{}, invalid("Recurrence must use Unix cron day-of-month syntax")
	}
	weekday, err := unixWeekdays(fields[4])
	if err != nil {
		return recurringSchedule{}, err
	}
	var expressions []string
	if fields[4] == "*" {
		expressions = []string{strings.Join([]string{fields[0], fields[1], fields[2], fields[3], "?", "*"}, " ")}
	} else if fields[2] == "*" {
		expressions = []string{strings.Join([]string{fields[0], fields[1], "?", fields[3], weekday, "*"}, " ")}
	} else {
		expressions = []string{strings.Join([]string{fields[0], fields[1], fields[2], fields[3], "?", "*"}, " "), strings.Join([]string{fields[0], fields[1], "?", fields[3], weekday, "*"}, " ")}
	}
	out := recurringSchedule{intersection: len(expressions) == 2 && (strings.HasPrefix(fields[2], "*") || strings.HasPrefix(fields[4], "*"))}
	for _, expression := range expressions {
		parsed, err := awsschedule.ParseApplicationAutoScaling("cron("+expression+")", zone)
		if err != nil {
			return recurringSchedule{}, invalid("Recurrence or TimeZone is invalid")
		}
		out.calendars = append(out.calendars, parsed)
	}
	return out, nil
}

func unixWeekdays(field string) (string, error) {
	if field == "*" {
		return "*", nil
	}
	var selected [7]bool
	names := []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}
	number := func(s string) (int, error) {
		for i, name := range names {
			if strings.EqualFold(s, name) {
				return i, nil
			}
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 7 {
			return 0, invalid("Invalid cron weekday")
		}
		return n, nil
	}
	for part := range strings.SplitSeq(field, ",") {
		base, stepText, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			var err error
			step, err = strconv.Atoi(stepText)
			if err != nil || step < 1 || step > 7 {
				return "", invalid("Invalid cron weekday step")
			}
		}
		lo, hi := 0, 6
		if base != "*" {
			left, right, rangeSet := strings.Cut(base, "-")
			var err error
			lo, err = number(left)
			if err != nil {
				return "", err
			}
			hi = lo
			if rangeSet {
				hi, err = number(right)
				if err != nil {
					return "", err
				}
			} else if hasStep {
				hi = 6
			}
			if hi < lo {
				return "", invalid("Invalid cron weekday range")
			}
		}
		for n := lo; n <= hi; n += step {
			selected[n%7] = true
		}
	}
	var values []string
	for n, yes := range selected {
		if yes {
			values = append(values, strconv.Itoa(n+1))
		}
	}
	if len(values) == 0 {
		return "", invalid("Invalid cron weekday")
	}
	return strings.Join(values, ","), nil
}

func (s recurringSchedule) next(after time.Time) (time.Time, bool) {
	if s.intersection {
		a, aOK := s.calendars[0].Next(after)
		b, bOK := s.calendars[1].Next(after)
		for aOK && bOK {
			if a.Equal(b) {
				return a, true
			}
			if a.Before(b) {
				a, aOK = s.calendars[0].Next(b.Add(-time.Nanosecond))
			} else {
				b, bOK = s.calendars[1].Next(a.Add(-time.Nanosecond))
			}
		}
		return time.Time{}, false
	}
	var first time.Time
	found := false
	for _, calendar := range s.calendars {
		next, exists := calendar.Next(after)
		if exists && (!found || next.Before(first)) {
			first = next
			found = true
		}
	}
	return first, found
}
