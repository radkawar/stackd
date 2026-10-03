package secretsmanager

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awsschedule"
)

// rotationSchedule applies the Secrets Manager window restrictions to the shared
// AWS calendar. end is exclusive internally; NextRotationDate is end minus 1s.
type rotationSchedule struct {
	calendar awsschedule.Schedule
	interval time.Duration
	duration time.Duration
	hourly   bool
}

func rotationRules(previous, requested *api.RotationRulesType) (*api.RotationRulesType, error) {
	rules := &api.RotationRulesType{}
	if previous != nil {
		*rules = *previous
	}
	if requested != nil {
		if requested.AutomaticallyAfterDays != nil && requested.ScheduleExpression != nil {
			return nil, failure("InvalidParameterException", "Specify AutomaticallyAfterDays or ScheduleExpression, but not both.")
		}
		if requested.AutomaticallyAfterDays != nil {
			rules.AutomaticallyAfterDays = requested.AutomaticallyAfterDays
			rules.ScheduleExpression = nil
		}
		if requested.ScheduleExpression != nil {
			rules.ScheduleExpression = requested.ScheduleExpression
			rules.AutomaticallyAfterDays = nil
		}
		if requested.Duration != nil {
			rules.Duration = requested.Duration
		}
	}
	if rules.AutomaticallyAfterDays == nil && rules.ScheduleExpression == nil {
		rules.AutomaticallyAfterDays = ptr(api.AutomaticallyRotateAfterDaysType(30))
	}
	if _, err := parseRotationSchedule(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func parseRotationSchedule(rules *api.RotationRulesType) (rotationSchedule, error) {
	var schedule rotationSchedule
	invalid := func() (rotationSchedule, error) {
		return rotationSchedule{}, failure("InvalidParameterException", "The rotation schedule or rotation window is invalid.")
	}
	if rules == nil {
		return invalid()
	}
	if rules.Duration != nil {
		duration := value(rules.Duration)
		if len(duration) < 2 || len(duration) > 3 || !strings.HasSuffix(duration, "h") {
			return invalid()
		}
		for _, ch := range duration[:len(duration)-1] {
			if ch < '0' || ch > '9' {
				return invalid()
			}
		}
		hours, err := strconv.Atoi(duration[:len(duration)-1])
		if err != nil || hours < 1 || hours > 24 {
			return invalid()
		}
		schedule.duration = time.Duration(hours) * time.Hour
	}
	expression := value(rules.ScheduleExpression)
	if rules.ScheduleExpression == nil {
		if rules.AutomaticallyAfterDays == nil || *rules.AutomaticallyAfterDays < 1 || *rules.AutomaticallyAfterDays > 999 {
			return invalid()
		}
		days := int64(*rules.AutomaticallyAfterDays)
		unit := "days"
		if days == 1 {
			unit = "day"
		}
		expression = fmt.Sprintf("rate(%d %s)", days, unit)
	}
	if len(expression) > 256 {
		return invalid()
	}
	if strings.HasPrefix(expression, "rate(") && strings.HasSuffix(expression, ")") {
		fields := strings.Fields(expression[5 : len(expression)-1])
		if len(fields) != 2 {
			return invalid()
		}
		n, err := strconv.ParseInt(fields[0], 10, 32)
		if err != nil || n < 1 {
			return invalid()
		}
		switch strings.TrimSuffix(fields[1], "s") {
		case "hour":
			if n < 4 || n > 999*24 {
				return invalid()
			}
			schedule.interval, schedule.hourly = time.Duration(n)*time.Hour, true
		case "day":
			if n > 999 {
				return invalid()
			}
			schedule.interval = time.Duration(n) * 24 * time.Hour
		default:
			return invalid()
		}
	} else {
		if !strings.HasPrefix(expression, "cron(") || !strings.HasSuffix(expression, ")") {
			return invalid()
		}
		fields := strings.Fields(expression[5 : len(expression)-1])
		if len(fields) != 6 || fields[0] != "0" || fields[5] != "*" {
			return invalid()
		}
		// The documented /8 shorthand means 0/8. Calendar evaluation still
		// belongs to awsschedule, including hour increments and day modifiers.
		if strings.HasPrefix(fields[1], "/") {
			fields[1] = "0" + fields[1]
		}
		expression = "cron(" + strings.Join(fields, " ") + ")"
		hours, err := awsschedule.ParseEventBridge("cron(0 " + fields[1] + " * * ? *)")
		if err != nil {
			return invalid()
		}
		base := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		first, ok := hours.Next(base.Add(-time.Second))
		if !ok {
			return invalid()
		}
		second, ok := hours.Next(first)
		if !ok {
			return invalid()
		}
		schedule.hourly = second.Before(base.Add(24 * time.Hour))
		for at := first; at.Before(base.Add(24 * time.Hour)); {
			next, ok := hours.Next(at)
			if !ok || next.Sub(at) < 4*time.Hour || schedule.end(at).After(next) || schedule.end(at).After(at.Truncate(24*time.Hour).Add(24*time.Hour)) {
				return invalid()
			}
			at = next
		}
	}
	calendar, err := awsschedule.ParseEventBridge(expression)
	if err != nil {
		return invalid()
	}
	schedule.calendar = calendar
	if schedule.interval > 0 {
		// Check every distinct UTC hour of the rate's phase. A fixed rate may
		// cross midnight, but its individual rotation windows may not.
		base := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		at := base
		for {
			next, _ := calendar.Next(at)
			if schedule.end(at).After(next) || schedule.end(at).After(at.Truncate(24*time.Hour).Add(24*time.Hour)) {
				return invalid()
			}
			at = next
			if at.Hour() == 0 {
				break
			}
		}
	}
	return schedule, nil
}

func (schedule rotationSchedule) end(start time.Time) time.Time {
	if schedule.duration != 0 {
		return start.Add(schedule.duration)
	}
	if schedule.hourly {
		return start.Add(time.Hour)
	}
	return start.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
}

func (schedule rotationSchedule) next(anchor, after time.Time) (time.Time, bool) {
	if schedule.interval == 0 {
		return schedule.calendar.Next(after)
	}
	// Rate windows are anchored at midnight, not the API request's minute.
	first, _ := schedule.calendar.Next(anchor.UTC().Truncate(24 * time.Hour))
	if first.After(after) {
		return first, true
	}
	return schedule.calendar.NextAfter(first, after)
}

func setRotationSchedule(secret *SecretRecord, schedule rotationSchedule, anchor, after time.Time) error {
	due, ok := schedule.next(anchor, after)
	if !ok {
		return failure("InvalidParameterException", "The rotation schedule has no future occurrence.")
	}
	return setRotationWindow(secret, schedule, due, after)
}

func setRotationWindow(secret *SecretRecord, schedule rotationSchedule, due, after time.Time) error {
	if schedule.interval == 0 && due.Sub(after) > 366*24*time.Hour {
		return failure("InvalidParameterException", "The rotation schedule must have an occurrence within one year.")
	}
	end := schedule.end(due).Add(-time.Second)
	secret.RotationDue, secret.NextRotation = &due, &end
	if secret.RotationRules.ScheduleExpression != nil {
		days := int64((due.Sub(after) + 24*time.Hour - 1) / (24 * time.Hour))
		if schedule.interval != 0 {
			days = int64((schedule.interval + 24*time.Hour - 1) / (24 * time.Hour))
		}
		secret.RotationRules.AutomaticallyAfterDays = ptr(api.AutomaticallyRotateAfterDaysType(max(1, days)))
	}
	return nil
}

// noteSecretRotation updates the next window after a genuine current-value
// write. The caller owns persistence and replica propagation in its transaction.
func (s *Service) noteSecretRotation(_ Transaction, secret *SecretRecord, now time.Time) error {
	secret.LastRotated = &now
	if secret.RotationEnabled == nil || !*secret.RotationEnabled {
		return nil
	}
	schedule, err := parseRotationSchedule(secret.RotationRules)
	if err != nil {
		return err
	}
	return setRotationSchedule(secret, schedule, now, now)
}
