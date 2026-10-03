package organizations

import (
	"stackd/internal/awsschedule"
	"time"
)

// Native Backup admission classifies the next two occurrences, rather than the
// smallest interval over every possible future date.
func backupScheduleInterval(expression string, now time.Time) (time.Duration, bool) {
	calendar, err := awsschedule.ParseBackup(expression)
	if err != nil {
		return 0, false
	}
	first, ok := calendar.Next(now)
	if !ok {
		return 0, false
	}
	second, ok := calendar.Next(first)
	if !ok {
		return 0, false
	}
	return second.Sub(first), true
}
