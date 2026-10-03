package scheduler_test

import (
	"testing"
	"time"

	"stackd/internal/awsschedule"
)

func instant(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSchedulerDSTGapAndFold(t *testing.T) {
	for _, tc := range []struct {
		name, expression, after, want string
	}{
		{
			"gap",
			"cron(30 2 * * ? *)",
			"2026-03-08T00:00:00Z",
			"2026-03-09T06:30:00Z",
		},
		{
			"first fold",
			"cron(30 1 * * ? *)",
			"2026-11-01T00:00:00Z",
			"2026-11-01T05:30:00Z",
		},
		{
			"skip repeated fold",
			"cron(30 1 * * ? *)",
			"2026-11-01T05:30:00Z",
			"2026-11-02T06:30:00Z",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := awsschedule.ParseScheduler(tc.expression, "America/New_York")
			if err != nil {
				t.Fatal(err)
			}
			next, ok := s.Next(instant(t, tc.after))
			if !ok || !next.Equal(instant(t, tc.want)) {
				t.Fatalf("next=%s found=%v; want %s", next, ok, tc.want)
			}
		})
	}
}

func TestSchedulerRateRetainsElapsedDayAndCalendarDialects(t *testing.T) {
	s, err := awsschedule.ParseScheduler("rate(1 days)", "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	after := instant(t, "2026-03-07T17:00:00Z")
	next, ok := s.Next(after)
	if !ok || !next.Equal(after.Add(24*time.Hour)) {
		t.Fatalf("rate drifted over DST: %s", next)
	}
	for _, expression := range []string{
		"cron(0 0 1 * ? 2200)",
		"cron(0 0 0 1 * ? *)",
		"cron(0 0 ? * 3#1,6#3 *)",
		"cron(0 0 1 * ? 2026junk)",
	} {
		if _, err := awsschedule.ParseScheduler(expression, "UTC"); err == nil {
			t.Fatalf("accepted invalid Scheduler expression %q", expression)
		}
	}
	if _, err := awsschedule.ParseEventBridge("cron(0 0 1 * ? 2200)"); err != nil {
		t.Fatalf("changed existing EventBridge dialect: %v", err)
	}
}
