package guardduty

import "time"

const findingRetention = 90 * 24 * time.Hour

func findingExpires(f Finding) time.Time {
	// TODO: Comeback calibrate the native retention timestamp anchor. AWS
	// documents a 90-day maximum but not whether aggregation resets it. Cap
	// local retention from creation; feedback and archival cannot extend it.
	return f.Created.Add(findingRetention)
}

func findingExpired(f Finding, now time.Time) bool {
	return !findingExpires(f).After(now)
}
