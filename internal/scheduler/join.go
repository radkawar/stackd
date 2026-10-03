package scheduler

import (
	"context"
	"errors"
)

// Join gives independent drivers one execution order and lifetime. Call it once
// for each driver during service assembly before starting workers, without
// concurrent driver calls.
// Sources retain their supplied order; all services must use the first driver's
// clock. Wake, RunDue and Close through any joined handle affect the whole group.
// If read is non-nil, each complete selection scan uses its callback context.
// It must release the read snapshot before returning, allowing Run to write.
// A nil read leaves sources responsible for their own selection transactions.
func Join(read func(context.Context, func(context.Context) error) error, drivers ...*Driver) (*Driver, error) {
	if len(drivers) == 0 {
		return nil, errors.New("at least one job driver is required")
	}
	seen := make(map[*execution]bool, len(drivers))
	for _, driver := range drivers {
		if driver == nil || driver.execution == nil {
			return nil, errors.New("job driver is required")
		}
		if driver.started || driver.closed {
			return nil, errors.New("job drivers must be joined before startup or shutdown")
		}
		if seen[driver.execution] {
			return nil, errors.New("job driver is already included in the group")
		}
		seen[driver.execution] = true
	}
	shared := drivers[0].execution
	shared.read = read
	for _, driver := range drivers[1:] {
		shared.sources = append(shared.sources, driver.sources...)
		driver.cancel()
		driver.execution = shared
	}
	return drivers[0], nil
}
