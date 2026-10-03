package dynamodb

import (
	"fmt"
	"time"
)

const onDemandSwitchLimit = 4

func validateOnDemandSwitch(r Reader, key TableKey, now time.Time) error {
	switches, err := r.OnDemandSwitches(key)
	if err != nil {
		return err
	}
	if len(switches) == onDemandSwitchLimit {
		next := switches[0].Add(24 * time.Hour)
		if now.Before(next) {
			return failure("LimitExceededException", fmt.Sprintf("A table can switch from provisioned to on-demand billing mode four times in a rolling 24-hour window. Next switch can be made at %s", next.UTC().Format(time.RFC3339)))
		}
	}
	return nil
}

// Commit completed switches with table state, not when an external engine call
// is merely attempted. Pending intent already excludes competing transitions.
func recordOnDemandSwitch(tx Transaction, key TableKey, at time.Time) error {
	switches, err := tx.OnDemandSwitches(key)
	if err != nil {
		return err
	}
	if len(switches) == onDemandSwitchLimit {
		copy(switches, switches[1:])
		switches[len(switches)-1] = at
	} else {
		switches = append(switches, at)
	}
	return tx.PutOnDemandSwitches(key, switches)
}
