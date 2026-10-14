package rds

// AllocatedStorage retains a general-purpose storage capacity request. The native
// runtime has no quota/resize API: this is not a physical allocation promise.
// https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html
func validateAllocatedStorage(capacity int32) error {
	if capacity < 20 || capacity > 65536 {
		return failure("InvalidParameterValue", "AllocatedStorage must be between 20 and 65536 GiB.")
	}
	return nil
}

// AWS rounds increases smaller than ten percent up, but does not allow shrinking.
// https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html
// TODO: Comeback add a real maintenance-window owner before admitting deferred
// capacity changes; add an actual volume quota/resize owner before claiming
// physical capacity enforcement.
func modifiedAllocatedStorage(current, requested int32) (int32, error) {
	if err := validateAllocatedStorage(requested); err != nil {
		return 0, err
	}
	if requested < current {
		return 0, failure("InvalidParameterValue", "AllocatedStorage cannot be decreased.")
	}
	if current != 0 && requested != current {
		minimum := current + (current+9)/10
		if requested < minimum {
			requested = minimum
		}
		if err := validateAllocatedStorage(requested); err != nil {
			return 0, err
		}
	}
	return requested, nil
}
