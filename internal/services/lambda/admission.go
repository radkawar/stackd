package lambda

import "stackd/internal/awswire"

func checkSynchronousPayloadSize(payload []byte) *awswire.Error {
	if len(payload) > sourceEventLimit {
		return failure("RequestTooLargeException", "Request payload exceeds 6 MB.", 413)
	}
	return nil
}

// These counts describe actual admitted work, not retained permits. Reservation
// mutations reclassify running calls while holding the same service lock.
type concurrencyUsage struct {
	running, unreserved int
	functions           map[string]*functionConcurrencyUsage
}
type functionConcurrencyUsage struct {
	running     int
	reserved    bool
	provisioned map[string]int
}

func concurrencyThrottle(reserved bool) *awswire.Error {
	reason := "ConcurrentInvocationLimitExceeded"
	if reserved {
		reason = "ReservedFunctionConcurrentInvocationLimitExceeded"
	}
	return &awswire.Error{Code: "TooManyRequestsException", Message: "Rate Exceeded.", StatusCode: 429, Reason: reason, Type: "User"}
}

// admitInvocation runs with Service.mu held. Its reader belongs to the current
// repository transaction. A successful admission must be released by its caller;
// zero identifies the distinct asynchronous zero-reservation discard contract.
func (s *Service) admitInvocation(r Reader, deployment FunctionVersionKey, ref FunctionReference) (zero bool, wire *awswire.Error) {
	key := deployment.FunctionKey
	if wire := s.checkRecursion(r, key); wire != nil {
		return false, wire
	}
	reserved, present, err := r.FunctionConcurrency(key)
	if err != nil {
		return false, wireError(err)
	}
	if present && reserved == 0 {
		return true, concurrencyThrottle(true)
	}
	usage := s.inFlight[key.Scope]
	if usage != nil {
		if function := usage.functions[key.Name]; present && function != nil && function.running >= int(reserved) {
			return false, concurrencyThrottle(true)
		}
		if usage.running >= lambdaConcurrentExecutions {
			return false, concurrencyThrottle(false)
		}
	}
	provisionedSlot := s.provisionedExecutionLocked(deployment, ref)
	if !present && usage != nil && usage.unreserved >= lambdaUnreservedMinimum {
		rows, err := r.AllProvisionedConcurrency()
		if err != nil {
			return false, wireError(err)
		}
		account, err := r.AccountUsage(key.Scope)
		if err != nil {
			return false, wireError(err)
		}
		available := lambdaConcurrentExecutions - account.ReservedConcurrency
		onDemand := usage.unreserved
		needsUnreserved := true
		for _, row := range rows {
			if row.Key.Scope != key.Scope {
				continue
			}
			_, reserved, err := r.FunctionConcurrency(row.Key.FunctionKey)
			if err != nil {
				return false, wireError(err)
			}
			if reserved {
				continue
			}
			available -= int64(row.Requested)
			active := 0
			if function := usage.functions[row.Key.Name]; function != nil {
				active = function.provisioned[row.Key.Qualifier]
				onDemand -= min(active, int(row.Requested))
			}
			if provisionedSlot != nil && row.Key == provisionedSlot.provisioned && active < int(row.Requested) {
				needsUnreserved = false
			}
		}
		if needsUnreserved && int64(onDemand) >= available {
			return false, concurrencyThrottle(false)
		}
	}
	if usage == nil {
		usage = &concurrencyUsage{functions: map[string]*functionConcurrencyUsage{}}
		s.inFlight[key.Scope] = usage
	}
	function := usage.functions[key.Name]
	if function == nil {
		function = &functionConcurrencyUsage{reserved: present}
		usage.functions[key.Name] = function
	}
	if provisionedSlot != nil {
		if function.provisioned == nil {
			function.provisioned = make(map[string]int)
		}
		function.provisioned[provisionedSlot.provisioned.Qualifier]++
	}
	function.running++
	usage.running++
	if !function.reserved {
		usage.unreserved++
	}
	return false, nil
}

// reservationChanged runs after a successful reservation commit, with Service.mu
// held. An existing invocation keeps running but occupies its current pool.
func (s *Service) reservationChanged(key FunctionKey, present bool) {
	usage := s.inFlight[key.Scope]
	if usage == nil {
		return
	}
	function := usage.functions[key.Name]
	if function == nil || function.reserved == present {
		return
	}
	if present {
		usage.unreserved -= function.running
	} else {
		usage.unreserved += function.running
	}
	function.reserved = present
}

func (s *Service) releaseInvocation(key FunctionKey, slot *execution) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releaseInvocationLocked(key, slot)
}

func (s *Service) releaseInvocationLocked(key FunctionKey, slot *execution) {
	usage := s.inFlight[key.Scope]
	function := usage.functions[key.Name]
	usage.running--
	function.running--
	if slot != nil && slot.provisionedGeneration != "" {
		qualifier := slot.provisioned.Qualifier
		function.provisioned[qualifier]--
		if function.provisioned[qualifier] == 0 {
			delete(function.provisioned, qualifier)
		}
	}
	if !function.reserved {
		usage.unreserved--
	}
	if function.running == 0 {
		delete(usage.functions, key.Name)
	}
	if usage.running == 0 {
		delete(s.inFlight, key.Scope)
	}
}
