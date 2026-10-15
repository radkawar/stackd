package elbv2

import (
	"context"
	"sort"
	"sync"
)

// Each group owns its draw sequence. Traffic to another group or account must
// not bias a group's distribution (a single shared counter can starve targets).
// The zero value is ready for use by a runtimeController.
type targetRoundRobin struct {
	mu   sync.Mutex
	next map[targetRotationKey]uint64
}

type targetRotationKey struct {
	Scope
	groupARN string
}

func (r *targetRoundRobin) draw(scope Scope, groupARN string, count int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.next == nil {
		r.next = make(map[targetRotationKey]uint64)
	}
	key := targetRotationKey{scope, groupARN}
	n := r.next[key]
	r.next[key] = n + 1
	return int(n % uint64(count))
}

func (r *targetRoundRobin) forget(scope Scope, groupARN string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.next, targetRotationKey{scope, groupARN})
}

func (r *runtimeController) selectTarget(ctx context.Context, scope Scope, groupARN string) (TargetRecord, TargetGroupRecord, TargetEndpoint, error) {
	var group TargetGroupRecord
	var candidates []TargetRecord
	err := r.service.repository.View(ctx, func(tx Reader) error {
		var e error
		group, e = tx.TargetGroup(scope, groupARN)
		if e != nil {
			return e
		}
		candidates, e = tx.Targets(scope, groupARN)
		return e
	})
	if err != nil {
		return TargetRecord{}, group, TargetEndpoint{}, err
	}
	// Stable membership order, independent of the repository implementation.
	sort.Slice(candidates, func(i, j int) bool {
		if value(candidates[i].Data.Id) != value(candidates[j].Data.Id) {
			return value(candidates[i].Data.Id) < value(candidates[j].Data.Id)
		}
		return targetPort(candidates[i].Data) < targetPort(candidates[j].Data)
	})
	type resolvedTarget struct {
		target   TargetRecord
		endpoint TargetEndpoint
	}
	eligible := make([]resolvedTarget, 0, len(candidates))
	// Count only current, enabled identities. A stale healthy row must neither
	// mask fail-open nor weight a surviving target multiple times per rotation.
	// Cross-zone is inherited from the always-enabled ALB policy: no caller-zone
	// restriction, cookie affinity, slow-start ramp or anomaly weighting applies.
	for _, state := range [...]string{"healthy", "unhealthy"} {
		for _, target := range candidates {
			if target.State != state {
				continue
			}
			endpoint, e := r.service.networks.ResolveTarget(ctx, scope, value(group.Data.VpcId), value(group.Data.TargetType), value(target.Data.Id))
			if e != nil || !targetEndpointMatches(target.Scope, value(group.Data.TargetType), value(target.Data.Id), target.OwnerARN, target.Incarnation, endpoint) {
				continue
			}
			if _, e := targetAddress(endpoint); e != nil {
				continue
			}
			enabled, e := r.targetEnabled(ctx, group, target, endpoint)
			if e != nil {
				return TargetRecord{}, group, TargetEndpoint{}, e
			}
			if enabled {
				eligible = append(eligible, resolvedTarget{target, endpoint})
			}
		}
		if len(eligible) > 0 {
			selected := eligible[r.targetRotation.draw(scope, groupARN, len(eligible))]
			return selected.target, group, selected.endpoint, nil
		}
	}
	// Initial, unused and draining registrations never receive new requests.
	return TargetRecord{}, group, TargetEndpoint{}, ErrNotFound
}
