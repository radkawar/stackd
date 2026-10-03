package dynamodb

import (
	"slices"
	"sync"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/dynamodb"
)

// capacityAdmission owns a deterministic service-time burst envelope, not AWS's
// private global/physical-partition allocation. The caller must hold the native
// database data gate across check, the real operation, and consume, including
// reads. This mutex protects counters across databases, never an engine call.
// TODO: Comeback to physical-partition and default on-demand quota admission.
type capacityAdmission struct {
	mu     sync.Mutex
	clock  clock.Clock
	tables map[TableKey]*capacityTableBudget
}

type capacityTableBudget struct {
	generation   string
	lastOnDemand time.Time
	provisioned  bool
	updated      time.Time
	base         capacityResourceBudget
	indexes      map[string]capacityResourceBudget
}

type capacityResourceBudget struct {
	read, write capacityDirectionBudget
}

type capacityDirectionBudget struct {
	rate, balance float64
	initialized   bool
}

func newCapacityAdmission(source clock.Clock) *capacityAdmission {
	return &capacityAdmission{clock: source, tables: make(map[TableKey]*capacityTableBudget)}
}

func provisionedTable(table *TableRecord) bool {
	return table != nil && (table.Data.BillingModeSummary == nil || value(table.Data.BillingModeSummary.BillingMode) == "PROVISIONED")
}

func onDemandRate(capacity *api.OnDemandThroughput, write bool) float64 {
	if capacity == nil {
		return 0
	}
	units := capacity.MaxReadRequestUnits
	if write {
		units = capacity.MaxWriteRequestUnits
	}
	if units == nil || *units == -1 {
		return 0
	}
	return float64(*units)
}

func capacityLimited(table *TableRecord, write bool) bool {
	if table == nil {
		return false
	}
	if provisionedTable(table) || onDemandRate(table.Data.OnDemandThroughput, write) > 0 {
		return true
	}
	for _, index := range table.Data.GlobalSecondaryIndexes {
		if onDemandRate(index.OnDemandThroughput, write) > 0 {
			return true
		}
	}
	return false
}

func (a *capacityAdmission) observe(table *TableRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tableBudget(table, a.clock.Now())
}

func (a *capacityAdmission) check(table *TableRecord, index string, write bool) []api.IndexName {
	a.mu.Lock()
	defer a.mu.Unlock()
	budget := a.tableBudget(table, a.clock.Now())
	if budget == nil {
		return nil
	}
	if !write {
		resource := budget.base
		name := ""
		if global, ok := budget.indexes[index]; ok {
			resource, name = global, index
		}
		if resource.read.blocked() {
			return []api.IndexName{api.IndexName(name)}
		}
		return nil
	}

	var blocked []api.IndexName
	if budget.base.write.blocked() {
		blocked = append(blocked, "")
	}
	// Every current GSI participates in write backpressure, even if the actual
	// completed write will leave that index's projection unchanged.
	for name, resource := range budget.indexes {
		if resource.write.blocked() {
			blocked = append(blocked, api.IndexName(name))
		}
	}
	slices.Sort(blocked)
	return blocked
}

// coversReadBatch keeps one native call when every processed key fits. A
// singleton only needs positive credit, like other admitted operations; a larger
// batch that cannot fit is admitted key by key using actual native charges.
func (a *capacityAdmission) coversReadBatch(table *TableRecord, units float64, count int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	budget := a.tableBudget(table, a.clock.Now())
	if budget == nil {
		return true
	}
	read := budget.base.read
	return !read.blocked() && (read.rate == 0 || count <= 1 || units <= read.balance)
}

func (a *capacityAdmission) consume(table *TableRecord, index string, units consumedUnits) {
	a.mu.Lock()
	defer a.mu.Unlock()
	budget := a.tableBudget(table, a.clock.Now())
	if budget == nil {
		return
	}
	if index == "" {
		budget.base.consume(units)
		return
	}
	if resource, ok := budget.indexes[index]; ok {
		resource.consume(units)
		budget.indexes[index] = resource
	}
}

// preview copies only this plan's current resources. The caller retains the
// native data gate while selecting siblings and charging actual completions;
// changes to this scratch owner never reserve or commit live credits.
func (a *capacityAdmission) preview(plan *dataPlan) *capacityAdmission {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.clock.Now()
	preview := newCapacityAdmission(a.clock)
	copyTable := func(table *TableRecord) {
		budget := a.tableBudget(table, now)
		if budget == nil {
			return
		}
		copied := *budget
		if budget.indexes != nil {
			copied.indexes = make(map[string]capacityResourceBudget, len(budget.indexes))
			for name, resource := range budget.indexes {
				copied.indexes[name] = resource
			}
		}
		preview.tables[table.Key] = &copied
	}
	if plan != nil {
		copyTable(plan.table)
		for _, table := range plan.additional {
			copyTable(table)
		}
	}
	return preview
}

func (a *capacityAdmission) forgetTable(key TableKey) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.tables, key)
}

// tableBudget reconciles current metadata and refills while a.mu is held. A
// PAY_PER_REQUEST transition timestamp also detects mode round trips without
// intervening data calls, so old provisioned debt cannot survive them.
func (a *capacityAdmission) tableBudget(table *TableRecord, now time.Time) *capacityTableBudget {
	if table == nil {
		return nil
	}
	if !capacityLimited(table, false) && !capacityLimited(table, true) {
		delete(a.tables, table.Key)
		return nil
	}
	var lastOnDemand time.Time
	if summary := table.Data.BillingModeSummary; summary != nil && summary.LastUpdateToPayPerRequestDateTime != nil {
		lastOnDemand = *summary.LastUpdateToPayPerRequestDateTime
	}
	generation := value(table.Data.TableId)
	provisioned := provisionedTable(table)
	budget := a.tables[table.Key]
	if budget == nil || budget.generation != generation || budget.provisioned != provisioned || !budget.lastOnDemand.Equal(lastOnDemand) {
		budget = &capacityTableBudget{generation: generation, lastOnDemand: lastOnDemand, provisioned: provisioned, updated: now}
		a.tables[table.Key] = budget
	}
	elapsed := 0.0
	if now.After(budget.updated) {
		elapsed = now.Sub(budget.updated).Seconds()
		budget.updated = now
	}
	budget.base.refresh(table.Data.ProvisionedThroughput, table.Data.OnDemandThroughput, provisioned, elapsed)
	for _, index := range table.Data.GlobalSecondaryIndexes {
		name := value(index.IndexName)
		resource := budget.indexes[name]
		resource.refresh(index.ProvisionedThroughput, index.OnDemandThroughput, provisioned, elapsed)
		if budget.indexes == nil {
			budget.indexes = make(map[string]capacityResourceBudget, len(table.Data.GlobalSecondaryIndexes))
		}
		budget.indexes[name] = resource
	}
	// Ordinary checks need no allocation or index reconciliation scan. Removed
	// names are pruned only when current metadata no longer accounts for them.
	if len(budget.indexes) > len(table.Data.GlobalSecondaryIndexes) {
		for name := range budget.indexes {
			current := false
			for _, index := range table.Data.GlobalSecondaryIndexes {
				if value(index.IndexName) == name {
					current = true
					break
				}
			}
			if !current {
				delete(budget.indexes, name)
			}
		}
	}
	return budget
}

func (b *capacityResourceBudget) refresh(capacity *api.ProvisionedThroughputDescription, onDemand *api.OnDemandThroughput, provisioned bool, elapsed float64) {
	var read, write float64
	if !provisioned {
		read, write = onDemandRate(onDemand, false), onDemandRate(onDemand, true)
	} else if capacity != nil {
		if capacity.ReadCapacityUnits != nil {
			read = float64(*capacity.ReadCapacityUnits)
		}
		if capacity.WriteCapacityUnits != nil {
			write = float64(*capacity.WriteCapacityUnits)
		}
	}
	b.read.refresh(read, elapsed)
	b.write.refresh(write, elapsed)
}

func (b *capacityDirectionBudget) refresh(rate, elapsed float64) {
	if rate == 0 {
		*b = capacityDirectionBudget{}
		return
	}
	// Refill at the previously observed rate before adopting a throughput
	// change. Only surplus is clamped; completed-operation debt is retained.
	b.balance = min(b.balance+elapsed*b.rate, 300*b.rate)
	if !b.initialized && rate > 0 {
		b.balance = 300 * rate
		b.initialized = true
	}
	b.rate = rate
	b.balance = min(b.balance, 300*rate)
}

func (b capacityDirectionBudget) blocked() bool {
	return b.rate > 0 && b.balance <= 0
}

func (b *capacityResourceBudget) consume(units consumedUnits) {
	// Admission requires positive credit, not an estimate of the entire cost.
	// Actual completion may create per-operation debt, allowing an operation
	// larger than the five-minute bank without ever rejecting its effects.
	if b.read.rate > 0 && units.read > 0 {
		b.read.balance -= units.read
	}
	if b.write.rate > 0 && units.write > 0 {
		b.write.balance -= units.write
	}
}
