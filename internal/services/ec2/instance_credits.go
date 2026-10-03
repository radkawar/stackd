package ec2

import (
	"context"
	"errors"
	"math"
	"math/bits"
	"strings"
	"time"

	native "stackd/compute/ec2"
	api "stackd/internal/awsapi/ec2"
)

// InstanceCreditRecord belongs to the instance, not a separate usage ledger.
// Balances use vCPU nanoseconds: one AWS CPU credit is one vCPU-minute.
// NativePID/NativeStartTimeTicks identify the VMM whose cumulative Usage was
// sampled. Reopening its controller must not reset Usage or UpdatedAt.
// Excess is surplus already above the repayable 24-hour cap, awaiting HourEnd.
// Mode remembers the last burstable policy even while the type is non-burstable;
// instanceHasCPUCredits determines whether accounting and quotas are active.
type InstanceCreditRecord struct {
	Mode                            string
	Earned, Launch, Surplus, Excess time.Duration
	Usage                           time.Duration
	UpdatedAt, StoppedAt, HourEnd   time.Time
	// Current five-minute CloudWatch contribution, not a second usage ledger.
	MetricUsage, MetricCharged time.Duration
	MetricPeriodEnd            time.Time
	NativePID                  int
	NativeStartTimeTicks       uint64
}

// InstanceCreditDefaultRecord is account/Region/family state. Changes contains
// only the rolling 24-hour modification window required by the AWS limit.
type InstanceCreditDefaultRecord struct {
	Scope        Scope
	Family, Mode string
	Changes      []time.Time
}

// InstanceCreditLaunchRecord retains the rolling eligibility window for T2
// Standard's documented 100 launch-credit allocations per account/Region/day.
type InstanceCreditLaunchRecord struct {
	Scope  Scope
	Starts []time.Time
}

// InstanceCreditMetricSample is a service-owned AWS/EC2 metric contribution.
// Durations are converted to credits by the sink (divide by time.Minute).
// Usage/Charged are interval sums; Balance/SurplusBalance are observed gauges.
type InstanceCreditMetricSample struct {
	Key                                     ResourceKey
	Mode                                    string
	At                                      time.Time
	Usage, Balance, SurplusBalance, Charged time.Duration
}

const instanceCreditPollInterval = time.Second
const instanceCreditQuotaPeriod = 100 * time.Millisecond

func instanceCreditFamily(typ api.InstanceType) string {
	family, _, _ := strings.Cut(string(typ), ".")
	return family
}

func supportedCreditFamily(family string) bool {
	switch family {
	case "t2", "t3", "t3a", "t4g", "t8i":
		return true
	}
	return false
}

func validateCreditMode(mode string) error {
	if mode != "standard" && mode != "unlimited" {
		return failure("InvalidParameterValue", "CPU credit specification must be either 'standard' or 'unlimited'.")
	}
	return nil
}

// Documented pristine defaults are distinct from the captured account overrides.
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/burstable-performance-instances-how-to.html
func defaultInstanceCreditMode(family string) string {
	if family == "t2" {
		return "standard"
	}
	return "unlimited"
}

func (s *Service) admitInstanceCredits(ctx context.Context, typ api.InstanceType, request *api.CreditSpecificationRequest) (InstanceCreditRecord, error) {
	family := instanceCreditFamily(typ)
	rate, hasRate := lookupInstanceCreditRate(typ)
	if !supportedCreditFamily(family) || !hasRate {
		info, err := s.instanceTypes.ResolveInstanceType(ctx, typ)
		if err != nil {
			return InstanceCreditRecord{}, err
		}
		if info.BurstablePerformanceSupported != nil && bool(*info.BurstablePerformanceSupported) {
			return InstanceCreditRecord{}, unsupported("CPU credit execution requires a documented ordinary T2, T3, T3a, T4g or T8i instance type.")
		}
		if request != nil {
			return InstanceCreditRecord{}, failure("InvalidParameterCombination", "CreditSpecification is only supported for burstable performance instances.")
		}
		return InstanceCreditRecord{}, nil
	}
	if rate.EarnedCPUTimePerHour <= 0 || rate.MaximumEarnedCPUTime <= 0 || rate.VCpus <= 0 {
		return InstanceCreditRecord{}, errors.New("ec2: invalid documented CPU credit rate")
	}
	mode := defaultInstanceCreditMode(family)
	if request != nil {
		mode = str(request.CpuCredits)
	} else {
		err := s.repository.View(ctx, func(tx Reader) error {
			record, err := tx.InstanceCreditDefault(scopeFor(ctx), family)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err == nil {
				mode = record.Mode
			}
			return err
		})
		if err != nil {
			return InstanceCreditRecord{}, err
		}
	}
	if err := validateCreditMode(mode); err != nil {
		return InstanceCreditRecord{}, err
	}
	return InstanceCreditRecord{Mode: mode}, nil
}

// multiplyCreditTime computes a*b/divisor without losing fractional rates or
// overflowing intermediate int64 nanosecond products.
func multiplyCreditTime(a, b, divisor time.Duration) time.Duration {
	high, low := bits.Mul64(uint64(a), uint64(b))
	if high >= uint64(divisor) {
		return time.Duration(math.MaxInt64)
	}
	value, _ := bits.Div64(high, low, uint64(divisor))
	if value > math.MaxInt64 {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(value)
}

func creditWindow(values []time.Time, now time.Time) []time.Time {
	first := 0
	cutoff := now.Add(-24 * time.Hour)
	for first < len(values) && !values[first].After(cutoff) {
		first++
	}
	return values[first:]
}

// beginInstanceCredits runs in the instance transaction before Start, after
// inspecting and sampling the paused native VMM outside that transaction. It is
// idempotent for the same native identity. Only a genuinely new start gets a
// new usage cursor and, for T2 Standard, launch credits.
func (s *Service) beginInstanceCredits(ctx context.Context, tx Transaction, record *InstanceRecord, status native.Status, usage time.Duration) error {
	credit := &record.Credits
	if credit.Mode == "" {
		return nil
	}
	if status.PID <= 0 || status.StartTimeTicks == 0 || usage < 0 {
		return errors.New("ec2: missing native CPU accounting identity")
	}
	if credit.NativePID == status.PID && credit.NativeStartTimeTicks == status.StartTimeTicks {
		return nil
	}
	if status.State != native.Paused {
		return errors.New("ec2: a new CPU credit cursor requires a paused VMM")
	}
	if credit.NativePID != 0 && credit.StoppedAt.IsZero() {
		return errors.New("ec2: previous VMM credit usage has not been settled")
	}
	now := s.clock.Now()
	family := instanceCreditFamily(api.InstanceType(str(record.Data.InstanceType)))
	rate, ok := lookupInstanceCreditRate(api.InstanceType(str(record.Data.InstanceType)))
	if !ok {
		return unsupported("No documented CPU credit rate for the instance type.")
	}
	if family == "t2" || (!credit.StoppedAt.IsZero() && !now.Before(credit.StoppedAt.Add(7*24*time.Hour))) {
		credit.Earned = 0
	}
	credit.Launch = 0
	if family == "t2" && credit.Mode == "standard" {
		window, err := tx.InstanceCreditLaunches(record.Key.Scope)
		if errors.Is(err, ErrNotFound) {
			window = InstanceCreditLaunchRecord{Scope: record.Key.Scope}
		} else if err != nil {
			return err
		}
		window.Starts = creditWindow(window.Starts, now)
		if len(window.Starts) < 100 {
			credit.Launch = time.Duration(rate.VCpus) * 30 * time.Minute
			window.Starts = append(window.Starts, now)
			if err := tx.PutInstanceCreditLaunches(window); err != nil {
				return err
			}
		}
	}
	credit.NativePID, credit.NativeStartTimeTicks = status.PID, status.StartTimeTicks
	credit.Usage, credit.UpdatedAt, credit.StoppedAt = usage, now, time.Time{}
	credit.HourEnd = now.Truncate(time.Hour).Add(time.Hour)
	credit.MetricPeriodEnd = now.Truncate(5 * time.Minute).Add(5 * time.Minute)
	return nil
}

// accrueInstanceCredits uses actual cumulative vCPU execution and shared service
// time. It never derives customer utilization from elapsed wall time. The
// caller must persist the returned charged-time metric with the new cursor.
func accrueInstanceCredits(credit *InstanceCreditRecord, rate instanceCreditRate, now time.Time, usage time.Duration) (time.Duration, error) {
	if now.Before(credit.UpdatedAt) {
		return 0, errors.New("ec2: CPU credit service time moved backwards")
	}
	if usage < credit.Usage {
		return 0, errors.New("ec2: cumulative native CPU usage regressed")
	}
	earned := multiplyCreditTime(now.Sub(credit.UpdatedAt), rate.EarnedCPUTimePerHour, time.Hour)
	consumed := usage - credit.Usage
	credit.Usage, credit.UpdatedAt = usage, now
	// Launch credits pay for CPU first and are outside the earned-credit cap.
	fromLaunch := min(credit.Launch, consumed)
	credit.Launch -= fromLaunch
	consumed -= fromLaunch
	if earned >= consumed {
		available := earned - consumed
		repaid := min(credit.Surplus, available)
		credit.Surplus -= repaid
		available -= repaid
		// A resize can retain more earned credits than the new accrual limit.
		// The limit discards newly earned credits, not the retained balance.
		credit.Earned += min(available, max(0, rate.MaximumEarnedCPUTime-credit.Earned))
	} else {
		deficit := consumed - earned
		paid := min(credit.Earned, deficit)
		credit.Earned -= paid
		deficit -= paid
		if credit.Mode == "unlimited" {
			deferred := min(deficit, rate.MaximumEarnedCPUTime-credit.Surplus)
			credit.Surplus += deferred
			credit.Excess += deficit - deferred
		}
	}
	var charged time.Duration
	if !credit.HourEnd.IsZero() && !now.Before(credit.HourEnd) {
		charged, credit.Excess = credit.Excess, 0
		credit.HourEnd = now.Truncate(time.Hour).Add(time.Hour)
	}
	return charged, nil
}

// instanceCPUQuota translates policy into real kernel CPU bandwidth. A fresh
// standard T3.nano has aggregate 0.1 CPU (10ms/100ms), never unrestricted boot.
// Near exhaustion, spread remaining credits over the next observation interval.
// The cgroup enforces this even between polls; polling is not the enforcement.
// During controller downtime the kernel retains its last static quota. Usage
// remains observable on reconnect, but no finer downtime metering is inferred.
func instanceCPUQuota(credit InstanceCreditRecord, rate instanceCreditRate) native.CPUQuota {
	quota := native.CPUQuota{Period: instanceCreditQuotaPeriod}
	if credit.Mode == "" || credit.Mode == "unlimited" {
		return quota
	}
	baseline := multiplyCreditTime(quota.Period, rate.EarnedCPUTimePerHour, time.Hour)
	full := time.Duration(rate.VCpus) * quota.Period
	balance := credit.Earned + credit.Launch
	burst := multiplyCreditTime(balance, quota.Period, instanceCreditPollInterval)
	quota.Runtime = baseline + min(full-baseline, burst)
	return quota
}

func applyInstanceCreditQuota(ctx context.Context, handle native.Instance, record InstanceRecord) error {
	if !instanceHasCPUCredits(record) {
		return nil
	}
	rate, ok := lookupInstanceCreditRate(api.InstanceType(str(record.Data.InstanceType)))
	if !ok {
		return unsupported("No documented CPU credit rate for the instance type.")
	}
	return handle.SetCPUQuota(ctx, instanceCPUQuota(record.Credits, rate))
}

// sampleInstanceCredits may run on a paused or running VMM, but never after its
// threads have disappeared. Reconnection uses the persisted native identity and
// cursor; callers must not call begin merely because a controller was replaced.
func sampleInstanceCredits(record *InstanceRecord, status native.Status, usage time.Duration, now time.Time) (time.Duration, error) {
	if record.Credits.Mode == "" {
		return 0, nil
	}
	credit := &record.Credits
	if status.PID != credit.NativePID || status.StartTimeTicks != credit.NativeStartTimeTicks || credit.NativePID == 0 {
		return 0, errors.New("ec2: native CPU usage belongs to another VMM")
	}
	rate, ok := lookupInstanceCreditRate(api.InstanceType(str(record.Data.InstanceType)))
	if !ok {
		return 0, unsupported("No documented CPU credit rate for the instance type.")
	}
	return accrueInstanceCredits(credit, rate, now, usage)
}

// stopInstanceCredits follows Pause -> CPUUsage -> sampleInstanceCredits and
// native Stop. T2 loses all balances; other supported families retain earned
// credits for seven days. Stopping charges all outstanding unlimited surplus.
func stopInstanceCredits(record *InstanceRecord, now time.Time) time.Duration {
	credit := &record.Credits
	if credit.Mode == "" {
		return 0
	}
	charged := credit.Surplus + credit.Excess
	credit.Surplus, credit.Excess, credit.Launch = 0, 0, 0
	if instanceCreditFamily(api.InstanceType(str(record.Data.InstanceType))) == "t2" {
		credit.Earned = 0
	}
	credit.StoppedAt, credit.UpdatedAt, credit.HourEnd = now, time.Time{}, time.Time{}
	credit.NativePID, credit.NativeStartTimeTicks, credit.Usage = 0, 0, 0
	return charged
}

func changeInstanceCreditMode(record *InstanceRecord, mode string) time.Duration {
	credit := &record.Credits
	if credit.Mode == mode {
		return 0
	}
	credit.Mode = mode
	if mode == "unlimited" {
		credit.Launch = 0
		return 0
	}
	charged := credit.Surplus + credit.Excess
	credit.Surplus, credit.Excess = 0, 0
	return charged
}

func accumulateInstanceCreditSample(record *InstanceRecord, now time.Time, usage, charged time.Duration, terminal bool) (InstanceCreditMetricSample, bool) {
	credit := &record.Credits
	credit.MetricUsage += usage
	credit.MetricCharged += charged
	if credit.MetricPeriodEnd.IsZero() {
		credit.MetricPeriodEnd = now.Truncate(5 * time.Minute).Add(5 * time.Minute)
	}
	if !terminal && now.Before(credit.MetricPeriodEnd) {
		return InstanceCreditMetricSample{}, false
	}
	sample := InstanceCreditMetricSample{
		Key: record.Key, Mode: credit.Mode, At: now, Usage: credit.MetricUsage,
		Balance: credit.Earned + credit.Launch, SurplusBalance: credit.Surplus, Charged: credit.MetricCharged,
	}
	credit.MetricUsage, credit.MetricCharged = 0, 0
	credit.MetricPeriodEnd = now.Truncate(5 * time.Minute).Add(5 * time.Minute)
	if terminal && credit.NativePID == 0 {
		credit.MetricPeriodEnd = time.Time{}
	}
	// A delayed controller observation is one observed aggregate, never invented
	// per-period CPU samples for the intervals it did not observe.
	return sample, true
}

func (s *Service) recordInstanceCreditSample(ctx context.Context, record *InstanceRecord, usage, charged time.Duration, terminal bool) error {
	sample, due := accumulateInstanceCreditSample(record, s.clock.Now(), usage, charged, terminal)
	if !due || s.instanceMetrics == nil {
		return nil
	}
	return s.instanceMetrics.RecordInstanceCreditMetrics(ctx, sample)
}

// admitInstanceCreditTypeChange changes policy, not the stopped usage cursor.
// Earned credits remain instance-owned across type changes, including a stopped
// fixed-performance detour. Their original seven-day expiry is not extended.
// The accrual limit applies to new credits; it is not a resize-time debit.
// Stop already settled surplus and published the final old-type contribution.
// Evidence and documented-rule boundaries: testdata/ec2/instance_credit_transitions.json.
func (s *Service) admitInstanceCreditTypeChange(ctx context.Context, record *InstanceRecord, typ api.InstanceType) error {
	if str(record.Data.InstanceType) == string(typ) {
		return nil
	}
	if record.Credits.NativePID != 0 {
		return failure("IncorrectInstanceState", "CPU credit state has not completed stopping.")
	}
	_, burstable := lookupInstanceCreditRate(typ)
	var request *api.CreditSpecificationRequest
	if burstable && record.Credits.Mode != "" {
		request = &api.CreditSpecificationRequest{CpuCredits: new(api.String(record.Credits.Mode))}
	}
	credit, err := s.admitInstanceCredits(ctx, typ, request)
	if err != nil {
		return err
	}
	// Retain Standard as well as Unlimited so returning from fixed performance
	// does not silently adopt the account's launch default.
	if record.Credits.Mode == "" {
		record.Credits.Mode = credit.Mode
	}
	if !record.Credits.StoppedAt.IsZero() && !s.clock.Now().Before(record.Credits.StoppedAt.Add(7*24*time.Hour)) {
		record.Credits.Earned = 0
	}
	return nil
}
