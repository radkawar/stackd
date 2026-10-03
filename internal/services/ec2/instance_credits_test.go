package ec2

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"stackd/clock"
	native "stackd/compute/ec2"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

func TestStandardCreditsEnforceBaselineThenEarnAndSpend(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	rate := instanceCreditRate{EarnedCPUTimePerHour: 6 * time.Minute, MaximumEarnedCPUTime: 144 * time.Minute, VCpus: 2}
	credit := InstanceCreditRecord{Mode: "standard", UpdatedAt: now}
	if quota := instanceCPUQuota(credit, rate); quota.Runtime != 10*time.Millisecond || quota.Period != 100*time.Millisecond {
		t.Fatalf("fresh T3.nano quota = %+v", quota)
	}
	if _, err := accrueInstanceCredits(&credit, rate, now.Add(10*time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	if credit.Earned != time.Minute {
		t.Fatalf("idle earned CPU time = %v", credit.Earned)
	}
	if quota := instanceCPUQuota(credit, rate); quota.Runtime != 200*time.Millisecond {
		t.Fatalf("credited burst quota = %+v", quota)
	}
	// Measured usage, not service time, consumes the balance. The first sample
	// deliberately models a surviving VMM that ran while its controller was away.
	if _, err := accrueInstanceCredits(&credit, rate, now.Add(10*time.Minute+time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	if credit.Earned != 100*time.Millisecond {
		t.Fatalf("remaining balance = %v", credit.Earned)
	}
	if quota := instanceCPUQuota(credit, rate); quota.Runtime != 20*time.Millisecond {
		t.Fatalf("near-exhaustion quota = %+v", quota)
	}
	if _, err := accrueInstanceCredits(&credit, rate, now.Add(10*time.Minute+2*time.Second), time.Minute+200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if credit.Earned != 0 || credit.Surplus != 0 {
		t.Fatalf("standard balance crossed into surplus: %+v", credit)
	}
	if quota := instanceCPUQuota(credit, rate); quota.Runtime != 10*time.Millisecond {
		t.Fatalf("exhausted quota = %+v", quota)
	}
}

func TestT2LaunchCreditsSpentBeforeEarnedAndOutsideCap(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	rate := instanceCreditRate{EarnedCPUTimePerHour: 6 * time.Minute, MaximumEarnedCPUTime: 144 * time.Minute, VCpus: 1}
	credit := InstanceCreditRecord{Mode: "standard", Launch: 30 * time.Minute, UpdatedAt: now}
	if _, err := accrueInstanceCredits(&credit, rate, now.Add(24*time.Hour), 0); err != nil {
		t.Fatal(err)
	}
	if credit.Earned != 144*time.Minute || credit.Launch != 30*time.Minute {
		t.Fatalf("T2 idle cap = %+v", credit)
	}
	if _, err := accrueInstanceCredits(&credit, rate, now.Add(24*time.Hour+time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	if credit.Earned != 144*time.Minute || credit.Launch != 29*time.Minute {
		t.Fatalf("T2 spending order = %+v", credit)
	}
	record := InstanceRecord{Credits: credit}
	changeInstanceCreditMode(&record, "unlimited")
	if record.Credits.Launch != 0 || record.Credits.Earned != 144*time.Minute {
		t.Fatalf("T2 mode switch lost earned balance: %+v", record.Credits)
	}
}

func TestUnlimitedSurplusRepaymentAndSettlement(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	rate := instanceCreditRate{EarnedCPUTimePerHour: 6 * time.Minute, MaximumEarnedCPUTime: 144 * time.Minute, VCpus: 2}
	credit := InstanceCreditRecord{Mode: "unlimited", UpdatedAt: now, HourEnd: now.Add(time.Hour)}
	if quota := instanceCPUQuota(credit, rate); quota.Runtime != 0 {
		t.Fatalf("unlimited was throttled: %+v", quota)
	}
	if _, err := accrueInstanceCredits(&credit, rate, now.Add(time.Minute), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	debt := 114 * time.Second
	if credit.Surplus != debt || credit.Earned != 0 {
		t.Fatalf("surplus after measured burst = %+v", credit)
	}
	if _, err := accrueInstanceCredits(&credit, rate, now.Add(20*time.Minute), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if credit.Surplus != 0 || credit.Earned != 0 {
		t.Fatalf("idle repayment = %+v", credit)
	}
	// Exactly at the 24-hour cap, additional measured CPU becomes chargeable
	// excess, settled at the hour boundary rather than retained forever.
	credit.Surplus = rate.MaximumEarnedCPUTime
	at := credit.UpdatedAt
	usage := credit.Usage + time.Second
	if charged, err := accrueInstanceCredits(&credit, rate, at, usage); err != nil || charged != 0 {
		t.Fatalf("early charge=%v err=%v", charged, err)
	}
	if credit.Excess != time.Second || credit.Surplus != rate.MaximumEarnedCPUTime {
		t.Fatalf("surplus cap = %+v", credit)
	}
	if charged, err := accrueInstanceCredits(&credit, rate, now.Add(time.Hour), usage); err != nil || charged != time.Second {
		t.Fatalf("hour charge=%v err=%v", charged, err)
	}
	record := InstanceRecord{Credits: credit}
	want := record.Credits.Surplus
	if charged := changeInstanceCreditMode(&record, "standard"); charged != want || record.Credits.Surplus != 0 {
		t.Fatalf("standard switch charged %v want %v", charged, want)
	}
}

func TestCreditReconnectDoesNotResetCumulativeUsage(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	record := InstanceRecord{Data: api.Instance{InstanceType: new(api.InstanceType("t3.nano"))}, Credits: InstanceCreditRecord{
		Mode: "standard", Earned: time.Minute, Usage: 5 * time.Second, UpdatedAt: now, NativePID: 10, NativeStartTimeTicks: 20,
	}}
	status := native.Status{PID: 10, StartTimeTicks: 20, State: native.Running}
	if _, err := sampleInstanceCredits(&record, status, 15*time.Second, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if record.Credits.Earned != 50*time.Second+100*time.Millisecond || record.Credits.Usage != 15*time.Second {
		t.Fatalf("reconnect forgot preexisting cursor: %+v", record.Credits)
	}
	before := record.Credits
	status.StartTimeTicks++
	if _, err := sampleInstanceCredits(&record, status, 16*time.Second, now.Add(2*time.Second)); err == nil {
		t.Fatal("reused PID accepted as surviving VMM")
	}
	if record.Credits != before {
		t.Fatal("rejected VMM replacement mutated credit state")
	}
	status.StartTimeTicks--
	if _, err := sampleInstanceCredits(&record, status, time.Second, now.Add(2*time.Second)); err == nil {
		t.Fatal("regressing usage reset instead of rejecting")
	}
	if record.Credits != before {
		t.Fatal("regressing usage mutated balance")
	}
}

func TestCreditStopSettlesSurplusAndPreservesFamilyRetention(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	for _, typ := range []api.InstanceType{"t2.micro", "t3.nano", "t3a.nano", "t4g.nano", "t8i.nano"} {
		t.Run(string(typ), func(t *testing.T) {
			record := InstanceRecord{Data: api.Instance{InstanceType: new(typ)}, Credits: InstanceCreditRecord{
				Mode: "unlimited", Earned: time.Minute, Launch: time.Second, Surplus: 2 * time.Second, Excess: time.Second,
				Usage: time.Minute, NativePID: 10, NativeStartTimeTicks: 20, UpdatedAt: now.Add(-time.Second), HourEnd: now.Add(time.Hour),
			}}
			if charged := stopInstanceCredits(&record, now); charged != 3*time.Second {
				t.Fatalf("stop charge=%v", charged)
			}
			want := time.Minute
			if typ == "t2.micro" {
				want = 0
			}
			if record.Credits.Earned != want || record.Credits.Launch != 0 || record.Credits.Surplus != 0 || record.Credits.Excess != 0 {
				t.Fatalf("stopped balance=%+v", record.Credits)
			}
			if record.Credits.StoppedAt != now || record.Credits.NativePID != 0 || !record.Credits.UpdatedAt.IsZero() {
				t.Fatalf("stopped cursor=%+v", record.Credits)
			}
		})
	}
}

func TestCreditAccrualExactFractionalRateAndLargeElapsed(t *testing.T) {
	// Official T2.2xlarge: 81.6 credits/hour, not an integer-rounded rate.
	rate := 81*time.Minute + 36*time.Second
	if got := multiplyCreditTime(24*time.Hour, rate, time.Hour); got != 1958*time.Minute+24*time.Second {
		t.Fatalf("24h fractional accrual=%v", got)
	}
	if got := multiplyCreditTime(7*24*time.Hour, 6*time.Minute, time.Hour); got != 1008*time.Minute {
		t.Fatalf("large elapsed overflow=%v", got)
	}
}

func TestStoppedCreditRetentionExpiresAtSevenDays(t *testing.T) {
	stopped := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	for _, elapsed := range []time.Duration{7*24*time.Hour - time.Nanosecond, 7 * 24 * time.Hour} {
		t.Run(elapsed.String(), func(t *testing.T) {
			repository := NewMemoryRepository(nil)
			service := &Service{repository: repository, clock: clock.NewManual(stopped.Add(elapsed))}
			record := InstanceRecord{Key: ResourceKey{Scope: Scope{"aws", "111111111111", "us-east-1"}, ID: "i-11111111111111111"},
				Data:    api.Instance{InstanceType: new(api.InstanceType("t3.nano"))},
				Credits: InstanceCreditRecord{Mode: "standard", Earned: time.Minute, StoppedAt: stopped}}
			status := native.Status{PID: 10, StartTimeTicks: 20, State: native.Paused}
			err := repository.Update(context.Background(), func(tx Transaction) error {
				return service.beginInstanceCredits(tx.Context(), tx, &record, status, time.Second)
			})
			if err != nil {
				t.Fatal(err)
			}
			want := time.Minute
			if elapsed == 7*24*time.Hour {
				want = 0
			}
			if record.Credits.Earned != want || record.Credits.Launch != 0 || record.Credits.Usage != time.Second || !record.Credits.StoppedAt.IsZero() {
				t.Fatalf("restart credit state = %+v", record.Credits)
			}
		})
	}
}

func TestT2LaunchEligibilityIsRollingScopedAndNotReissuedOnReconnect(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	repository := NewMemoryRepository(nil)
	manual := clock.NewManual(now)
	service := &Service{repository: repository, clock: manual}
	scope := Scope{"aws", "111111111111", "us-east-1"}
	window := InstanceCreditLaunchRecord{Scope: scope, Starts: make([]time.Time, 100)}
	for index := range window.Starts {
		window.Starts[index] = now.Add(-time.Hour)
	}
	if err := repository.Update(context.Background(), func(tx Transaction) error { return tx.PutInstanceCreditLaunches(window) }); err != nil {
		t.Fatal(err)
	}
	record := InstanceRecord{Key: ResourceKey{Scope: scope, ID: "i-11111111111111111"},
		Data: api.Instance{InstanceType: new(api.InstanceType("t2.micro"))}, Credits: InstanceCreditRecord{Mode: "standard"}}
	status := native.Status{PID: 10, StartTimeTicks: 20, State: native.Paused}
	begin := func(record *InstanceRecord, status native.Status) {
		t.Helper()
		if err := repository.Update(context.Background(), func(tx Transaction) error { return service.beginInstanceCredits(tx.Context(), tx, record, status, 0) }); err != nil {
			t.Fatal(err)
		}
	}
	begin(&record, status)
	if record.Credits.Launch != 0 {
		t.Fatal("T2 launch credits exceeded regional daily eligibility")
	}
	stopInstanceCredits(&record, now)
	if err := manual.Advance(23 * time.Hour); err != nil {
		t.Fatal(err)
	}
	status.StartTimeTicks++
	begin(&record, status)
	if record.Credits.Launch != 30*time.Minute {
		t.Fatalf("expired rolling window failed to grant launch credits: %+v", record.Credits)
	}
	record.Credits.Launch -= time.Minute
	before := record.Credits
	status.State = native.Running
	begin(&record, status)
	if record.Credits != before {
		t.Fatalf("reconnect reissued T2 credits or reset cursor: %+v", record.Credits)
	}
	other := InstanceRecord{Key: ResourceKey{Scope: Scope{"aws", "222222222222", "us-east-1"}, ID: "i-22222222222222222"},
		Data: api.Instance{InstanceType: new(api.InstanceType("t2.micro"))}, Credits: InstanceCreditRecord{Mode: "standard"}}
	status.State = native.Paused
	begin(&other, status)
	if other.Credits.Launch != 30*time.Minute {
		t.Fatal("account-scoped launch credit eligibility leaked")
	}
}

func TestCreditDefaultAdmissionIsScopedAndExplicitModeWins(t *testing.T) {
	repository := NewMemoryRepository(nil)
	service := &Service{repository: repository}
	scoped := Scope{"aws", "111111111111", "us-east-1"}
	if err := repository.Update(context.Background(), func(tx Transaction) error {
		return tx.PutInstanceCreditDefault(InstanceCreditDefaultRecord{Scope: scoped, Family: "t3", Mode: "standard"})
	}); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ account, region, explicit, want string }{
		{scoped.AccountID, scoped.Region, "", "standard"},
		{scoped.AccountID, scoped.Region, "unlimited", "unlimited"},
		{"222222222222", scoped.Region, "", "unlimited"},
		{scoped.AccountID, "us-west-2", "", "unlimited"},
	} {
		ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: scoped.Partition, AccountID: item.account, Region: item.region})
		var request *api.CreditSpecificationRequest
		if item.explicit != "" {
			request = &api.CreditSpecificationRequest{CpuCredits: new(api.String(item.explicit))}
		}
		credit, err := service.admitInstanceCredits(ctx, "t3.nano", request)
		if err != nil || credit.Mode != item.want {
			t.Fatalf("account=%s region=%s explicit=%s: credit=%+v err=%v", item.account, item.region, item.explicit, credit, err)
		}
		if credit.Earned != 0 || credit.Launch != 0 || !credit.UpdatedAt.IsZero() {
			t.Fatalf("admission fabricated pre-start credits: %+v", credit)
		}
	}
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: scoped.Partition, AccountID: scoped.AccountID, Region: scoped.Region})
	if _, err := service.admitInstanceCredits(ctx, "t3.nano", &api.CreditSpecificationRequest{CpuCredits: new(api.String("invalid"))}); err == nil {
		t.Fatal("invalid credit mode accepted")
	}
}

func TestCreditMetricsAccumulateToFiveMinuteEdgeAndFlushOnStop(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	record := InstanceRecord{Credits: InstanceCreditRecord{Mode: "unlimited", NativePID: 10, MetricPeriodEnd: now.Add(5 * time.Minute)}}
	for minute := 1; minute < 5; minute++ {
		record.Credits.Earned = time.Duration(minute) * time.Minute
		if _, due := accumulateInstanceCreditSample(&record, now.Add(time.Duration(minute)*time.Minute), time.Second, 0, false); due {
			t.Fatalf("published credit metric before edge at minute %d", minute)
		}
	}
	if record.Credits.MetricUsage != 4*time.Second {
		t.Fatalf("unpublished usage lost: %v", record.Credits.MetricUsage)
	}
	record.Credits.Earned = 7 * time.Minute
	sample, due := accumulateInstanceCreditSample(&record, now.Add(5*time.Minute), 2*time.Second, time.Second, false)
	if !due || sample.At != now.Add(5*time.Minute) || sample.Usage != 6*time.Second || sample.Charged != time.Second || sample.Balance != 7*time.Minute {
		t.Fatalf("edge metric did not contain interval sums and latest gauge: %+v due=%v", sample, due)
	}
	if record.Credits.MetricUsage != 0 || record.Credits.MetricCharged != 0 || record.Credits.MetricPeriodEnd != now.Add(10*time.Minute) {
		t.Fatalf("published contributions were not consumed: %+v", record.Credits)
	}
	record.Credits.NativePID = 0
	sample, due = accumulateInstanceCreditSample(&record, now.Add(6*time.Minute), time.Second, 2*time.Second, true)
	if !due || sample.Usage != time.Second || sample.Charged != 2*time.Second || !record.Credits.MetricPeriodEnd.IsZero() {
		t.Fatalf("stop lost final partial interval or retained inactive metric window: %+v record=%+v", sample, record.Credits)
	}
}

func TestNativeStoppedCreditTypeAndModeTransitions(t *testing.T) {
	for _, name := range []string{"instance_credits_resize", "instance_credits_transitions_owned", "instance_credits_unlimited_detour"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile("../../../testdata/aws/ec2/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Account, Region string
				Calls           []struct {
					Label, Operation, Code string
					Input, Output          json.RawMessage
				}
			}
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
			service := New(Config{Clock: clock.NewManual(now)})
			t.Cleanup(func() {
				if err := service.Close(); err != nil {
					t.Error(err)
				}
			})
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: fixture.Account, Region: fixture.Region, PrincipalARN: "arn:aws:iam::" + fixture.Account + ":root", PrincipalID: fixture.Account})
			for _, call := range fixture.Calls {
				if call.Code != "Success" {
					continue
				}
				err := service.repository.Update(ctx, func(tx Transaction) error {
					switch call.Operation {
					case "RunInstances":
						var request api.RunInstancesRequest
						var response api.Reservation
						if err := json.Unmarshal(call.Input, &request); err != nil {
							return err
						}
						if err := json.Unmarshal(call.Output, &response); err != nil {
							return err
						}
						record := InstanceRecord{Key: key(ctx, str(response.Instances[0].InstanceId)), Data: response.Instances[0],
							Credits: InstanceCreditRecord{Mode: str(request.CreditSpecification.CpuCredits), Earned: time.Minute, StoppedAt: now.Add(-time.Minute)}}
						// The native stop/start path supplies the type/mode responses.
						// This reducer replay isolates stopped attribute mutations.
						record.Data.State = instanceStateValue("stopped")
						return tx.PutInstance(record)
					case "ModifyInstanceAttribute":
						var request api.ModifyInstanceAttributeRequest
						if err := json.Unmarshal(call.Input, &request); err != nil {
							return err
						}
						if request.InstanceType != nil {
							_, err := service.modifyInstanceAttribute(tx.Context(), tx, &request)
							return err
						}
					case "DescribeInstances":
						var expected api.DescribeInstancesResult
						if err := json.Unmarshal(call.Output, &expected); err != nil {
							return err
						}
						for _, reservation := range expected.Reservations {
							for _, instance := range reservation.Instances {
								// Immediate stopped descriptions can still show the
								// previous type. Compare stabilized running starts,
								// not AWS's eventually consistent read timing.
								if instance.State == nil || str(instance.State.Name) != "running" {
									continue
								}
								record, err := tx.Instance(key(ctx, str(instance.InstanceId)))
								if err != nil {
									return err
								}
								if str(record.Data.InstanceType) != str(instance.InstanceType) {
									t.Fatalf("%s: type=%s, native=%s", call.Label, str(record.Data.InstanceType), str(instance.InstanceType))
								}
								if cpu := instance.CpuOptions; cpu != nil {
									got := record.Data.CpuOptions
									if got == nil || got.CoreCount == nil || got.ThreadsPerCore == nil ||
										*got.CoreCount != *cpu.CoreCount || *got.ThreadsPerCore != *cpu.ThreadsPerCore {
										t.Fatalf("%s: CPU options=%+v, native=%+v", call.Label, got, cpu)
									}
								}
							}
						}
					case "DescribeInstanceCreditSpecifications":
						var request api.DescribeInstanceCreditSpecificationsRequest
						var expected api.DescribeInstanceCreditSpecificationsResult
						if err := json.Unmarshal(call.Input, &request); err != nil {
							return err
						}
						if err := json.Unmarshal(call.Output, &expected); err != nil {
							return err
						}
						got, err := service.describeInstanceCreditSpecifications(tx.Context(), tx, &request)
						if err != nil {
							return err
						}
						if len(got.InstanceCreditSpecifications) != len(expected.InstanceCreditSpecifications) {
							t.Fatalf("%s: modes=%+v, native=%+v", call.Label, got, expected)
						}
						for index, specification := range expected.InstanceCreditSpecifications {
							if str(got.InstanceCreditSpecifications[index].CpuCredits) != str(specification.CpuCredits) {
								t.Fatalf("%s: mode=%s, native=%s", call.Label, str(got.InstanceCreditSpecifications[index].CpuCredits), str(specification.CpuCredits))
							}
						}
					}
					return nil
				})
				if err != nil {
					t.Fatalf("%s: %v", call.Label, err)
				}
			}
		})
	}
}

func TestDocumentedCreditTypeTransitions(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/ec2/instance_credit_transitions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name, Evidence, Type, Mode, Earned string
			StoppedFor                         string `json:"stopped_for"`
			Types                              []api.InstanceType
			Retained                           string
			Active                             bool
			StartAfter                         string `json:"start_after"`
			Started, Launch, Quota             string
			Samples                            []struct{ Elapsed, Usage, Earned string }
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	duration := func(value string) time.Duration {
		t.Helper()
		parsed, err := time.ParseDuration(value)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	for _, item := range fixture.Cases {
		t.Run(item.Name, func(t *testing.T) {
			t.Log(item.Evidence)
			now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
			manual := clock.NewManual(now)
			service := New(Config{Clock: manual})
			t.Cleanup(func() {
				if err := service.Close(); err != nil {
					t.Error(err)
				}
			})
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"})
			instanceKey := key(ctx, "i-0123456789abcdef0")
			stopped := now.Add(-duration(item.StoppedFor))
			record := InstanceRecord{Key: instanceKey,
				Data: api.Instance{InstanceId: new(api.String(instanceKey.ID)), InstanceType: new(api.InstanceType(item.Type)),
					Architecture: new(api.ArchitectureValues("x86_64")), State: instanceStateValue("stopped")},
				Credits: InstanceCreditRecord{Mode: item.Mode, Earned: duration(item.Earned), StoppedAt: stopped}}
			if err := service.repository.Update(ctx, func(tx Transaction) error { return tx.PutInstance(record) }); err != nil {
				t.Fatal(err)
			}
			for _, typ := range item.Types {
				err := service.repository.Update(ctx, func(tx Transaction) error {
					_, err := service.modifyInstanceAttribute(tx.Context(), tx, &api.ModifyInstanceAttributeRequest{
						InstanceId: new(api.InstanceId(instanceKey.ID)), InstanceType: &api.AttributeValue{Value: new(api.String(typ))}})
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := service.repository.View(ctx, func(tx Reader) error { var err error; record, err = tx.Instance(instanceKey); return err }); err != nil {
				t.Fatal(err)
			}
			if record.Credits.Earned != duration(item.Retained) || record.Credits.Mode != item.Mode || record.Credits.StoppedAt != stopped {
				t.Fatalf("resize changed retained policy/balance/expiry: %+v", record.Credits)
			}
			if instanceHasCPUCredits(record) != item.Active {
				t.Fatalf("CPU accounting activity after resize = %v, want %v", instanceHasCPUCredits(record), item.Active)
			}
			if !item.Active {
				return
			}
			if err := manual.Advance(duration(item.StartAfter)); err != nil {
				t.Fatal(err)
			}
			status := native.Status{PID: 10, StartTimeTicks: 20, State: native.Paused}
			if err := service.repository.Update(ctx, func(tx Transaction) error {
				return service.beginInstanceCredits(tx.Context(), tx, &record, status, 0)
			}); err != nil {
				t.Fatal(err)
			}
			if record.Credits.Earned != duration(item.Started) || record.Credits.Launch != duration(item.Launch) {
				t.Fatalf("new-type start balances = %+v", record.Credits)
			}
			rate, _ := lookupInstanceCreditRate(*record.Data.InstanceType)
			if quota := instanceCPUQuota(record.Credits, rate); quota.Runtime != duration(item.Quota) {
				t.Fatalf("new-type start quota = %+v, want runtime %s", quota, item.Quota)
			}
			for _, sample := range item.Samples {
				if err := manual.Advance(duration(sample.Elapsed)); err != nil {
					t.Fatal(err)
				}
				charged, err := sampleInstanceCredits(&record, status, duration(sample.Usage), manual.Now())
				if err != nil {
					t.Fatal(err)
				}
				if record.Credits.Earned != duration(sample.Earned) || record.Credits.Surplus != 0 || charged != 0 {
					t.Fatalf("post-resize measured accounting = %+v charge=%s; want earned %s", record.Credits, charged, sample.Earned)
				}
			}
		})
	}
}

func TestCreditResizeRejectsUnsettledCursorWithoutExpiringBalance(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	service := &Service{clock: clock.NewManual(now)}
	record := InstanceRecord{Data: api.Instance{InstanceType: new(api.InstanceType("t3.micro"))},
		Credits: InstanceCreditRecord{Mode: "standard", Earned: time.Minute, StoppedAt: now.Add(-8 * 24 * time.Hour), NativePID: 10}}
	before := record.Credits
	err := service.admitInstanceCreditTypeChange(t.Context(), &record, "t3.nano")
	if err == nil || wireError(err).Code != "IncorrectInstanceState" || record.Credits != before {
		t.Fatalf("unsettled resize: err=%v before=%+v after=%+v", err, before, record.Credits)
	}
}
