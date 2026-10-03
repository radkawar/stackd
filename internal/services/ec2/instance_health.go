package ec2

import (
	"context"
	"log/slog"
	"time"

	native "stackd/compute/ec2"
	api "stackd/internal/awsapi/ec2"
)

const instanceHealthInterval = time.Minute

// InstanceStatusCheck retains a native observation and the beginning of its
// current continuous failure. An empty status has not yet been observed.
type InstanceStatusCheck struct {
	Status        api.StatusType
	ImpairedSince time.Time
}

// InstanceHealthRecord owns check initialization and the latest observation.
// UpdatedAt schedules the next one-minute check; advancing virtual time never
// fabricates observations for intervals in which no native check ran.
type InstanceHealthRecord struct {
	UpdatedAt                  time.Time
	System, Guest, AttachedEBS InstanceStatusCheck
	HibernationReady           bool
}

func observeInstanceCheck(previous InstanceStatusCheck, reachable bool, at time.Time) InstanceStatusCheck {
	if reachable {
		return InstanceStatusCheck{Status: "passed"}
	}
	if previous.Status == "failed" {
		return previous
	}
	return InstanceStatusCheck{Status: "failed", ImpairedSince: at}
}

func (s *Service) observeInstanceHealth(ctx context.Context, record *InstanceRecord, handle native.Instance, state native.State) (*InstanceHealthRecord, error) {
	// TODO: Comeback model native delayed status publication and automatic recovery from retained health observations.
	if s.clock.Now().Before(record.Health.UpdatedAt.Add(instanceHealthInterval)) {
		return nil, nil
	}
	typ, err := s.instanceTypes.ResolveInstanceType(ctx, api.InstanceType(str(record.Data.InstanceType)))
	if err != nil {
		return nil, err
	}
	checkEBS := str(typ.Hypervisor) == "nitro"
	observed, err := handle.CheckHealth(ctx, checkEBS)
	at := s.clock.Now().Truncate(time.Minute)
	health := &InstanceHealthRecord{UpdatedAt: at}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		slog.Error("EC2 instance health observation unavailable", "instance", resourceARN(record.Key.Scope, "instance", record.Key.ID), "error", err)
		unknown := InstanceStatusCheck{Status: "insufficient-data"}
		health.System, health.Guest = unknown, unknown
		if checkEBS {
			health.AttachedEBS = unknown
		}
		return health, nil
	}
	health.System = observeInstanceCheck(record.Health.System, state != native.Error && state != native.Exited && observed.Network.Attached, at)
	health.Guest = observeInstanceCheck(record.Health.Guest, observed.Network.Reachable, at)
	health.HibernationReady = observed.HibernationReady
	if checkEBS {
		health.AttachedEBS = observeInstanceCheck(record.Health.AttachedEBS, observed.DisksReachable, at)
	}
	return health, nil
}

func (check InstanceStatusCheck) detailStatus() api.StatusType {
	if check.Status == "" {
		return "initializing"
	}
	return check.Status
}

func (check InstanceStatusCheck) summaryStatus() api.SummaryStatus {
	switch check.Status {
	case "passed":
		return "ok"
	case "failed":
		return "impaired"
	default:
		return api.SummaryStatus(check.detailStatus())
	}
}

func instanceCheckSummary(check InstanceStatusCheck) *api.InstanceStatusSummary {
	detail := api.InstanceStatusDetails{Name: new(api.StatusName("reachability")), Status: new(check.detailStatus())}
	if !check.ImpairedSince.IsZero() {
		detail.ImpairedSince = new(api.DateTime(check.ImpairedSince))
	}
	return &api.InstanceStatusSummary{Status: new(check.summaryStatus()), Details: api.InstanceStatusDetailsList{detail}}
}

func ebsCheckSummary(check InstanceStatusCheck) *api.EbsStatusSummary {
	if check.Status == "" {
		return nil
	}
	detail := api.EbsStatusDetails{Name: new(api.StatusName("reachability")), Status: new(check.detailStatus())}
	if !check.ImpairedSince.IsZero() {
		detail.ImpairedSince = new(api.MillisecondDateTime(check.ImpairedSince))
	}
	return &api.EbsStatusSummary{Status: new(check.summaryStatus()), Details: api.EbsStatusDetailsList{detail}}
}
