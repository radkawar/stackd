package ec2

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"stackd/compute/docker"
)

// SystemdLimits applies native CFS quota to the real VMM process. It shares the
// same privileged manager-call owner as ECS, while EC2 owns credit policy.
type SystemdLimits struct{ Client *docker.Client }

func instanceScopeName(arn string) string {
	return fmt.Sprintf("stackdec2%x.scope", sha256.Sum256([]byte(arn)))
}

func (l SystemdLimits) Apply(ctx context.Context, arn string, pid int, quota CPUQuota) error {
	if l.Client == nil || arn == "" || pid <= 0 || quota.Period < time.Microsecond || quota.Runtime < 0 {
		return errors.New("EC2 CPU limits require a native client, instance, process and nonnegative quota")
	}
	period := quota.Period.Microseconds()
	perSecond := uint64(math.MaxUint64)
	if quota.Runtime != 0 {
		perSecond = uint64(quota.Runtime/time.Microsecond) * 1_000_000 / uint64(period)
		if perSecond == 0 {
			return errors.New("EC2 CPU quota is below native microsecond resolution")
		}
	}
	name := instanceScopeName(arn)
	owner := "stackd EC2 instance " + arn
	unit, err := docker.InspectUnit(ctx, l.Client, name, docker.ToolkitImage)
	if err != nil {
		return err
	}
	properties := []string{"CPUQuotaPerSecUSec", "t", strconv.FormatUint(perSecond, 10), "CPUQuotaPeriodUSec", "t", strconv.FormatInt(period, 10)}
	if unit == nil {
		args := []string{"StartTransientUnit", "ssa(sv)a(sa(sv))", name, "fail", "4", "Description", "s", owner, "PIDs", "au", "1", strconv.Itoa(pid)}
		args = append(args, properties...)
		args = append(args, "0")
		if _, err := docker.SystemdCall(ctx, l.Client, name, docker.ToolkitImage, args...); err != nil {
			return fmt.Errorf("create EC2 CPU scope: %w", err)
		}
	} else {
		if unit.Description != owner {
			return fmt.Errorf("native scope %s belongs to %q", name, unit.Description)
		}
		args := append([]string{"SetUnitProperties", "sba(sv)", name, "true", "2"}, properties...)
		if _, err := docker.SystemdCall(ctx, l.Client, name, docker.ToolkitImage, args...); err != nil {
			return fmt.Errorf("set EC2 CPU quota: %w", err)
		}
	}
	return docker.WaitUnit(ctx, l.Client, name, docker.ToolkitImage, true, func(unit *docker.Unit) error {
		if unit.Description != owner {
			return fmt.Errorf("native scope %s belongs to %q", name, unit.Description)
		}
		return nil
	})
}

// Remove runs only after the VMM has exited. Scopes commonly disappear themselves
// when their last native process exits; neither case deletes EBS disk contents.
func (l SystemdLimits) Remove(ctx context.Context, arn string) error {
	name := instanceScopeName(arn)
	owner := "stackd EC2 instance " + arn
	return docker.StopUnit(ctx, l.Client, name, docker.ToolkitImage, func(unit *docker.Unit) error {
		if unit.Description != owner {
			return fmt.Errorf("native scope %s belongs to %q", name, unit.Description)
		}
		return nil
	})
}
