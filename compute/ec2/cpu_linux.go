package ec2

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CPUUsage sums the actual native vCPU thread clocks, excluding the QEMU main
// loop, disk worker and network I/O threads. It resets when the VMM is replaced;
// the service owns credit checkpoints and reset handling.
func (i *nativeInstance) CPUUsage(ctx context.Context) (time.Duration, error) {
	unlock, err := i.driver.lock(ctx)
	if err != nil {
		return 0, err
	}
	defer unlock()
	client, err := i.driver.existing(ctx, i.directory)
	if err != nil {
		return 0, err
	}
	defer client.close()
	var cpus []struct {
		ThreadID int `json:"thread-id"`
	}
	if err := client.execute(ctx, "query-cpus-fast", nil, &cpus); err != nil {
		return 0, err
	}
	if len(cpus) == 0 {
		return 0, errors.New("native guest has no vCPU threads")
	}
	var total time.Duration
	for _, cpu := range cpus {
		if cpu.ThreadID <= 0 {
			return 0, errors.New("invalid native vCPU thread ID")
		}
		// schedstat's first field is sum_exec_runtime in nanoseconds, not
		// jiffies. Read the QMP-identified thread under its owning process.
		data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(client.pid), "task", strconv.Itoa(cpu.ThreadID), "schedstat"))
		if err != nil {
			return 0, err
		}
		fields := strings.Fields(string(data))
		if len(fields) != 3 {
			return 0, errors.New("invalid native vCPU scheduler accounting")
		}
		nanoseconds, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || nanoseconds < 0 {
			return 0, errors.New("invalid native vCPU CPU time")
		}
		total += time.Duration(nanoseconds)
	}
	return total, nil
}

func (i *nativeInstance) SetCPUQuota(ctx context.Context, quota CPUQuota) error {
	if quota.Period <= 0 || quota.Runtime < 0 {
		return errors.New("invalid native CPU quota")
	}
	if i.driver.config.CPULimits == nil {
		return &CapabilityError{Feature: "injected CPU bandwidth controller"}
	}
	unlock, err := i.driver.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	client, err := i.driver.existing(ctx, i.directory)
	if err != nil {
		return err
	}
	defer client.close()
	if i.quotaPID == client.pid && i.quota == quota {
		return nil
	}
	if err := i.driver.config.CPULimits.Apply(ctx, i.spec.InstanceARN, client.pid, quota); err != nil {
		return err
	}
	i.quotaPID, i.quota = client.pid, quota
	return nil
}
