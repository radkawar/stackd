package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SystemdCall executes the native manager API through the installed trusted
// toolkit. It needs local rootful Docker and the host system bus; it neither
// changes daemon configuration nor grants customer containers host access.
func SystemdCall(ctx context.Context, client *Client, owner, helperImage string, args ...string) ([]byte, error) {
	command := []string{"/host", "/usr/bin/busctl", "--system", "--no-pager", "--json=short", "--timeout=10s", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager"}
	command = append(command, args...)
	return RunHelper(ctx, client, "systemd", ContainerConfig{
		Image: helperImage, Entrypoint: []string{"chroot"}, Cmd: command,
		User: "0:0", NetworkDisabled: true,
		Env:    []string{"SYSTEMD_LOG_TARGET=console"},
		Labels: map[string]string{"stackd.compute.unit": owner},
		HostConfig: ContainerHostConfig{
			NetworkMode: "none", ReadonlyRootfs: true,
			Memory: 64 << 20, MemorySwap: 64 << 20,
			CPUPeriod: 100000, CPUQuota: 100000, PidsLimit: 32,
			CapDrop: []string{"ALL"}, CapAdd: []string{"SYS_CHROOT"},
			SecurityOpt: []string{"apparmor=unconfined"},
			Mounts:      []ContainerMount{{Type: "bind", Source: "/", Target: "/host", ReadOnly: true}},
			LogConfig:   ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}},
		},
	})
}

// Unit is observed native state. A successfully queued manager job is not
// evidence that the unit is active or stopped.
type Unit struct {
	Description, Load, Active, Sub string
	Job                            uint32
}

func InspectUnit(ctx context.Context, client *Client, name, helperImage string) (*Unit, error) {
	output, err := SystemdCall(ctx, client, name, helperImage, "ListUnitsByPatterns", "asas", "0", "1", name)
	if err != nil {
		return nil, err
	}
	var result struct {
		Type string                `json:"type"`
		Data [][][]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("decode systemd unit: %w", err)
	}
	if result.Type != "a(ssssssouso)" || len(result.Data) != 1 {
		return nil, fmt.Errorf("unexpected systemd unit status %q", output)
	}
	if len(result.Data[0]) == 0 {
		return nil, nil
	}
	if len(result.Data[0]) != 1 || len(result.Data[0][0]) != 10 {
		return nil, fmt.Errorf("unexpected systemd unit entries %q", output)
	}
	fields := result.Data[0][0]
	var actualName string
	unit := &Unit{}
	for index, dest := range []*string{&actualName, &unit.Description, &unit.Load, &unit.Active, &unit.Sub} {
		if err := json.Unmarshal(fields[index], dest); err != nil {
			return nil, fmt.Errorf("decode systemd unit field %d: %w", index, err)
		}
	}
	if err := json.Unmarshal(fields[7], &unit.Job); err != nil {
		return nil, fmt.Errorf("decode systemd unit job: %w", err)
	}
	if actualName != name {
		return nil, fmt.Errorf("systemd returned unit %q for %q", actualName, name)
	}
	return unit, nil
}

// StopUnit waits for an owned unit to stop. A transient unit can be collected
// between inspection and StopUnit; observed absence completes that transition.
func StopUnit(ctx context.Context, client *Client, name, helperImage string, owned func(*Unit) error) error {
	unit, err := InspectUnit(ctx, client, name, helperImage)
	if err != nil || unit == nil {
		return err
	}
	if err := owned(unit); err != nil {
		return err
	}
	if unit.Active == "inactive" && unit.Job == 0 {
		return nil
	}
	if _, err := SystemdCall(ctx, client, name, helperImage, "StopUnit", "ss", name, "replace"); err != nil {
		// Only an ordinary command exit can be reconciled with collection.
		// Transport, decoding and joined helper-cleanup failures must survive.
		if _, exited := err.(helperExitError); !exited {
			return err
		}
		current, inspectErr := InspectUnit(ctx, client, name, helperImage)
		if inspectErr != nil {
			return errors.Join(err, inspectErr)
		}
		if current == nil {
			return nil
		}
		return err
	}
	return WaitUnit(ctx, client, name, helperImage, false, owned)
}

// WaitUnit observes a queued native transition, checking the caller's ownership
// invariant on every surviving unit. The timer only bounds observation frequency.
func WaitUnit(ctx context.Context, client *Client, name, helperImage string, active bool, owned func(*Unit) error) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		unit, err := InspectUnit(ctx, client, name, helperImage)
		if err != nil {
			return err
		}
		if unit == nil {
			if !active {
				return nil
			}
			return fmt.Errorf("systemd unit %s disappeared before becoming active", name)
		}
		if err := owned(unit); err != nil {
			return err
		}
		if !active && unit.Active == "inactive" && unit.Job == 0 {
			return nil
		}
		if unit.Load != "loaded" || unit.Active == "failed" || active && unit.Active == "inactive" && unit.Job == 0 {
			return fmt.Errorf("systemd unit %s is %s/%s/%s, wanted active=%t", name, unit.Load, unit.Active, unit.Sub, active)
		}
		if active && unit.Active == "active" && unit.Job == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for systemd unit %s active=%t: %w", name, active, ctx.Err())
		case <-ticker.C:
		}
	}
}
