package ec2

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os/exec"
)

// CheckHealth observes the live attachment and, when requested, reads each
// attached NVMe through its running VMM. Offline files are not a substitute for
// reachability through the guest's actual block graph.
func (i *nativeInstance) CheckHealth(ctx context.Context, checkDisks bool) (Health, error) {
	var health Health
	var err error
	health.Network, err = i.attachment.CheckHealth(ctx)
	if err != nil {
		return health, err
	}
	if checkDisks {
		health.DisksReachable, err = i.checkDiskHealth(ctx)
	}
	if i.spec.Hibernation {
		health.HibernationReady = i.guestHibernation(ctx, false) == nil
		if ctx.Err() != nil {
			return health, ctx.Err()
		}
	}
	return health, err
}

func (i *nativeInstance) checkDiskHealth(ctx context.Context) (bool, error) {
	unlock, err := i.driver.lock(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	client, err := i.driver.existing(ctx, i.directory)
	if err != nil {
		return false, err
	}
	defer client.close()
	disks, err := i.attachedDisks(ctx, client)
	if err != nil {
		return false, err
	}
	rootPresent := false
	for _, disk := range disks {
		rootPresent = rootPresent || disk.Root
		var output bytes.Buffer
		var readErr error
		err := i.driver.withExport(ctx, client, i.directory, disk.NodeName, func(socket, export string) error {
			options := "driver=nbd,server.type=unix,server.path=" + escapeOption(socket) + ",export=" + escapeOption(export)
			readErr = runNative(ctx, i.driver.config.IOBinary, []string{"-r", "--image-opts", "-c", "read -q 0 512", options}, nil, &output)
			return readErr
		})
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			var exit *exec.ExitError
			if readErr == nil || !errors.As(readErr, &exit) {
				return false, err
			}
			// A completed native read failed. Tool launch/export failures instead
			// return errors: they are not observations of guest disk impairment.
			slog.Warn("EC2 native disk health read failed", "instance", i.spec.InstanceARN, "node", disk.NodeName, "error", err, "output", output.String())
			return false, nil
		}
	}
	return rootPresent, nil
}
