package eks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
)

func nativeAuditPolicyHash() string {
	sum := sha256.Sum256([]byte(nativeAuditPolicy))
	return hex.EncodeToString(sum[:])
}

func (k *K3d) reconcileNativeAuditPolicy(ctx context.Context, state *diskState, dir string) error {
	desired := nativeAuditPolicyHash()
	if state.NativeLogging && state.AuditPolicyHash == desired {
		return nil
	}
	// Recheck ownership immediately before changing the retained server. Use the
	// inspected ID for mounted-policy reloads, not a mutable container name.
	containers, err := k.ownedContainers(ctx, *state)
	if err != nil {
		return err
	}
	var server *dockerContainer
	for i := range containers {
		if containers[i].Name == "/k3d-"+state.Name+"-server-0" {
			server = &containers[i]
			break
		}
	}
	if server == nil {
		return errors.New("eks: owned native server is missing during audit policy upgrade")
	}
	mountedPolicy, mountedWebhook := false, false
	for _, mount := range server.Mounts {
		switch mount.Destination {
		case "/etc/stackd/audit-policy.yaml", "/etc/stackd/audit-webhook.kubeconfig":
			if mount.Type != "bind" || mount.Source != filepath.Join(dir, filepath.Base(mount.Destination)) {
				return errors.New("eks: retained audit mount differs from its owned private source")
			}
			mountedPolicy = mountedPolicy || mount.Destination == "/etc/stackd/audit-policy.yaml"
			mountedWebhook = mountedWebhook || mount.Destination == "/etc/stackd/audit-webhook.kubeconfig"
		}
	}
	if mountedPolicy != mountedWebhook {
		return errors.New("eks: retained native server has incomplete audit mounts")
	}
	if mountedPolicy {
		// startBridge atomically replaces the host files. A Docker restart
		// remounts their current inodes and makes the API server reload policy.
		if _, err = k.command(ctx, "docker", "restart", "--time", "30", server.ID); err != nil {
			return err
		}
	} else {
		// Pre-mount servers, including ones already marked NativeLogging, need
		// fresh copies and the existing config drop-in, never a new filesystem.
		if err = k.installNativeLogging(ctx, *state, dir); err != nil {
			return err
		}
	}
	state.NativeLogging = true
	state.AuditPolicyHash = desired
	return nil
}
