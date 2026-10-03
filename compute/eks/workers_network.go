package eks

import (
	"context"
	"errors"
	"fmt"
)

// WorkerNetworks is supplied by the existing shared compute network owner.
// It must preserve EC2's current security-group, NACL and anti-spoof enforcement.
type WorkerNetworks interface {
	ReconcileEKSWorkerPeers(context.Context, string, string, string, int, []string, map[string]string) error
	DeleteEKSWorkerPeers(context.Context, string, string, string) error
}
type WorkerPeer struct{ InstanceARN, Address string }

func (k *K3d) ReconcileWorkerNetwork(ctx context.Context, clusterID, groupID string, workers []WorkerPeer) error {
	c, e := k.workerCluster(clusterID)
	if e != nil {
		return e
	}
	if k.config.WorkerNetworks == nil {
		return errors.New("eks: native EC2 worker packet owner is unavailable")
	}
	if len(workers) == 0 {
		return k.config.WorkerNetworks.DeleteEKSWorkerPeers(ctx, clusterID, groupID, c.state.Token)
	}
	containers, e := k.ownedContainers(ctx, c.state)
	if e != nil {
		return e
	}
	ids := make([]string, 0, len(containers))
	for _, v := range containers {
		if v.Config.Labels[ownerLabel] == c.state.Token && v.Config.Labels[idLabel] == clusterID && v.State.Running {
			if v.Name == "/k3d-"+c.state.Name+"-agent-0" {
				// Complete inner checksums before the host NATs VXLAN packets.
				// Linux nf_nat otherwise misadjusts the outer UDP checksum for
				// encapsulated CHECKSUM_PARTIAL packets (netdev, 2026-09-21).
				// Keep checksum validation enabled on both tunnel endpoints.
				if _, e := k.command(ctx, "docker", "exec", v.ID, "ethtool", "-K", fmt.Sprintf("flannel.%d", c.state.NativePort), "tx", "off"); e != nil {
					return fmt.Errorf("eks: configure worker overlay checksums: %w", e)
				}
			}
			ids = append(ids, v.ID)
		}
	}
	addresses := make(map[string]string, len(workers))
	for _, v := range workers {
		addresses[v.InstanceARN] = v.Address
	}
	return k.config.WorkerNetworks.ReconcileEKSWorkerPeers(ctx, clusterID, groupID, c.state.Token, c.state.NativePort, ids, addresses)
}
