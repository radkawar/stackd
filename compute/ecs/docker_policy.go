package ecs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"stackd/compute/docker"
	"stackd/compute/network"
)

func networkPolicyTable(taskARN string) string {
	return fmt.Sprintf("stackd_ecs_%x", sha256.Sum256([]byte(taskARN)))
}

func (d *DockerExecutor) networkHelper(ctx context.Context, taskARN, network string, command []string, environment []string) ([]byte, error) {
	return docker.RunHelper(ctx, d.client, "ecs-network", docker.ContainerConfig{
		Image: docker.ToolkitImage, Entrypoint: command, Env: environment,
		Labels: map[string]string{dockerTaskLabel: taskARN, dockerRoleLabel: "network-helper"},
		HostConfig: docker.ContainerHostConfig{
			NetworkMode: network, ReadonlyRootfs: true,
			CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"},
			SecurityOpt: []string{"no-new-privileges:true"},
			Memory:      64 << 20, MemorySwap: 64 << 20, PidsLimit: 32,
			LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}},
		},
	})
}

func (e *dockerEnvironment) configureNetwork(ctx context.Context, anchor, callback string) error {
	output, err := e.executor.networkHelper(ctx, e.spec.TaskARN, "container:"+anchor, []string{"cat", "/sys/class/net/eth0/iflink"}, nil)
	if err != nil {
		return fmt.Errorf("discover ECS external veth index: %w", err)
	}
	index, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil || index <= 0 {
		return fmt.Errorf("invalid ECS external veth index %q", output)
	}
	output, err = e.executor.networkHelper(ctx, e.spec.TaskARN, "host", []string{"ip", "-d", "-j", "link", "show", "master", e.network.Device}, nil)
	if err != nil {
		return fmt.Errorf("inspect host network boundary: %w", err)
	}
	var links []struct {
		IfIndex  int    `json:"ifindex"`
		IfName   string `json:"ifname"`
		Master   string `json:"master"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal(output, &links); err != nil {
		return fmt.Errorf("decode native links: %w", err)
	}
	for _, link := range links {
		if link.IfIndex == index && link.Master == e.network.Device && link.LinkInfo.Kind == "veth" {
			e.peer, e.callback = link.IfName, callback
			return e.SetNetworkPolicy(ctx, e.spec.Network.Policy)
		}
	}
	return errors.New("ECS endpoint has no external veth on its owned bridge; refusing unfiltered execution")
}

// SG/NACL replacement is atomic. Public reassociation revokes the former native
// owner and retires its conntrack before admitting traffic to this attachment.
func (e *dockerEnvironment) SetNetworkPolicy(ctx context.Context, policy network.Policy) error {
	e.policyMu.Lock()
	defer e.policyMu.Unlock()
	if e.peer == "" || !policy.Subnet.IsValid() || !policy.Subnet.Contains(e.spec.Network.Address) {
		return errors.New("ECS native policy requires an attached peer and containing logical subnet")
	}
	if err := e.executor.networks.ApplyPolicy(ctx, networkPolicyTable(e.spec.TaskARN), e.spec.Network, policy, e.peer, network.Options{Callback: e.callback, PublicOwner: e.spec.TaskARN}, e.network); err != nil {
		return fmt.Errorf("install ECS outside-customer nftables boundary (host NET_ADMIN, netdev egress and bridge conntrack required): %w", err)
	}
	e.spec.Network.Policy = policy
	e.policyReady = true
	return nil
}

func (d *DockerExecutor) removeNetworkPolicy(ctx context.Context, taskARN string) error {
	return d.networks.RemovePolicy(ctx, networkPolicyTable(taskARN), taskARN)
}
