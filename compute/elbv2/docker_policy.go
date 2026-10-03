package elbv2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"stackd/compute/docker"
	"stackd/compute/network"
)

func (d *Docker) networkHelper(ctx context.Context, spec Specification, mode string, command, environment []string) ([]byte, error) {
	return docker.RunHelper(ctx, d.client, "elbv2-network", docker.ContainerConfig{
		Image: docker.ToolkitImage, Entrypoint: command, Env: environment,
		Labels: map[string]string{ownerLabel: spec.LoadBalancerARN, attachmentLabel: spec.AttachmentID, "stackd.elbv2.role": "network-helper"},
		HostConfig: docker.ContainerHostConfig{
			NetworkMode: mode, ReadonlyRootfs: true,
			CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"}, SecurityOpt: []string{"no-new-privileges:true"},
			Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32,
			LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}},
		},
	})
}

func (n *dockerNode) configurePolicy(ctx context.Context) error {
	n.policyMu.Lock()
	defer n.policyMu.Unlock()
	n.callback.mu.Lock()
	closed := n.callback.done
	n.callback.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	output, err := n.driver.networkHelper(ctx, n.spec, "container:"+n.id, []string{"cat", "/sys/class/net/eth0/iflink"}, nil)
	if err != nil {
		return fmt.Errorf("discover ALB external veth index: %w", err)
	}
	index, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil || index <= 0 {
		return fmt.Errorf("invalid ALB external veth index %q", output)
	}
	output, err = n.driver.networkHelper(ctx, n.spec, "host", []string{"ip", "-d", "-j", "link", "show", "master", n.bridge.Device}, nil)
	if err != nil {
		return fmt.Errorf("inspect ALB bridge peer: %w", err)
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
		return fmt.Errorf("decode ALB bridge peer: %w", err)
	}
	for _, link := range links {
		if link.IfIndex == index && link.Master == n.bridge.Device && link.LinkInfo.Kind == "veth" {
			n.peer = link.IfName
			return n.setPolicy(ctx, n.policy)
		}
	}
	return errors.New("ALB has no native external veth on its owned bridge; refusing unfiltered sockets")
}

// SetNetworkPolicy atomically replaces the native boundary. A failed update
// detaches data streams and disables listeners, rather than serving old policy.
func (n *dockerNode) SetNetworkPolicy(ctx context.Context, policy network.Policy) error {
	n.policyMu.Lock()
	defer n.policyMu.Unlock()
	// Retain desired policy even on failure: a later relay restart must never
	// revive the last successful, potentially less restrictive boundary.
	n.policy = clonePolicy(policy)
	return n.setPolicy(ctx, n.policy)
}

func (n *dockerNode) setPolicy(ctx context.Context, policy network.Policy) error {
	n.callback.mu.Lock()
	closed := n.callback.done
	n.callback.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if n.peer == "" || !policy.Subnet.IsValid() || !policy.Subnet.Contains(n.spec.Network.Address) {
		n.callback.setEnabled(false)
		return errors.New("ALB policy requires an attached peer and containing logical subnet")
	}
	err := n.driver.networks.ApplyPolicy(ctx, policyTable(n.spec), n.spec.Network, policy, n.peer,
		network.Options{Callback: n.callbackAddress, PublicOwner: resourceKey(n.spec)}, n.bridge)
	if err != nil {
		n.callback.setEnabled(false)
		return fmt.Errorf("install ALB outside-node packet boundary: %w", err)
	}
	n.callback.mu.Lock()
	enabled := n.callback.enabled
	n.callback.mu.Unlock()
	if !enabled {
		n.callback.setEnabled(true)
	}
	return nil
}

func (d *Docker) removePolicy(ctx context.Context, spec Specification) error {
	return d.networks.RemovePolicy(ctx, policyTable(spec), resourceKey(spec))
}

func clonePolicy(policy network.Policy) network.Policy {
	policy.SecurityIngress = slices.Clone(policy.SecurityIngress)
	policy.SecurityEgress = slices.Clone(policy.SecurityEgress)
	policy.ACLIngress = slices.Clone(policy.ACLIngress)
	policy.ACLEgress = slices.Clone(policy.ACLEgress)
	return policy
}
