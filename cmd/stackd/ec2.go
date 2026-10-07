//go:build linux

package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"

	"stackd/compute/docker"
	ec2runtime "stackd/compute/ec2"
	"stackd/compute/network"
)

func newEC2Runtime(ctx context.Context, engine *docker.Client, bridges *network.Bridges, config ec2runtime.Config, upstream []netip.Addr) (*ec2runtime.QEMU, ec2runtime.Config, error) {
	var err error
	config.StateDirectory, err = filepath.Abs(config.StateDirectory)
	if err != nil {
		return nil, config, err
	}
	for name, destination := range map[string]*string{
		"qemu-system-x86_64": &config.SystemBinary,
		"qemu-img":           &config.ImageBinary,
		"qemu-nbd":           &config.NBDBinary,
		"qemu-io":            &config.IOBinary,
	} {
		*destination, err = exec.LookPath(name)
		if err != nil {
			return nil, config, fmt.Errorf("EC2 requires installed %s: %w", name, err)
		}
	}
	dnsmasq, err := exec.LookPath("dnsmasq")
	if err != nil {
		return nil, config, fmt.Errorf("EC2 requires installed dnsmasq: %w", err)
	}
	dhcpRelease, err := exec.LookPath("dhcp_release")
	if err != nil {
		return nil, config, fmt.Errorf("EC2 requires installed dhcp_release (dnsmasq-utils): %w", err)
	}
	config.Networks, err = ec2runtime.NewGuestNetworks(ctx, ec2runtime.GuestNetworkConfig{
		Docker: engine, Bridges: bridges, StateDirectory: filepath.Join(config.StateDirectory, "networks"),
		DNSMasqBinary: dnsmasq, DHCPReleaseBinary: dhcpRelease, DNSUpstream: upstream,
	})
	if err != nil {
		return nil, config, err
	}
	config.CPULimits = &ec2runtime.SystemdLimits{Client: engine}
	runtime, err := ec2runtime.NewQEMU(config)
	return runtime, config, err
}
