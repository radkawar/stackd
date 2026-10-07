//go:build !linux

package main

import (
	"context"
	"net/netip"

	"stackd/compute/docker"
	ec2runtime "stackd/compute/ec2"
	"stackd/compute/network"
)

func newEC2Runtime(_ context.Context, _ *docker.Client, _ *network.Bridges, config ec2runtime.Config, _ []netip.Addr) (*ec2runtime.QEMU, ec2runtime.Config, error) {
	runtime, err := ec2runtime.NewQEMU(config)
	return runtime, config, err
}
