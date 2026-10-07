//go:build !linux

package main

import (
	"errors"
	"testing"

	ec2runtime "stackd/compute/ec2"
)

func TestNonLinuxControllerRejectsEC2Runtime(t *testing.T) {
	config := ec2runtime.Config{StateDirectory: "unavailable-native-state"}
	// The portable controller boundary must not need Linux-only networking or
	// cgroup owners merely to report that explicitly requested EC2 is unsupported.
	driver, actual, err := newEC2Runtime(t.Context(), nil, nil, config, nil)
	var capability *ec2runtime.CapabilityError
	if !errors.As(err, &capability) {
		t.Fatalf("non-Linux controller did not report a native capability error: %v", err)
	}
	if driver != nil {
		t.Fatal("non-Linux controller exposed an executable EC2 backend")
	}
	if actual.StateDirectory != config.StateDirectory || actual.Networks != nil || actual.CPULimits != nil {
		t.Fatalf("unsupported EC2 request constructed native host owners: %+v", actual)
	}
}
