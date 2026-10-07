package main

import (
	"flag"
	"fmt"
	"net"
)

// Docker selects transport only. Every native owner is an explicit opt-in so a
// database engine never inherits another service's host or image prerequisites.
type containerRuntimeFlags struct {
	Lambda, DynamoDB, Kinesis, ECS, CodeBuild, InventoryORC bool
}

func registerContainerRuntimeFlags(flags *flag.FlagSet) *containerRuntimeFlags {
	selection := new(containerRuntimeFlags)
	flags.BoolVar(&selection.Lambda, "lambda-runtime", false, "enable real Lambda containers; requires docker-host, installed images and Linux telemetry helpers")
	flags.BoolVar(&selection.DynamoDB, "dynamodb-runtime", false, "enable real DynamoDB Local databases; requires docker-host and the installed pinned image")
	flags.BoolVar(&selection.Kinesis, "kinesis-runtime", false, "enable real Kafka-backed Kinesis logs; requires docker-host and the installed pinned image")
	flags.BoolVar(&selection.ECS, "ecs-runtime", false, "enable real ECS tasks; requires local rootful Linux Docker with systemd/cgroup v2 and installed toolkit image")
	flags.BoolVar(&selection.CodeBuild, "codebuild-runtime", false, "enable real CodeBuild containers; requires docker-host")
	flags.BoolVar(&selection.InventoryORC, "inventory-orc-runtime", false, "enable native ORC inventory encoding; requires docker-host and the installed ORC image")
	return selection
}

func (selection *containerRuntimeFlags) requireDocker(host string) error {
	if host == "" && (selection.Lambda || selection.DynamoDB || selection.Kinesis || selection.ECS || selection.CodeBuild || selection.InventoryORC) {
		return fmt.Errorf("container runtime flags require an explicit docker-host")
	}
	return nil
}

func containerEndpoint(scheme, explicit string, address *net.TCPAddr) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if address.IP.IsLoopback() {
		return "", fmt.Errorf("containers cannot reach the loopback listener; use -listen %s or an explicit reachable -compute-endpoint", net.JoinHostPort("0.0.0.0", fmt.Sprint(address.Port)))
	}
	return scheme + "://" + net.JoinHostPort("host.docker.internal", fmt.Sprint(address.Port)), nil
}
