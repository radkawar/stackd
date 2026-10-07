package main

import (
	"flag"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestContainerRuntimesRequireExplicitSelection(t *testing.T) {
	flags := flag.NewFlagSet("stackd", flag.ContinueOnError)
	selection := registerContainerRuntimeFlags(flags)
	host := flags.String("docker-host", "", "")
	if err := flags.Parse([]string{"-docker-host", "unix:///desktop.sock", "-lambda-runtime", "-dynamodb-runtime", "-kinesis-runtime"}); err != nil {
		t.Fatal(err)
	}
	if !selection.Lambda || !selection.DynamoDB || !selection.Kinesis {
		t.Fatal("requested Desktop engines were not selected")
	}
	if selection.ECS || selection.CodeBuild || selection.InventoryORC {
		t.Fatal("Desktop engines implicitly selected Linux ECS or unrelated native helpers")
	}
	if err := selection.requireDocker(*host); err != nil {
		t.Fatal(err)
	}
}

func TestDockerTransportDoesNotEnableRuntimes(t *testing.T) {
	flags := flag.NewFlagSet("stackd", flag.ContinueOnError)
	selection := registerContainerRuntimeFlags(flags)
	if err := flags.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if *selection != (containerRuntimeFlags{}) {
		t.Fatal("native runtime was enabled without an explicit flag")
	}
	if err := selection.requireDocker(""); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lambda", "dynamodb", "kinesis", "ecs", "codebuild", "inventory-orc"} {
		t.Run(name, func(t *testing.T) {
			flags := flag.NewFlagSet("stackd", flag.ContinueOnError)
			selection := registerContainerRuntimeFlags(flags)
			if err := flags.Parse([]string{"-" + name + "-runtime"}); err != nil {
				t.Fatal(err)
			}
			if err := selection.requireDocker(""); err == nil {
				t.Fatal("requested native runtime silently disabled without Docker")
			}
		})
	}
}

func TestContainerEndpointUsesActualListenerPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().(*net.TCPAddr)
	_, err = containerEndpoint("http", "", address)
	if err == nil || !strings.Contains(err.Error(), "-listen "+net.JoinHostPort("0.0.0.0", strconv.Itoa(address.Port))) {
		t.Fatalf("loopback rejection did not preserve actual bound port: %v", err)
	}
	explicit := "http://host.docker.internal:4567"
	if endpoint, err := containerEndpoint("http", explicit, address); err != nil || endpoint != explicit {
		t.Fatalf("explicit reachable endpoint was rejected or replaced: %q %v", endpoint, err)
	}
	if endpoint, err := containerEndpoint("http", "", &net.TCPAddr{IP: net.IPv4zero, Port: 4567}); err != nil || endpoint != explicit {
		t.Fatalf("Desktop wildcard endpoint mismatch: %q %v", endpoint, err)
	}
}
