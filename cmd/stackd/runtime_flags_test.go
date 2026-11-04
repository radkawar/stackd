package main

import (
	"flag"
	"net"
	"os"
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

func TestEKSStorageReserveFlagRejectsInvalidValues(t *testing.T) {
	originalFlags, originalArgs := flag.CommandLine, os.Args
	t.Cleanup(func() {
		flag.CommandLine, os.Args = originalFlags, originalArgs
	})
	for _, value := range []string{"0", "-1", "4294967296", "9223372036854775807"} {
		t.Run(value, func(t *testing.T) {
			flag.CommandLine = flag.NewFlagSet("stackd", flag.ContinueOnError)
			os.Args = []string{"stackd", "-eks-storage-reserve-gib=" + value}
			if err := run(); err == nil || !strings.Contains(err.Error(), "eks-storage-reserve-gib") {
				t.Fatalf("expected storage reserve rejection before runtime startup; got %v", err)
			}
			if option := flag.CommandLine.Lookup("eks-storage-reserve-gib"); option == nil || option.DefValue != "64" {
				t.Fatal("native storage reserve flag must default to 64 GiB")
			}
		})
	}
}
