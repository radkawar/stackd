package codebuild

import (
	"slices"
	"testing"

	"stackd/compute/docker"
)

func TestBuildContainerUsesOnlyExplicitRuntimeDNS(t *testing.T) {
	if _, err := NewDockerExecutor(&docker.Client{}, DockerConfig{Namespace: "dns", Networking: docker.Networking{DNS: []string{"0.0.0.0"}}}); err == nil {
		t.Fatal("unspecified runtime resolver accepted")
	}
	unset, err := NewDockerExecutor(&docker.Client{}, DockerConfig{Namespace: "dns"})
	if err != nil {
		t.Fatal(err)
	}
	if config, err := unset.containerConfig(Specification{ARN: "build", Image: "image"}); err != nil || config.HostConfig.DNS != nil {
		t.Fatalf("daemon resolver default changed: %v %v", config.HostConfig.DNS, err)
	}
	selected, err := NewDockerExecutor(&docker.Client{}, DockerConfig{Namespace: "dns", Networking: docker.Networking{DNS: []string{"192.0.2.53", "198.51.100.53"}}})
	if err != nil {
		t.Fatal(err)
	}
	config, err := selected.containerConfig(Specification{ARN: "build", Image: "image"})
	if err != nil || !slices.Equal(config.HostConfig.DNS, []string{"192.0.2.53", "198.51.100.53"}) {
		t.Fatalf("build resolver not applied: %v %v", config.HostConfig.DNS, err)
	}
}
