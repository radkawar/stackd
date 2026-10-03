package docker

// ContainerConfig contains native Engine container creation fields, independent
// of any service's deployment or execution model.
type ContainerConfig struct {
	Image                string
	Entrypoint           []string `json:",omitempty"`
	Cmd, Env             []string `json:",omitempty"`
	WorkingDir, User     string   `json:",omitempty"`
	Labels               map[string]string
	OpenStdin, StdinOnce bool                       `json:",omitempty"`
	NetworkDisabled      bool                       `json:",omitempty"`
	MacAddress           string                     `json:",omitempty"`
	NetworkingConfig     *ContainerNetworkingConfig `json:",omitempty"`
	Healthcheck          *ContainerHealthConfig     `json:",omitempty"`
	HostConfig           ContainerHostConfig
}

type ContainerHostConfig struct {
	NetworkMode                                        string `json:",omitempty"`
	CgroupParent                                       string `json:",omitempty"`
	AutoRemove                                         bool   `json:",omitempty"`
	Privileged                                         bool   `json:",omitempty"`
	ReadonlyRootfs                                     bool
	Memory, MemorySwap, CPUPeriod, CPUQuota, PidsLimit int64
	MemoryReservation, CPUShares                       int64    `json:",omitempty"`
	CapAdd, CapDrop, SecurityOpt, ExtraHosts           []string `json:",omitempty"`
	Mounts                                             []ContainerMount
	LogConfig                                          ContainerLogConfig
}

type ContainerHealthConfig struct {
	Test                           []string
	Interval, Timeout, StartPeriod int64
	Retries                        int
}

type ContainerNetworkingConfig struct {
	EndpointsConfig map[string]ContainerEndpointConfig
}

type ContainerEndpointConfig struct {
	IPAMConfig ContainerEndpointIPAMConfig
}

type ContainerEndpointIPAMConfig struct {
	IPv4Address string
}

type ContainerMount struct {
	Type, Source, Target string
	ReadOnly             bool                   `json:",omitempty"`
	VolumeOptions        ContainerVolumeOptions `json:",omitzero"`
}

type ContainerVolumeOptions struct {
	NoCopy bool
	// Labels also identify volumes implicitly created by a late container create.
	Labels map[string]string `json:",omitempty"`
}

type ContainerLogConfig struct {
	Type   string
	Config map[string]string `json:",omitempty"`
}

type VolumeConfig struct {
	Name       string
	Driver     string `json:",omitempty"`
	Labels     map[string]string
	DriverOpts map[string]string `json:",omitempty"`
}
