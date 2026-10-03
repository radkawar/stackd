package eks

import (
	"context"
	"maps"
	"slices"
	native "stackd/compute/eks"
	"time"
)

// NodegroupKey is scoped by the parent cluster and the customer group name.
type NodegroupKey struct {
	Cluster Key
	Name    string
}

func (k NodegroupKey) ARN(id string) string {
	return "arn:" + k.Cluster.Partition + ":eks:" + k.Cluster.Region + ":" + k.Cluster.AccountID + ":nodegroup/" + k.Cluster.Name + "/" + k.Name + "/" + id
}

// Nodegroup retains admitted intent, external ownership references and observed
// membership. Generation fences completions; TemplateGeneration fences launches.
type Nodegroup struct {
	Key                                                                               NodegroupKey
	ID, ClusterID, Status, Operation, ErrorCode, ErrorMessage                         string
	NodeRoleARN, NodeRoleID, Version, ReleaseVersion, AmiType, CapacityType, ImageID  string
	LaunchTemplateID, LaunchTemplateName, LaunchTemplateVersion                       string
	ManagedTemplateID, ManagedTemplateVersion, GroupName, GroupARN, ProfileName       string
	ClientToken, RequestHash, UpdateID                                                string
	Generation, TemplateGeneration, AppliedTemplateGeneration                         int64
	MinSize, MaxSize, DesiredSize, DiskSize, MaxUnavailable, MaxUnavailablePercentage int32
	UpdateStrategy                                                                    string
	Force                                                                             bool
	// The DEFAULT scale-down fence survives recovery and completion until a new update.
	ScaleDownStarted                 bool
	ScaleDownScaleUpVersion          uint64
	Created, Modified, Due, Deadline time.Time
	InstanceTypes, Subnets           []string
	Labels, Tags                     map[string]string
	Taints                           []native.WorkerTaint
	Workers                          []NodegroupWorker
}

// NodegroupWorker is authoritative only when joined with current owner inventory.
type NodegroupWorker struct {
	InstanceID, PrivateIP, AvailabilityZone, TemplateID, TemplateVersion, LifecycleState string
	NodeName, NodeUID, KubeletVersion                                                    string
	Ready, Unschedulable                                                                 bool
	// BootstrapStarted retains the capacity request's clock across later rollout batches.
	BootstrapStarted             time.Time
	DrainStarted, DrainCompleted time.Time
}
type NodegroupUpdate struct {
	Key                                                                 NodegroupKey
	ID, Type, Status, ClientToken, RequestHash, ErrorCode, ErrorMessage string
	Created                                                             time.Time
	Version, ReleaseVersion, LaunchTemplateVersion                      string
	Params                                                              []UpdateParam
}
type nodegroupUpdateKey struct {
	Key NodegroupKey
	ID  string
}
type NodegroupReader interface {
	Nodegroup(NodegroupKey) (Nodegroup, error)
	Nodegroups(Key) ([]Nodegroup, error)
	AllNodegroups() ([]Nodegroup, error)
	NodegroupUpdate(NodegroupKey, string) (NodegroupUpdate, error)
	NodegroupUpdates(NodegroupKey) ([]NodegroupUpdate, error)
}
type NodegroupTransaction interface {
	NodegroupReader
	PutNodegroup(Nodegroup) error
	DeleteNodegroup(NodegroupKey) error
	PutNodegroupUpdate(NodegroupUpdate) error
}

// NodegroupCompute delegates existing IAM, EC2 launch-template and Auto Scaling
// commands. Reconcile and deletion run strictly outside resource transactions.
type NodegroupCompute interface {
	// Admit resolves the customer image and the existing owned ASG's live scaling.
	Admit(context.Context, Cluster, *Nodegroup) (bool, error)
	Reconcile(context.Context, Cluster, Nodegroup, native.WorkerBootstrap, int32) (NodegroupObservation, error)
	Observe(context.Context, Nodegroup) (NodegroupObservation, error)
	Terminate(context.Context, Nodegroup, string, bool) error
	CompleteTermination(context.Context, Nodegroup, string) error
	Delete(context.Context, Nodegroup) (bool, error)
}
type NodegroupObservation struct {
	GroupARN, ManagedTemplateID, ManagedTemplateVersion  string
	MinSize, MaxSize, DesiredSize, AvailabilityZoneCount int32
	ScaleUpVersion                                       uint64
	Workers                                              []NodegroupWorker
}

func cloneNodegroup(v Nodegroup) Nodegroup {
	v.InstanceTypes = slices.Clone(v.InstanceTypes)
	v.Subnets = slices.Clone(v.Subnets)
	v.Labels = maps.Clone(v.Labels)
	v.Tags = maps.Clone(v.Tags)
	v.Taints = slices.Clone(v.Taints)
	v.Workers = slices.Clone(v.Workers)
	return v
}

func cloneNodegroupUpdate(v NodegroupUpdate) NodegroupUpdate {
	v.Params = slices.Clone(v.Params)
	return v
}
