package eks

import (
	"encoding/json"
	domain "stackd/internal/services/eks"
	"stackd/storage/sqlite/eks/internal/sqlcgen"
)

func (r reader) Nodegroup(k domain.NodegroupKey) (domain.Nodegroup, error) {
	row, e := r.q.GetNodegroup(r.ctx, sqlcgen.GetNodegroupParams{Partition: k.Cluster.Partition, AccountID: k.Cluster.AccountID, Region: k.Cluster.Region, ClusterName: k.Cluster.Name, Name: k.Name})
	if e != nil {
		return domain.Nodegroup{}, missing(e)
	}
	return r.readNodegroup(row)
}
func (r reader) Nodegroups(k domain.Key) ([]domain.Nodegroup, error) {
	rows, e := r.q.ListNodegroups(r.ctx, sqlcgen.ListNodegroupsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Nodegroup, 0, len(rows))
	for _, row := range rows {
		v, e := r.readNodegroup(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) AllNodegroups() ([]domain.Nodegroup, error) {
	rows, e := r.q.AllNodegroups(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Nodegroup, 0, len(rows))
	for _, row := range rows {
		v, e := r.readNodegroup(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) readNodegroup(row sqlcgen.EksNodegroup) (domain.Nodegroup, error) {
	v := domain.Nodegroup{Key: domain.NodegroupKey{Cluster: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.ClusterName}, Name: row.Name}, ID: row.ID,
		ClusterID:                 row.ClusterID,
		Status:                    row.Status,
		Operation:                 row.Operation,
		ErrorCode:                 row.ErrorCode,
		ErrorMessage:              row.ErrorMessage,
		NodeRoleARN:               row.NodeRoleArn,
		NodeRoleID:                row.NodeRoleID,
		Version:                   row.Version,
		ReleaseVersion:            row.ReleaseVersion,
		AmiType:                   row.AmiType,
		CapacityType:              row.CapacityType,
		ImageID:                   row.ImageID,
		LaunchTemplateID:          row.LaunchTemplateID,
		LaunchTemplateName:        row.LaunchTemplateName,
		LaunchTemplateVersion:     row.LaunchTemplateVersion,
		ManagedTemplateID:         row.ManagedTemplateID,
		ManagedTemplateVersion:    row.ManagedTemplateVersion,
		GroupName:                 row.GroupName,
		GroupARN:                  row.GroupArn,
		ProfileName:               row.ProfileName,
		ClientToken:               row.ClientToken,
		RequestHash:               row.RequestHash,
		UpdateID:                  row.UpdateID,
		Generation:                row.Generation,
		TemplateGeneration:        row.TemplateGeneration,
		AppliedTemplateGeneration: row.AppliedTemplateGeneration,
		MinSize:                   int32(row.MinSize),
		MaxSize:                   int32(row.MaxSize),
		DesiredSize:               int32(row.DesiredSize),
		DiskSize:                  int32(row.DiskSize),
		MaxUnavailable:            int32(row.MaxUnavailable),
		MaxUnavailablePercentage:  int32(row.MaxUnavailablePercentage),
		UpdateStrategy:            row.UpdateStrategy,
		Force:                     row.Force != 0,
		ScaleDownStarted:          row.ScaleDownStarted != 0,
		ScaleDownScaleUpVersion:   uint64(row.ScaleDownScaleUpVersion),
		Created:                   readTime(row.Created),
		Modified:                  readTime(row.Modified),
		Due:                       readTime(row.Due),
		Deadline:                  readTime(row.Deadline)}
	if e := json.Unmarshal([]byte(row.InstanceTypes), &v.InstanceTypes); e != nil {
		return v, e
	}
	if e := json.Unmarshal([]byte(row.Subnets), &v.Subnets); e != nil {
		return v, e
	}
	if e := json.Unmarshal([]byte(row.Labels), &v.Labels); e != nil {
		return v, e
	}
	if e := json.Unmarshal([]byte(row.Tags), &v.Tags); e != nil {
		return v, e
	}
	if e := json.Unmarshal([]byte(row.Taints), &v.Taints); e != nil {
		return v, e
	}
	k := v.Key
	workers, e := r.q.ListNodegroupWorkers(r.ctx, sqlcgen.ListNodegroupWorkersParams{Partition: k.Cluster.Partition, AccountID: k.Cluster.AccountID, Region: k.Cluster.Region, ClusterName: k.Cluster.Name, Name: k.Name})
	if e != nil {
		return v, e
	}
	for _, row := range workers {
		v.Workers = append(v.Workers, domain.NodegroupWorker{InstanceID: row.InstanceID,
			PrivateIP:        row.PrivateIp,
			AvailabilityZone: row.AvailabilityZone,
			TemplateID:       row.TemplateID,
			TemplateVersion:  row.TemplateVersion,
			LifecycleState:   row.LifecycleState,
			NodeName:         row.NodeName,
			NodeUID:          row.NodeUid,
			KubeletVersion:   row.KubeletVersion,
			Ready:            row.Ready != 0,
			Unschedulable:    row.Unschedulable != 0,
			BootstrapStarted: readTime(row.BootstrapStarted),
			DrainStarted:     readTime(row.DrainStarted),
			DrainCompleted:   readTime(row.DrainCompleted)})
	}
	return v, nil
}
func (w writer) PutNodegroup(v domain.Nodegroup) error {
	k := v.Key
	p := sqlcgen.PutNodegroupParams{Partition: k.Cluster.Partition, AccountID: k.Cluster.AccountID, Region: k.Cluster.Region, ClusterName: k.Cluster.Name, Name: k.Name, ID: v.ID,
		ClusterID:                 v.ClusterID,
		Status:                    v.Status,
		Operation:                 v.Operation,
		ErrorCode:                 v.ErrorCode,
		ErrorMessage:              v.ErrorMessage,
		NodeRoleArn:               v.NodeRoleARN,
		NodeRoleID:                v.NodeRoleID,
		Version:                   v.Version,
		ReleaseVersion:            v.ReleaseVersion,
		AmiType:                   v.AmiType,
		CapacityType:              v.CapacityType,
		ImageID:                   v.ImageID,
		LaunchTemplateID:          v.LaunchTemplateID,
		LaunchTemplateName:        v.LaunchTemplateName,
		LaunchTemplateVersion:     v.LaunchTemplateVersion,
		ManagedTemplateID:         v.ManagedTemplateID,
		ManagedTemplateVersion:    v.ManagedTemplateVersion,
		GroupName:                 v.GroupName,
		GroupArn:                  v.GroupARN,
		ProfileName:               v.ProfileName,
		ClientToken:               v.ClientToken,
		RequestHash:               v.RequestHash,
		UpdateID:                  v.UpdateID,
		Generation:                v.Generation,
		TemplateGeneration:        v.TemplateGeneration,
		AppliedTemplateGeneration: v.AppliedTemplateGeneration,
		MinSize:                   int64(v.MinSize),
		MaxSize:                   int64(v.MaxSize),
		DesiredSize:               int64(v.DesiredSize),
		DiskSize:                  int64(v.DiskSize),
		MaxUnavailable:            int64(v.MaxUnavailable),
		MaxUnavailablePercentage:  int64(v.MaxUnavailablePercentage),
		UpdateStrategy:            v.UpdateStrategy,
		Force:                     bit(v.Force),
		ScaleDownStarted:          bit(v.ScaleDownStarted),
		ScaleDownScaleUpVersion:   int64(v.ScaleDownScaleUpVersion),
		Created:                   timeValue(v.Created),
		Modified:                  timeValue(v.Modified),
		Due:                       timeValue(v.Due),
		Deadline:                  timeValue(v.Deadline)}
	{
		b, e := json.Marshal(v.InstanceTypes)
		if e != nil {
			return e
		}
		p.InstanceTypes = string(b)
	}
	{
		b, e := json.Marshal(v.Subnets)
		if e != nil {
			return e
		}
		p.Subnets = string(b)
	}
	{
		b, e := json.Marshal(v.Labels)
		if e != nil {
			return e
		}
		p.Labels = string(b)
	}
	{
		b, e := json.Marshal(v.Tags)
		if e != nil {
			return e
		}
		p.Tags = string(b)
	}
	{
		b, e := json.Marshal(v.Taints)
		if e != nil {
			return e
		}
		p.Taints = string(b)
	}
	if e := w.q.PutNodegroup(w.ctx, p); e != nil {
		return e
	}
	if e := w.q.DeleteNodegroupWorkers(w.ctx, sqlcgen.DeleteNodegroupWorkersParams{Partition: k.Cluster.Partition, AccountID: k.Cluster.AccountID, Region: k.Cluster.Region, ClusterName: k.Cluster.Name, Name: k.Name}); e != nil {
		return e
	}
	for _, v := range v.Workers {
		if e := w.q.PutNodegroupWorker(w.ctx, sqlcgen.PutNodegroupWorkerParams{Partition: k.Cluster.Partition, AccountID: k.Cluster.AccountID, Region: k.Cluster.Region, ClusterName: k.Cluster.Name, Name: k.Name, InstanceID: v.InstanceID,
			PrivateIp:        v.PrivateIP,
			AvailabilityZone: v.AvailabilityZone,
			TemplateID:       v.TemplateID,
			TemplateVersion:  v.TemplateVersion,
			LifecycleState:   v.LifecycleState,
			NodeName:         v.NodeName,
			NodeUid:          v.NodeUID,
			KubeletVersion:   v.KubeletVersion,
			Ready:            bit(v.Ready),
			Unschedulable:    bit(v.Unschedulable),
			BootstrapStarted: timeValue(v.BootstrapStarted),
			DrainStarted:     timeValue(v.DrainStarted),
			DrainCompleted:   timeValue(v.DrainCompleted)}); e != nil {
			return e
		}
	}
	return nil
}
func (w writer) DeleteNodegroup(k domain.NodegroupKey) error {
	return w.q.DeleteNodegroup(w.ctx, sqlcgen.DeleteNodegroupParams{Partition: k.Cluster.Partition, AccountID: k.Cluster.AccountID, Region: k.Cluster.Region, ClusterName: k.Cluster.Name, Name: k.Name})
}
func (w writer) deleteClusterNodegroups(k domain.Key) error {
	return w.q.DeleteClusterNodegroups(w.ctx, sqlcgen.DeleteClusterNodegroupsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name})
}
func (r reader) NodegroupUpdate(k domain.NodegroupKey, id string) (domain.NodegroupUpdate, error) {
	row, e := r.q.GetNodegroupUpdate(r.ctx, sqlcgen.GetNodegroupUpdateParams{Partition: k.Cluster.Partition, AccountID: k.Cluster.AccountID, Region: k.Cluster.Region, ClusterName: k.Cluster.Name, Name: k.Name, ID: id})
	if e != nil {
		return domain.NodegroupUpdate{}, missing(e)
	}
	return readNodegroupUpdate(row)
}
func (r reader) NodegroupUpdates(k domain.NodegroupKey) ([]domain.NodegroupUpdate, error) {
	rows, e := r.q.ListNodegroupUpdates(r.ctx, sqlcgen.ListNodegroupUpdatesParams{Partition: k.Cluster.Partition, AccountID: k.Cluster.AccountID, Region: k.Cluster.Region, ClusterName: k.Cluster.Name, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := make([]domain.NodegroupUpdate, 0, len(rows))
	for _, row := range rows {
		v, err := readNodegroupUpdate(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func readNodegroupUpdate(row sqlcgen.EksNodegroupUpdate) (domain.NodegroupUpdate, error) {
	v := domain.NodegroupUpdate{Key: domain.NodegroupKey{Cluster: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.ClusterName}, Name: row.Name}, ID: row.ID,
		Type:                  row.Type,
		Status:                row.Status,
		ClientToken:           row.ClientToken,
		RequestHash:           row.RequestHash,
		ErrorCode:             row.ErrorCode,
		ErrorMessage:          row.ErrorMessage,
		Created:               readTime(row.Created),
		Version:               row.Version,
		ReleaseVersion:        row.ReleaseVersion,
		LaunchTemplateVersion: row.LaunchTemplateVersion}
	err := json.Unmarshal([]byte(row.ParamsJson), &v.Params)
	return v, err
}
func (w writer) PutNodegroupUpdate(v domain.NodegroupUpdate) error {
	k := v.Key
	params, err := json.Marshal(v.Params)
	if err != nil {
		return err
	}
	return w.q.PutNodegroupUpdate(w.ctx, sqlcgen.PutNodegroupUpdateParams{Partition: k.Cluster.Partition, AccountID: k.Cluster.AccountID, Region: k.Cluster.Region, ClusterName: k.Cluster.Name, Name: k.Name, ID: v.ID,
		Type:                  v.Type,
		Status:                v.Status,
		ClientToken:           v.ClientToken,
		RequestHash:           v.RequestHash,
		ErrorCode:             v.ErrorCode,
		ErrorMessage:          v.ErrorMessage,
		Created:               timeValue(v.Created),
		Version:               v.Version,
		ReleaseVersion:        v.ReleaseVersion,
		LaunchTemplateVersion: v.LaunchTemplateVersion,
		ParamsJson:            string(params)})
}

var _ domain.NodegroupTransaction = writer{}
