package eks

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	native "stackd/compute/eks"
	api "stackd/internal/awsapi/eks"
	"strconv"
	"strings"
)

func (s *Service) nodegroupUpdateReplay(w NodegroupTransaction, n Nodegroup, token, hash string) (*NodegroupUpdate, error) {
	all, e := w.NodegroupUpdates(n.Key)
	if e != nil {
		return nil, e
	}
	for _, u := range all {
		if token != "" && u.ClientToken == token {
			if u.RequestHash != hash {
				return nil, invalid("ClientRequestToken was previously used with different parameters.")
			}
			return &u, nil
		}
	}
	return nil, nil
}
func (s *Service) admitNodegroupUpdate(w NodegroupTransaction, n Nodegroup, kind, token, hash string, params []UpdateParam) (NodegroupUpdate, error) {
	if n.Status != "ACTIVE" && n.Status != "DEGRADED" {
		return NodegroupUpdate{}, failure("ResourceInUseException", "Nodegroup has an operation in progress.", 409)
	}
	u := NodegroupUpdate{Key: n.Key, ID: uuid.NewString(), Type: kind, Status: "InProgress", ClientToken: token, RequestHash: hash, Created: s.clock.Now(), Version: n.Version, ReleaseVersion: n.ReleaseVersion, LaunchTemplateVersion: n.LaunchTemplateVersion, Params: params}
	n.Status = "UPDATING"
	n.Operation = kind
	n.UpdateID = u.ID
	n.ErrorCode = ""
	n.ErrorMessage = ""
	n.ScaleDownStarted, n.ScaleDownScaleUpVersion = false, 0
	n.Generation++
	n.Modified = u.Created
	n.Due = u.Created
	if e := w.PutNodegroupUpdate(u); e != nil {
		return u, e
	}
	return u, w.PutNodegroup(n)
}
func (s *Service) updateNodegroupConfig(ctx context.Context, tx Transaction, in *api.UpdateNodegroupConfigRequest) (*api.UpdateNodegroupConfigResponse, error) {
	_, n, e := s.loadNodegroup(ctx, tx, value(in.ClusterName), value(in.NodegroupName), "UpdateNodegroupConfig")
	if e != nil {
		return nil, e
	}
	hash, e := requestHash(in)
	if e != nil {
		return nil, e
	}
	token := value(in.ClientRequestToken)
	old, e := s.nodegroupUpdateReplay(tx, n, token, hash)
	if e != nil {
		return nil, e
	}
	if old != nil {
		return &api.UpdateNodegroupConfigResponse{Update: nodegroupUpdateAPI(*old)}, nil
	}
	if in.NodeRepairConfig != nil || in.WarmPoolConfig != nil {
		return nil, unsupported("Node repair and warm-pool execution are not configured.")
	}
	if in.Labels == nil && in.Taints == nil && in.ScalingConfig == nil && in.UpdateConfig == nil {
		return nil, invalid("No nodegroup configuration update was supplied.")
	}
	if in.Labels != nil {
		for _, k := range in.Labels.RemoveLabels {
			delete(n.Labels, string(k))
		}
		for k, v := range in.Labels.AddOrUpdateLabels {
			n.Labels[string(k)] = string(v)
		}
	}
	if in.Taints != nil {
		remove, e := nodegroupTaints(in.Taints.RemoveTaints)
		if e != nil {
			return nil, e
		}
		add, e := nodegroupTaints(in.Taints.AddOrUpdateTaints)
		if e != nil {
			return nil, e
		}
		taints := make([]native.WorkerTaint, 0, len(n.Taints)+len(add))
		for _, t := range n.Taints {
			keep := true
			for _, v := range remove {
				if t.Key == v.Key && t.Effect == v.Effect && t.Value == v.Value {
					keep = false
				}
			}
			for _, v := range add {
				if t.Key == v.Key && t.Effect == v.Effect {
					keep = false
				}
			}
			if keep {
				taints = append(taints, t)
			}
		}
		n.Taints = append(taints, add...)
	}
	if in.ScalingConfig != nil {
		mergeNodegroupScaling(&n, in.ScalingConfig)
	}
	if e = mergeNodegroupUpdateConfig(&n, in.UpdateConfig); e != nil {
		return nil, e
	}
	if e = validateNodegroup(n); e != nil {
		return nil, e
	}
	n.Force = true
	if in.Labels != nil || in.Taints != nil {
		n.TemplateGeneration++
	}
	params, e := nodegroupConfigParams(in)
	if e != nil {
		return nil, e
	}
	u, e := s.admitNodegroupUpdate(tx, n, "ConfigUpdate", token, hash, params)
	if e != nil {
		return nil, e
	}
	return &api.UpdateNodegroupConfigResponse{Update: nodegroupUpdateAPI(u)}, nil
}
func (s *Service) updateNodegroupVersion(ctx context.Context, tx Transaction, in *api.UpdateNodegroupVersionRequest) (*api.UpdateNodegroupVersionResponse, error) {
	c, n, e := s.loadNodegroup(ctx, tx, value(in.ClusterName), value(in.NodegroupName), "UpdateNodegroupVersion")
	if e != nil {
		return nil, e
	}
	hash, e := requestHash(in)
	if e != nil {
		return nil, e
	}
	token := value(in.ClientRequestToken)
	old, e := s.nodegroupUpdateReplay(tx, n, token, hash)
	if e != nil {
		return nil, e
	}
	if old != nil {
		return &api.UpdateNodegroupVersionResponse{Update: nodegroupUpdateAPI(*old)}, nil
	}
	if c.Status != "ACTIVE" {
		return nil, failure("ResourceInUseException", "Cluster is not active.", 409)
	}
	target := value(in.Version)
	if target == "" {
		target = c.KubernetesVersion
	}
	oldMinor, e := strconv.Atoi(strings.TrimPrefix(n.Version, "1."))
	if e != nil {
		return nil, e
	}
	minor, e := strconv.Atoi(strings.TrimPrefix(target, "1."))
	if e != nil {
		return nil, invalid("Invalid Kubernetes version.")
	}
	clusterMinor, e := strconv.Atoi(strings.TrimPrefix(c.KubernetesVersion, "1."))
	if e != nil {
		return nil, e
	}
	if minor < oldMinor || minor > clusterMinor || minor > oldMinor+1 {
		return nil, invalid("Nodegroup upgrades must advance by at most one minor version and cannot exceed the cluster version.")
	}
	if in.LaunchTemplate != nil {
		if n.LaunchTemplateID == "" && n.LaunchTemplateName == "" {
			return nil, invalid("This nodegroup was not created with a customer launch template.")
		}
		if id := value(in.LaunchTemplate.Id); id != "" && id != n.LaunchTemplateID {
			return nil, invalid("Launch template ID cannot change.")
		}
		if name := value(in.LaunchTemplate.Name); name != "" && name != n.LaunchTemplateName {
			return nil, invalid("Launch template name cannot change.")
		}
		if value(in.LaunchTemplate.Version) == "" {
			return nil, invalid("A launch template version is required.")
		}
		n.LaunchTemplateVersion = value(in.LaunchTemplate.Version)
	}
	n.Version = target
	n.ReleaseVersion = value(in.ReleaseVersion)
	n.TemplateGeneration++
	n.Force = in.Force != nil && bool(*in.Force)
	if s.nodegroups == nil {
		return nil, unsupported("Managed nodegroup owners are unavailable.")
	}
	customImage, e := s.nodegroups.Admit(ctx, c, &n)
	if e != nil {
		return nil, e
	}
	if customImage && (in.Version != nil || in.ReleaseVersion != nil) {
		return nil, invalid("A custom AMI launch template cannot be combined with version or releaseVersion.")
	}
	u, e := s.admitNodegroupUpdate(tx, n, "VersionUpdate", token, hash, nil)
	if e != nil {
		return nil, e
	}
	return &api.UpdateNodegroupVersionResponse{Update: nodegroupUpdateAPI(u)}, nil
}
func (s *Service) nodegroupDescribeUpdate(ctx context.Context, tx Transaction, in *api.DescribeUpdateRequest) (*api.DescribeUpdateResponse, error) {
	_, n, e := s.loadNodegroup(ctx, tx, value(in.Name), value(in.NodegroupName), "DescribeUpdate")
	if e != nil {
		return nil, e
	}
	u, e := tx.NodegroupUpdate(n.Key, value(in.UpdateId))
	if e != nil {
		return nil, e
	}
	return &api.DescribeUpdateResponse{Update: nodegroupUpdateAPI(u)}, nil
}
func (s *Service) nodegroupListUpdates(ctx context.Context, tx Transaction, in *api.ListUpdatesRequest) (*api.ListUpdatesResponse, error) {
	_, n, e := s.loadNodegroup(ctx, tx, value(in.Name), value(in.NodegroupName), "ListUpdates")
	if e != nil {
		return nil, e
	}
	all, e := tx.NodegroupUpdates(n.Key)
	if e != nil {
		return nil, e
	}
	ids := make([]string, 0, len(all))
	for _, u := range all {
		ids = append(ids, u.ID)
	}
	page, next, e := pageStrings(ids, value(in.NextToken), pageLimit(in.MaxResults), n.Key.ARN(n.ID)+"/updates")
	if e != nil {
		return nil, e
	}
	return &api.ListUpdatesResponse{UpdateIds: stringsToAPI(page), NextToken: next}, nil
}
func nodegroupUpdateAPI(u NodegroupUpdate) *api.Update {
	out := &api.Update{Id: new(api.String(u.ID)), Type: new(api.UpdateType(u.Type)), Status: new(api.UpdateStatus(u.Status)), CreatedAt: new(u.Created), Errors: api.ErrorDetails{}, Params: api.UpdateParams{}}
	if u.ErrorMessage != "" {
		out.Errors = append(out.Errors, api.ErrorDetail{ErrorCode: new(api.ErrorCode(u.ErrorCode)), ErrorMessage: new(api.String(u.ErrorMessage))})
	}
	for _, p := range u.Params {
		out.Params = append(out.Params, api.UpdateParam{Type: new(api.UpdateParamType(p.Type)), Value: new(api.String(p.Value))})
	}
	if u.Type == "VersionUpdate" {
		out.Params = append(out.Params, api.UpdateParam{Type: new(api.UpdateParamType("Version")), Value: new(api.String(u.Version))})
		if u.ReleaseVersion != "" {
			out.Params = append(out.Params, api.UpdateParam{Type: new(api.UpdateParamType("ReleaseVersion")), Value: new(api.String(u.ReleaseVersion))})
		}
		if u.LaunchTemplateVersion != "" {
			out.Params = append(out.Params, api.UpdateParam{Type: new(api.UpdateParamType("LaunchTemplateVersion")), Value: new(api.String(u.LaunchTemplateVersion))})
		}
	}
	return out
}

// Keep the admitted fields, not a projection of mutable nodegroup configuration:
// DescribeUpdate and token replay must describe this request after later updates.
func nodegroupConfigParams(in *api.UpdateNodegroupConfigRequest) ([]UpdateParam, error) {
	params := []UpdateParam{}
	addJSON := func(kind string, value any) error {
		body, err := json.Marshal(value)
		if err != nil {
			return err
		}
		params = append(params, UpdateParam{Type: kind, Value: string(body)})
		return nil
	}
	if in.Labels != nil {
		if in.Labels.AddOrUpdateLabels != nil {
			if err := addJSON("LabelsToAdd", in.Labels.AddOrUpdateLabels); err != nil {
				return nil, err
			}
		}
		if in.Labels.RemoveLabels != nil {
			if err := addJSON("LabelsToRemove", in.Labels.RemoveLabels); err != nil {
				return nil, err
			}
		}
	}
	if in.Taints != nil {
		if in.Taints.AddOrUpdateTaints != nil {
			if err := addJSON("TaintsToAdd", in.Taints.AddOrUpdateTaints); err != nil {
				return nil, err
			}
		}
		if in.Taints.RemoveTaints != nil {
			if err := addJSON("TaintsToRemove", in.Taints.RemoveTaints); err != nil {
				return nil, err
			}
		}
	}
	if v := in.ScalingConfig; v != nil {
		if v.MinSize != nil {
			params = append(params, UpdateParam{Type: "MinSize", Value: strconv.FormatInt(int64(*v.MinSize), 10)})
		}
		if v.MaxSize != nil {
			params = append(params, UpdateParam{Type: "MaxSize", Value: strconv.FormatInt(int64(*v.MaxSize), 10)})
		}
		if v.DesiredSize != nil {
			params = append(params, UpdateParam{Type: "DesiredSize", Value: strconv.FormatInt(int64(*v.DesiredSize), 10)})
		}
	}
	if v := in.UpdateConfig; v != nil {
		if v.MaxUnavailable != nil {
			params = append(params, UpdateParam{Type: "MaxUnavailable", Value: strconv.FormatInt(int64(*v.MaxUnavailable), 10)})
		}
		if v.MaxUnavailablePercentage != nil {
			params = append(params, UpdateParam{Type: "MaxUnavailablePercentage", Value: strconv.FormatInt(int64(*v.MaxUnavailablePercentage), 10)})
		}
		if v.UpdateStrategy != nil {
			params = append(params, UpdateParam{Type: "UpdateStrategy", Value: value(v.UpdateStrategy)})
		}
	}
	return params, nil
}
