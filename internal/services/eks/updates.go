package eks

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"

	"github.com/google/uuid"
	native "stackd/compute/eks"
	api "stackd/internal/awsapi/eks"
)

func (s *Service) updateClusterConfig(ctx context.Context, tx Transaction, in *api.UpdateClusterConfigRequest) (*api.UpdateClusterConfigResponse, error) {
	c, e := s.load(ctx, tx, value(in.Name), "UpdateClusterConfig")
	if e != nil {
		return nil, e
	}
	hash, e := requestHash(in)
	if e != nil {
		return nil, e
	}
	all, e := tx.ClusterUpdates(c.Key)
	if e != nil {
		return nil, e
	}
	token := value(in.ClientRequestToken)
	for _, u := range all {
		if token != "" && u.ClientToken == token && u.ResourceType == "" {
			if u.RequestHash != hash {
				return nil, invalid("ClientRequestToken was previously used with different parameters.")
			}
			return &api.UpdateClusterConfigResponse{Update: updateAPI(u)}, nil
		}
	}
	if c.Status != "ACTIVE" {
		return nil, failure("ResourceInUseException", "Cluster is not active.", 409)
	}
	if in.ComputeConfig != nil || in.ControlPlaneScalingConfig != nil || in.KubeApiServerConfig != nil || in.KubeControllerManagerConfig != nil || in.KubeSchedulerConfig != nil || in.KubernetesNetworkConfig != nil || in.RemoteNetworkConfig != nil || in.ResourcesVpcConfig != nil || in.StorageConfig != nil || in.UpgradePolicy != nil || in.ZonalShiftConfig != nil {
		return nil, unsupported("The requested cluster configuration is not implemented by this runtime.")
	}
	u := Update{Key: c.Key, ID: uuid.NewString(), Status: "InProgress", Created: s.clock.Now(), ClientToken: token, RequestHash: hash}
	changes := 0
	if in.DeletionProtection != nil && bool(*in.DeletionProtection) != c.DeletionProtection {
		u.DeletionProtection = new(bool(*in.DeletionProtection))
		u.Type = "DeletionProtectionUpdate"
		changes++
	}
	if in.AccessConfig != nil {
		mode := value(in.AccessConfig.AuthenticationMode)
		if !validAuthenticationMode(mode) {
			return nil, invalid("Invalid authentication mode.")
		}
		if mode != c.AuthenticationMode {
			if !authenticationModeTransition(c.AuthenticationMode, mode) {
				return nil, invalid("The cluster authentication mode cannot be changed to the requested mode.")
			}
			u.AuthenticationMode = mode
			u.Type = "AccessConfigUpdate"
			changes++
		}
	}
	if in.Logging != nil {
		logging, err := mergeLogging(c.EnabledLogTypes, in.Logging)
		if err != nil {
			return nil, err
		}
		if !slices.Equal(logging, c.EnabledLogTypes) {
			u.EnabledLogTypes = append([]string{}, logging...)
			u.Type = "LoggingUpdate"
			changes++
		}
	}
	if changes == 0 {
		return nil, invalid("Cluster already has the requested configuration or no configuration update was supplied.")
	}
	if changes > 1 {
		return nil, invalid("Only one type of cluster configuration update can be performed at a time.")
	}
	c.Status = "UPDATING"
	c.Operation = "update:" + u.ID
	c.Generation++
	c.Due = s.clock.Now()
	if e = tx.PutClusterUpdate(u); e != nil {
		return nil, e
	}
	if e = tx.PutCluster(c); e != nil {
		return nil, e
	}
	return &api.UpdateClusterConfigResponse{Update: updateAPI(u)}, nil
}

func (s *Service) updateClusterVersion(ctx context.Context, tx Transaction, in *api.UpdateClusterVersionRequest) (*api.UpdateClusterVersionResponse, error) {
	c, err := s.load(ctx, tx, value(in.Name), "UpdateClusterVersion")
	if err != nil {
		return nil, err
	}
	hash, err := requestHash(in)
	if err != nil {
		return nil, err
	}
	all, err := tx.ClusterUpdates(c.Key)
	if err != nil {
		return nil, err
	}
	token := value(in.ClientRequestToken)
	for _, u := range all {
		if token != "" && u.ClientToken == token && u.ResourceType == "" {
			if u.RequestHash != hash {
				return nil, invalid("ClientRequestToken was previously used with different parameters.")
			}
			return &api.UpdateClusterVersionResponse{Update: updateAPI(u)}, nil
		}
	}
	if c.Status != "ACTIVE" {
		return nil, failure("ResourceInUseException", "Cluster is not active.", 409)
	}
	if in.RollbackConfig != nil {
		return nil, unsupported("Kubernetes version rollback is not supported by the native runtime.")
	}
	version := value(in.Version)
	if !native.UpgradeAllowed(c.KubernetesVersion, version) {
		return nil, invalid("Kubernetes upgrades must advance to the next supported minor version.")
	}
	u := Update{Key: c.Key, ID: uuid.NewString(), Type: "VersionUpdate", Status: "InProgress", Created: s.clock.Now(), ClientToken: token, RequestHash: hash, KubernetesVersion: version}
	c.Status = "UPDATING"
	c.Operation = "update:" + u.ID
	c.Generation++
	c.Due = s.clock.Now()
	if err = tx.PutClusterUpdate(u); err != nil {
		return nil, err
	}
	if err = tx.PutCluster(c); err != nil {
		return nil, err
	}
	return &api.UpdateClusterVersionResponse{Update: updateAPI(u)}, nil
}
func (s *Service) describeUpdate(ctx context.Context, tx Transaction, in *api.DescribeUpdateRequest) (*api.DescribeUpdateResponse, error) {
	if in.NodegroupName != nil {
		if in.AddonName != nil || in.CapabilityName != nil {
			return nil, invalid("Specify only one update resource.")
		}
		return s.nodegroupDescribeUpdate(ctx, tx, in)
	}
	if in.AddonName != nil {
		if in.CapabilityName != nil {
			return nil, invalid("Specify only one update resource.")
		}
		return s.addonDescribeUpdate(ctx, tx, in)
	}
	c, e := s.load(ctx, tx, value(in.Name), "DescribeUpdate")
	if e != nil {
		return nil, e
	}
	if in.CapabilityName != nil {
		return nil, unsupported("Capability updates are not implemented.")
	}
	u, e := tx.ClusterUpdate(c.Key, value(in.UpdateId))
	if e != nil {
		return nil, e
	}
	if u.ResourceType != "" {
		return nil, ErrNotFound
	}
	return &api.DescribeUpdateResponse{Update: updateAPI(u)}, nil
}
func (s *Service) listUpdates(ctx context.Context, tx Transaction, in *api.ListUpdatesRequest) (*api.ListUpdatesResponse, error) {
	if in.NodegroupName != nil {
		if in.AddonName != nil || in.CapabilityName != nil {
			return nil, invalid("Specify only one update resource.")
		}
		return s.nodegroupListUpdates(ctx, tx, in)
	}
	if in.AddonName != nil {
		if in.CapabilityName != nil {
			return nil, invalid("Specify only one update resource.")
		}
		return s.addonListUpdates(ctx, tx, in)
	}
	c, e := s.load(ctx, tx, value(in.Name), "ListUpdates")
	if e != nil {
		return nil, e
	}
	if in.CapabilityName != nil {
		return nil, unsupported("Capability updates are not implemented.")
	}
	all, e := tx.ClusterUpdates(c.Key)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for _, u := range all {
		if u.ResourceType == "" {
			ids = append(ids, u.ID)
		}
	}
	page, next, e := pageStrings(ids, value(in.NextToken), pageLimit(in.MaxResults), c.Key.ARN()+"/updates")
	if e != nil {
		return nil, e
	}
	return &api.ListUpdatesResponse{UpdateIds: stringsToAPI(page), NextToken: next}, nil
}
func updateAPI(u Update) *api.Update {
	out := &api.Update{Id: new(api.String(u.ID)), Type: new(api.UpdateType(u.Type)), Status: new(api.UpdateStatus(u.Status)), CreatedAt: new(u.Created), Errors: api.ErrorDetails{}, Params: api.UpdateParams{}}
	for _, parameter := range u.Params {
		out.Params = append(out.Params, api.UpdateParam{Type: new(api.UpdateParamType(parameter.Type)), Value: new(api.String(parameter.Value))})
	}
	if u.ErrorMessage != "" {
		out.Errors = append(out.Errors, api.ErrorDetail{ErrorCode: new(api.ErrorCode(u.ErrorCode)), ErrorMessage: new(api.String(u.ErrorMessage))})
	}
	if u.DeletionProtection != nil {
		out.Params = append(out.Params, api.UpdateParam{Type: new(api.UpdateParamType("DeletionProtection")), Value: new(api.String(strconv.FormatBool(*u.DeletionProtection)))})
	}
	if u.AuthenticationMode != "" {
		out.Params = append(out.Params, api.UpdateParam{Type: new(api.UpdateParamTypeAUTHENTICATION_MODE), Value: new(api.String(u.AuthenticationMode))})
	}
	if u.KubernetesVersion != "" {
		out.Params = append(out.Params, api.UpdateParam{Type: new(api.UpdateParamTypeVERSION), Value: new(api.String(u.KubernetesVersion))})
	}
	if u.EnabledLogTypes != nil {
		body, _ := json.Marshal(loggingAPI(u.EnabledLogTypes))
		out.Params = append(out.Params, api.UpdateParam{Type: new(api.UpdateParamTypeCLUSTER_LOGGING), Value: new(api.String(body))})
	}
	return out
}
