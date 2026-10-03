package eks

import (
	"context"
	"errors"
	"time"

	native "stackd/compute/eks"
	api "stackd/internal/awsapi/eks"
)

func queueComponents(s *Service, tx Transaction, c Cluster) error {
	if c.Status != "ACTIVE" || c.Operation != "" && c.Operation != "components" && c.Operation != "reconcile" {
		return failure("ResourceInUseException", "Cluster has an operation in progress.", 409)
	}
	c.Operation = "components"
	c.Generation++
	c.Due = s.clock.Now()
	return tx.PutCluster(c)
}
func ensureNoComponents(tx Reader, k Key) error {
	profiles, err := tx.FargateProfiles(k)
	if err != nil {
		return err
	}
	if len(profiles) > 0 {
		return failure("ResourceInUseException", "Delete Fargate profiles before deleting the cluster.", 409)
	}
	return nil
}
func (s *Service) startComponents(tx Transaction) error {
	clusters, err := tx.AllClusters()
	if err != nil {
		return err
	}
	for _, c := range clusters {
		addons, err := tx.Addons(c.Key)
		if err != nil {
			return err
		}
		for _, a := range addons {
			if a.Operation == "" && (a.Status == "ACTIVE" || a.Status == "DEGRADED") {
				a.Due = s.clock.Now()
				a.Generation++
				if err = tx.PutAddon(a); err != nil {
					return err
				}
			}
		}
		profiles, err := tx.FargateProfiles(c.Key)
		if err != nil {
			return err
		}
		for _, p := range profiles {
			if p.Status == "ACTIVE" {
				p.Due = s.clock.Now()
				p.Generation++
				if err = tx.PutFargateProfile(p); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func nextComponentDue(tx Reader, k Key) (time.Time, error) {
	var next time.Time
	consider := func(t time.Time) {
		if !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	addons, err := tx.Addons(k)
	if err != nil {
		return next, err
	}
	for _, a := range addons {
		consider(a.Due)
	}
	profiles, err := tx.FargateProfiles(k)
	if err != nil {
		return next, err
	}
	for _, p := range profiles {
		consider(p.Due)
	}
	return next, nil
}
func (s *Service) reconcileComponents(ctx context.Context, c Cluster) error {
	var addons []Addon
	var profiles []FargateProfile
	if err := s.repository.View(ctx, func(tx Reader) error {
		var err error
		addons, err = tx.Addons(c.Key)
		if err != nil {
			return err
		}
		profiles, err = tx.FargateProfiles(c.Key)
		return err
	}); err != nil {
		return err
	}
	for _, a := range addons {
		if !a.Due.IsZero() && !a.Due.After(s.clock.Now()) {
			if err := s.reconcileAddon(ctx, c, a); err != nil {
				return err
			}
		}
	}
	for _, p := range profiles {
		if !p.Due.IsZero() && !p.Due.After(s.clock.Now()) {
			if err := s.reconcileFargate(ctx, c, p); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Service) reconcileAddon(ctx context.Context, c Cluster, a Addon) error {
	runtime, ok := s.runtime.(native.AddonRuntime)
	var observation native.AddonObservation
	var effectErr error
	configuration := a.Configuration
	if a.Operation == "" {
		configuration = a.AppliedConfiguration
	}
	spec := native.AddonSpecification{ClusterID: c.ID, ClusterName: c.Key.Name, Region: c.Key.Region, ID: a.ID, Name: a.Name, Version: a.Version, PreviousVersion: a.AppliedVersion, Configuration: configuration, PreviousConfiguration: a.AppliedConfiguration, ResolveConflicts: a.ResolveConflicts, Delete: a.Operation == "delete", Preserve: a.Preserve, Observe: a.Operation == "", Rollout: a.Operation == "rollout"}
	if a.Operation == "rollback" {
		spec.Version = a.AppliedVersion
		spec.PreviousVersion = a.Version
		spec.Configuration = a.AppliedConfiguration
		spec.PreviousConfiguration = a.Configuration
		spec.ResolveConflicts = "OVERWRITE"
	}
	if !ok {
		effectErr = errors.New("native add-on runtime is unavailable")
	} else {
		observation, effectErr = runtime.ReconcileAddon(ctx, spec)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Addon(c.Key, a.Name)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.ID != a.ID || current.Generation != a.Generation {
			return nil
		}
		if a.Operation == "rollback" {
			current.Generation++
			current.Due = s.clock.Now().Add(5 * time.Second)
			var pending *native.AddonPending
			if errors.As(effectErr, &pending) && s.clock.Now().Before(a.Modified.Add(5*time.Minute)) {
				return tx.PutAddon(current)
			}
			if effectErr != nil {
				current.Error += "; rollback failed: " + effectErr.Error()
				current.ErrorCode = "ClusterUnreachable"
				var addonErr *native.AddonError
				if errors.As(effectErr, &addonErr) {
					current.ErrorCode = addonErr.Code
				} else if pending != nil {
					current.ErrorCode = "InsufficientNumberOfReplicas"
				}
			}
			current.Operation = ""
			current.Status = "UPDATE_FAILED"
			current.Due = time.Time{}
			current.Modified = s.clock.Now()
			if effectErr == nil {
				current.Version = current.AppliedVersion
				current.Configuration = current.AppliedConfiguration
				current.AppliedConfiguration = observation.Configuration
			}
			if current.UpdateID != "" {
				u, err := tx.ClusterUpdate(c.Key, current.UpdateID)
				if err != nil {
					return err
				}
				u.Status = "Failed"
				u.ErrorCode = current.ErrorCode
				u.ErrorMessage = current.Error
				if err = tx.PutClusterUpdate(u); err != nil {
					return err
				}
			}
			return tx.PutAddon(current)
		}
		var pending *native.AddonPending
		if errors.As(effectErr, &pending) {
			if a.Operation != "" && s.clock.Now().Before(a.Modified.Add(5*time.Minute)) {
				current.Generation++
				current.Due = s.clock.Now().Add(5 * time.Second)
				if a.Operation == "update" && observation.Mutated {
					current.Operation = "rollout"
				}
				return tx.PutAddon(current)
			}
			effectErr = &native.AddonError{Code: "InsufficientNumberOfReplicas", Message: pending.Error()}
		}
		current.Generation++
		current.Due = s.clock.Now().Add(5 * time.Second)
		current.Modified = s.clock.Now()
		current.Error = ""
		current.ErrorCode = ""
		if effectErr != nil {
			current.Error = effectErr.Error()
			current.ErrorCode = "ClusterUnreachable"
			var addonErr *native.AddonError
			if errors.As(effectErr, &addonErr) {
				current.ErrorCode = addonErr.Code
			}
			if (a.Operation == "update" || a.Operation == "rollout") && a.Name == "coredns" && a.AppliedVersion != "" && current.ErrorCode != "ConfigurationConflict" && (observation.Mutated || a.Operation == "rollout") {
				current.Operation = "rollback"
				current.Status = "UPDATING"
				return tx.PutAddon(current)
			}
			switch a.Operation {
			case "create":
				if current.ErrorCode == "InsufficientNumberOfReplicas" {
					current.Status = "DEGRADED"
					current.AppliedConfiguration = observation.Configuration
					current.AppliedVersion = a.Version
				} else {
					current.Status = "CREATE_FAILED"
					current.Due = time.Time{}
				}
			case "update", "rollout":
				current.Status = "UPDATE_FAILED"
				current.Due = time.Time{}
			case "delete":
				current.Status = "DELETE_FAILED"
				current.Due = time.Time{}
			default:
				current.Status = "DEGRADED"
			}
		} else {
			current.Status = "ACTIVE"
			current.AppliedConfiguration = observation.Configuration
			current.AppliedVersion = a.Version
			if a.Operation == "delete" {
				current.Status = "DELETED"
			}
		}
		if a.UpdateID != "" && (a.Operation == "update" || a.Operation == "rollout") {
			u, err := tx.ClusterUpdate(c.Key, a.UpdateID)
			if err != nil {
				return err
			}
			if effectErr != nil {
				u.Status = "Failed"
				u.ErrorCode = current.ErrorCode
				u.ErrorMessage = current.Error
			} else {
				u.Status = "Successful"
			}
			if err = tx.PutClusterUpdate(u); err != nil {
				return err
			}
		}
		current.Operation = ""
		if current.Status == "DELETED" {
			return tx.DeleteAddon(c.Key, a.Name)
		}
		return tx.PutAddon(current)
	})
}
func (s *Service) reconcileFargate(ctx context.Context, c Cluster, p FargateProfile) error {
	runtime, ok := s.runtime.(native.FargateRuntime)
	var effectErr error
	if !ok {
		effectErr = errors.New("native Fargate runtime is unavailable")
	} else if p.Operation != "delete" {
		var roleID string
		if s.workloadRoles == nil {
			effectErr = errors.New("fargate execution-role owner is unavailable")
		} else {
			roleID, effectErr = s.workloadRoles.ValidateFargateExecutionRole(ctx, p.RoleARN, p.ARN())
			if effectErr == nil && roleID != p.RoleID {
				effectErr = errors.New("fargate execution role was deleted and recreated")
			}
			if effectErr == nil {
				effectErr = s.workloadRoles.ValidateFargateSubnets(ctx, p.Key, c.VPCID, p.Subnets)
			}
		}
		spec := fargateSpec(c, p)
		spec.AdmissionDenied = effectErr != nil
		spec.RegistryAuthorization = s.fargateRegistryAuthorization(p)
		runtimeErr := runtime.ReconcileFargate(ctx, spec)
		if effectErr == nil {
			effectErr = runtimeErr
		}
	} else {
		effectErr = runtime.ReconcileFargate(ctx, fargateSpec(c, p))
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.FargateProfile(c.Key, p.Name)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.ID != p.ID || current.Generation != p.Generation {
			return nil
		}
		if effectErr == nil && p.Operation == "delete" {
			return tx.DeleteFargateProfile(c.Key, p.Name)
		}
		current.Generation++
		current.Error = ""
		current.Due = s.clock.Now().Add(5 * time.Second)
		if effectErr != nil {
			current.Error = effectErr.Error()
			if p.Operation == "delete" {
				current.Status = "DELETE_FAILED"
				current.Due = time.Time{}
			} else if p.Operation == "create" {
				current.Status = "CREATE_FAILED"
				current.Due = time.Time{}
			}
		} else {
			current.Status = "ACTIVE"
		}
		current.Operation = ""
		return tx.PutFargateProfile(current)
	})
}
func (s *Service) addonDescribeUpdate(ctx context.Context, tx Transaction, in *api.DescribeUpdateRequest) (*api.DescribeUpdateResponse, error) {
	c, _, err := s.loadAddon(ctx, tx, value(in.Name), value(in.AddonName), "DescribeUpdate")
	if err != nil {
		return nil, err
	}
	u, err := tx.ClusterUpdate(c.Key, value(in.UpdateId))
	if err != nil {
		return nil, err
	}
	if u.ResourceType != "addon" || u.ResourceName != value(in.AddonName) {
		return nil, ErrNotFound
	}
	return &api.DescribeUpdateResponse{Update: updateAPI(u)}, nil
}
func (s *Service) addonListUpdates(ctx context.Context, tx Transaction, in *api.ListUpdatesRequest) (*api.ListUpdatesResponse, error) {
	c, _, err := s.loadAddon(ctx, tx, value(in.Name), value(in.AddonName), "ListUpdates")
	if err != nil {
		return nil, err
	}
	updates, err := tx.ClusterUpdates(c.Key)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, u := range updates {
		if u.ResourceType == "addon" && u.ResourceName == value(in.AddonName) {
			names = append(names, u.ID)
		}
	}
	page, next, err := pageStrings(names, value(in.NextToken), pageLimit(in.MaxResults), c.Key.ARN()+"/addons/"+value(in.AddonName)+"/updates")
	if err != nil {
		return nil, err
	}
	return &api.ListUpdatesResponse{UpdateIds: stringsToAPI(page), NextToken: next}, nil
}
