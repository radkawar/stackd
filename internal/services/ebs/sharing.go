package ebs

import (
	"context"
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

func snapshotShare(v SnapshotRecord, account string) (SnapshotShare, bool) {
	for _, share := range v.Shares {
		if share.AccountID == account {
			return share, true
		}
	}
	return SnapshotShare{}, false
}

func snapshotControlID(id string, reset bool) error {
	// TODO: Comeback implement AWS's opaque long-ID validity encoding once its
	// general contract is established; volume_controls_snapshot_ids_contract.json
	// records native digit-dependent rejection beyond the public length/hex syntax.
	valid := strings.HasPrefix(id, "snap-") && (len(id) == 13 || len(id) == 22)
	if valid {
		nonzero := false
		for _, c := range id[5:] {
			if !strings.ContainsRune("0123456789abcdef", c) {
				valid = false
			}
			nonzero = nonzero || c != '0'
		}
		valid = valid && nonzero
	}
	if valid {
		return nil
	}
	if reset {
		return ec2Failure("InvalidSnapshotID.Malformed", "The snapshot ID '"+id+"' is malformed")
	}
	if !strings.HasPrefix(id, "snap-") {
		return ec2Failure("InvalidParameterValue", "Value ("+id+") for parameter snapshotId is invalid. Expected: 'snap-...'.")
	}
	return ec2Failure("InvalidSnapshotID.Malformed", "Value ( "+id+" ) for parameter SNAPSHOT is invalid. ")
}

// Attribute admission is intentionally ordered: Modify validates IDs and owned
// existence before ordinary IAM; Describe/Reset perform IAM and DryRun first.
func (s *Service) snapshotAttribute(ctx context.Context, action, id string, dry *api.Boolean, conditions map[string][]string, apply func(Transaction, *SnapshotRecord) error) error {
	if err := s.advance(ctx); err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		if action == "ModifySnapshotAttribute" {
			if err := snapshotControlID(id, false); err != nil {
				return err
			}
		}
		scope := scopeFor(ctx)
		v, lookup := tx.RegionalSnapshot(scope.Partition, scope.Region, id)
		if lookup != nil && !errors.Is(lookup, ErrNotFound) {
			return lookup
		}
		owned := lookup == nil && !v.Deleted && v.Key.AccountID == scope.AccountID
		if lookup == nil {
			s.observeSnapshot(tx.Context(), v)
		}
		if lookup != nil {
			v.Key = SnapshotKey{Scope: scope, ID: id}
		}
		isDry := dry != nil && bool(*dry)
		if action == "ModifySnapshotAttribute" && !isDry && !owned {
			return ec2SnapshotMissing(id)
		}
		if err := s.authorize(tx.Context(), "ec2", action, v, conditions); err != nil {
			return err
		}
		if err := ec2DryRun(dry); err != nil {
			return err
		}
		if action != "ModifySnapshotAttribute" {
			if err := snapshotControlID(id, action == "ResetSnapshotAttribute"); err != nil {
				return err
			}
		}
		if !owned {
			return ec2SnapshotMissing(id)
		}
		return apply(tx, &v)
	})
}

func (s *Service) DescribeSnapshotAttribute(ctx context.Context, in *api.DescribeSnapshotAttributeRequest) (*api.DescribeSnapshotAttributeResult, error) {
	attribute := value(in.Attribute)
	if attribute != "createVolumePermission" && attribute != "productCodes" {
		return nil, ec2Failure("InvalidRequest", "The request received was invalid.")
	}
	out := &api.DescribeSnapshotAttributeResult{SnapshotId: new(api.String(value(in.SnapshotId)))}
	err := s.snapshotAttribute(ctx, "DescribeSnapshotAttribute", value(in.SnapshotId), in.DryRun, nil, func(_ Transaction, v *SnapshotRecord) error {
		if attribute == "productCodes" {
			out.ProductCodes = api.ProductCodeList{}
			return nil
		}
		out.CreateVolumePermissions = api.CreateVolumePermissionList{}
		if v.Public {
			out.CreateVolumePermissions = append(out.CreateVolumePermissions, api.CreateVolumePermission{Group: new(api.PermissionGroup("all"))})
		}
		for _, share := range v.Shares {
			if share.Granted {
				out.CreateVolumePermissions = append(out.CreateVolumePermissions, api.CreateVolumePermission{UserId: new(api.String(share.AccountID))})
			}
		}
		return nil
	})
	return out, err
}

type snapshotPermissionChange struct {
	add, legacy bool
	items       api.CreateVolumePermissionList
}

func permissionChange(in *api.ModifySnapshotAttributeRequest) (snapshotPermissionChange, error) {
	var change snapshotPermissionChange
	var add, remove api.CreateVolumePermissionList
	hasItem := func(item api.CreateVolumePermission) bool { return item.UserId != nil || item.Group != nil }
	if in.CreateVolumePermission != nil {
		add, remove = in.CreateVolumePermission.Add, in.CreateVolumePermission.Remove
	}
	hasAdd, hasRemove := slices.ContainsFunc(add, hasItem), slices.ContainsFunc(remove, hasItem)
	if hasAdd || hasRemove {
		if hasAdd && hasRemove {
			return change, ec2Failure("InvalidParameterCombination", "One and only one operation type may be specified for createVolumePermissions")
		}
		change.add, change.items = hasAdd, remove
		if change.add {
			change.items = add
		}
	} else {
		if in.Attribute == nil && in.OperationType == nil && len(in.UserIds) == 0 && len(in.GroupNames) == 0 {
			return change, ec2Failure("InvalidParameterCombination", "No attributes specified.")
		}
		if value(in.Attribute) == "" {
			return change, ec2Failure("MissingParameter", "Value for parameter attribute is invalid. Parameter may not be null or empty.")
		}
		if value(in.Attribute) != "createVolumePermission" {
			return change, ec2Failure("InvalidParameterValue", "Unrecognized attribute.")
		}
		operation := value(in.OperationType)
		if operation != "add" && operation != "remove" {
			return change, ec2Failure("InvalidParameterCombination", "No operation specified for createVolumePermission attribute.")
		}
		change.add, change.legacy = operation == "add", true
		for _, id := range in.UserIds {
			change.items = append(change.items, api.CreateVolumePermission{UserId: new(api.String(id))})
		}
		for _, group := range in.GroupNames {
			change.items = append(change.items, api.CreateVolumePermission{Group: new(api.PermissionGroup(group))})
		}
	}
	count := 0
	for _, item := range change.items {
		if item.UserId != nil {
			count++
		}
		if item.Group != nil {
			count++
		}
	}
	if count > 500 {
		return change, ec2Failure("InvalidParameterValue", "Modification size must not be greater than 500.")
	}
	return change, nil
}

func (c snapshotPermissionChange) conditions() map[string][]string {
	prefix := "ec2:Remove/"
	if c.add {
		prefix = "ec2:Add/"
	}
	userKey, groupKey := prefix+"userId", prefix+"group"
	conditions := map[string][]string{}
	for _, item := range c.items {
		if item.UserId != nil {
			conditions[userKey] = append(conditions[userKey], value(item.UserId))
		}
		if item.Group != nil {
			conditions[groupKey] = append(conditions[groupKey], value(item.Group))
		}
	}
	// Native authorization uses distinct values, not raw mutation cardinality.
	for key, values := range conditions {
		slices.Sort(values)
		conditions[key] = slices.Compact(values)
	}
	return conditions
}

func (s *Service) ModifySnapshotAttribute(ctx context.Context, in *api.ModifySnapshotAttributeRequest) (*api.Unit, error) {
	change, err := permissionChange(in)
	if err != nil {
		return nil, err
	}
	err = s.snapshotAttribute(ctx, "ModifySnapshotAttribute", value(in.SnapshotId), in.DryRun, change.conditions(), func(tx Transaction, v *SnapshotRecord) error {
		public := false
		accounts := false
		for _, item := range change.items {
			if item.UserId != nil {
				id := value(item.UserId)
				valid := len(id) == 12
				for _, c := range id {
					valid = valid && c >= '0' && c <= '9'
				}
				if !valid {
					message := "UserId " + id
					if change.legacy {
						message = "UserId (" + id + ") is invalid."
					}
					return ec2Failure("InvalidAMIAttributeItemValue", message)
				}
				accounts = true
			}
			if item.Group != nil {
				if value(item.Group) != "all" {
					return ec2Failure("InvalidAMIAttributeItemValue", "UserGroup "+value(item.Group))
				}
				public = true
			}
		}
		if change.add && public {
			if v.KMSKeyARN != "" {
				return ec2Failure("OperationNotPermitted", "Encrypted snapshots cannot be shared publicly.")
			}
			state, _, _, err := s.effectivePublicAccess(tx, v.Key.Scope)
			if err != nil {
				return err
			}
			if state != "unblocked" {
				return ec2Failure("OperationNotPermitted", "Public sharing of snapshots is blocked for this account.")
			}
		}
		if change.add && accounts && v.KMSKeyARN != "" {
			if s.keys == nil {
				return errors.New("EBS encryption is not configured")
			}
			managed, err := s.keys.IsAWSManagedKey(tx.Context(), v.KMSKeyARN)
			if err != nil {
				return err
			}
			if managed {
				return ec2Failure("OperationNotPermitted", "Encrypted snapshots with EBS default key cannot be shared")
			}
		}
		changed := false
		if public {
			changed = v.Public != change.add
			v.Public = change.add
		}
		sharingChanged := false
		for _, item := range change.items {
			if item.UserId == nil || value(item.UserId) == v.Key.AccountID {
				continue
			}
			id := value(item.UserId)
			index := slices.IndexFunc(v.Shares, func(share SnapshotShare) bool { return share.AccountID == id })
			if index < 0 {
				if change.add {
					v.Shares = append(v.Shares, SnapshotShare{AccountID: id, Granted: true})
					sharingChanged = true
				}
			} else if v.Shares[index].Granted != change.add {
				v.Shares[index].Granted = change.add
				sharingChanged = true
			}
		}
		if sharingChanged {
			slices.SortFunc(v.Shares, func(a, b SnapshotShare) int { return strings.Compare(a.AccountID, b.AccountID) })
			v.SharingAt = s.clock.Now().Add(SharingDelay)
		}
		if !changed && !sharingChanged {
			return nil
		}
		return tx.PutSnapshot(*v)
	})
	if err != nil {
		return nil, err
	}
	s.jobs.Wake()
	return &api.Unit{}, nil
}

func (s *Service) ResetSnapshotAttribute(ctx context.Context, in *api.ResetSnapshotAttributeRequest) (*api.Unit, error) {
	if value(in.Attribute) != "createVolumePermission" {
		return nil, ec2Failure("InvalidRequest", "The request received was invalid.")
	}
	err := s.snapshotAttribute(ctx, "ResetSnapshotAttribute", value(in.SnapshotId), in.DryRun, nil, func(tx Transaction, v *SnapshotRecord) error {
		changed := v.Public
		v.Public = false
		sharingChanged := false
		for i := range v.Shares {
			if v.Shares[i].Granted {
				v.Shares[i].Granted = false
				sharingChanged = true
			}
		}
		if sharingChanged {
			v.SharingAt = s.clock.Now().Add(SharingDelay)
		}
		if !changed && !sharingChanged {
			return nil
		}
		return tx.PutSnapshot(*v)
	})
	if err != nil {
		return nil, err
	}
	s.jobs.Wake()
	return &api.Unit{}, nil
}
