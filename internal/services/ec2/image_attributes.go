package ec2

import (
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/ec2"
)

func imageAttributeValue[T ~string](v *T) *api.AttributeValue {
	out := &api.AttributeValue{}
	if v != nil {
		out.Value = new(api.String(*v))
	}
	return out
}

func (s *Service) describeImageAttribute(ctx context.Context, tx Transaction, in *api.DescribeImageAttributeRequest) (*api.ImageAttribute, error) {
	image, err := ownedImage(ctx, tx, str(in.ImageId))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeImage(ctx, "DescribeImageAttribute", image, nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	out := &api.ImageAttribute{ImageId: image.Data.ImageId}
	switch str(in.Attribute) {
	case "description":
		out.Description = imageAttributeValue(image.Data.Description)
	case "launchPermission":
		out.LaunchPermissions = image.LaunchPermissions
	case "productCodes":
		out.ProductCodes = image.Data.ProductCodes
		if out.ProductCodes == nil {
			out.ProductCodes = api.ProductCodeList{}
		}
	case "kernel":
		out.KernelId = imageAttributeValue(image.Data.KernelId)
	case "ramdisk":
		out.RamdiskId = imageAttributeValue(image.Data.RamdiskId)
	case "bootMode":
		out.BootMode = imageAttributeValue(image.Data.BootMode)
	case "imdsSupport":
		out.ImdsSupport = imageAttributeValue(image.Data.ImdsSupport)
	case "sriovNetSupport":
		out.SriovNetSupport = imageAttributeValue(image.Data.SriovNetSupport)
	case "tpmSupport":
		out.TpmSupport = imageAttributeValue(image.Data.TpmSupport)
	case "uefiData":
		out.UefiData = &api.AttributeValue{}
	case "lastLaunchedTime":
		out.LastLaunchedTime = imageAttributeValue(image.Data.LastLaunchedTime)
	case "deregistrationProtection":
		out.DeregistrationProtection = imageAttributeValue(image.Data.DeregistrationProtection)
	case "blockDeviceMapping":
		// AWS explicitly deprecated this selector with AuthFailure. This is not
		// an inference from a standing-account denial; see API_DescribeImageAttribute.
		return nil, failure("AuthFailure", "Unauthorized attempt to access restricted resource")
	default:
		return nil, failure("InvalidParameterValue", "Invalid image attribute.")
	}
	return out, nil
}

func validImageAccount(account string) bool {
	if len(account) != 12 {
		return false
	}
	for _, c := range account {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func launchPermissionKey(permission api.LaunchPermission) (string, error) {
	if permission.OrganizationArn != nil || permission.OrganizationalUnitArn != nil {
		// TODO: Comeback resolve current Organizations membership for AMI grants.
		return "", unsupported("Organization and organizational-unit image launch permissions are not implemented.")
	}
	if (permission.UserId == nil) == (permission.Group == nil) {
		return "", failure("InvalidAMIAttributeItemValue", "Exactly one account or group is required for a launch permission.")
	}
	if permission.UserId != nil {
		if !validImageAccount(str(permission.UserId)) {
			return "", failure("InvalidAMIAttributeItemValue", "Invalid user ID: "+str(permission.UserId))
		}
		return "user:" + str(permission.UserId), nil
	}
	if str(permission.Group) != "all" {
		return "", failure("InvalidAMIAttributeItemValue", "Invalid user group: "+str(permission.Group))
	}
	return "group:all", nil
}

func imageModification(in *api.ModifyImageAttributeRequest) (string, *api.String, api.LaunchPermissionList, api.LaunchPermissionList, error) {
	bad := func() (string, *api.String, api.LaunchPermissionList, api.LaunchPermissionList, error) {
		return "", nil, nil, nil, failure("InvalidParameterCombination", "Exactly one image attribute must be specified.")
	}
	if len(in.ProductCodes) > 0 {
		return "", nil, nil, nil, unsupported("Product code modification is not supported.")
	}
	if len(in.OrganizationArns) > 0 || len(in.OrganizationalUnitArns) > 0 {
		return "", nil, nil, nil, unsupported("Organization launch permissions are not implemented.")
	}
	attribute, value := str(in.Attribute), in.Value
	count := 0
	if in.Attribute != nil {
		count++
	}
	if in.Description != nil {
		count++
		attribute, value = "description", in.Description.Value
	}
	if in.ImdsSupport != nil {
		count++
		attribute, value = "imdsSupport", in.ImdsSupport.Value
	}
	if in.LaunchPermission != nil {
		count++
		attribute = "launchPermission"
	}
	if count != 1 {
		return bad()
	}
	legacy := in.OperationType != nil || len(in.UserGroups) > 0 || len(in.UserIds) > 0
	if attribute != "launchPermission" {
		if legacy || in.LaunchPermission != nil {
			return bad()
		}
		if in.Value != nil && in.Attribute == nil {
			return bad()
		}
		if attribute != "description" && attribute != "imdsSupport" {
			return "", nil, nil, nil, failure("InvalidParameterValue", "Invalid image attribute.")
		}
		if str(value) == "" {
			return "", nil, nil, nil, failure("MissingParameter", "The request must contain the parameter "+attribute)
		}
		if attribute == "description" && utf8.RuneCountInString(str(value)) > 255 {
			return "", nil, nil, nil, failure("InvalidParameterValue", "Image description exceeds 255 characters.")
		}
		if attribute == "imdsSupport" && str(value) != "v2.0" {
			return "", nil, nil, nil, failure("InvalidParameterValue", "ImdsSupport must be v2.0 and cannot be reset.")
		}
		return attribute, value, nil, nil, nil
	}
	if in.Value != nil || in.LaunchPermission != nil && legacy {
		return bad()
	}
	var add, remove api.LaunchPermissionList
	if in.LaunchPermission != nil {
		add, remove = in.LaunchPermission.Add, in.LaunchPermission.Remove
	} else {
		entries := make(api.LaunchPermissionList, 0, len(in.UserIds)+len(in.UserGroups))
		for _, id := range in.UserIds {
			entries = append(entries, api.LaunchPermission{UserId: new(api.String(id))})
		}
		for _, group := range in.UserGroups {
			entries = append(entries, api.LaunchPermission{Group: new(api.PermissionGroup(group))})
		}
		switch str(in.OperationType) {
		case "add":
			add = entries
		case "remove":
			remove = entries
		default:
			return "", nil, nil, nil, failure("InvalidParameterValue", "OperationType must be add or remove.")
		}
	}
	if len(add)+len(remove) == 0 {
		return bad()
	}
	for _, entries := range []api.LaunchPermissionList{add, remove} {
		for _, permission := range entries {
			if _, err := launchPermissionKey(permission); err != nil {
				return "", nil, nil, nil, err
			}
		}
	}
	return attribute, nil, add, remove, nil
}

func (s *Service) modifyImageAttribute(ctx context.Context, tx Transaction, in *api.ModifyImageAttributeRequest) (*emptyResult, error) {
	image, err := ownedImage(ctx, tx, str(in.ImageId))
	if err != nil {
		return nil, err
	}
	attribute, value, add, remove, err := imageModification(in)
	if err != nil {
		return nil, err
	}
	conditions := map[string][]string{"ec2:Attribute": {attribute}}
	if value != nil {
		conditions["ec2:Attribute/"+attribute] = []string{str(value)}
	}
	if err := s.authorizeImage(ctx, "ModifyImageAttribute", image, conditions); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	switch attribute {
	case "description":
		image.Data.Description = copyPointer(value)
	case "imdsSupport":
		image.Data.ImdsSupport = new(api.ImdsSupportValues(*value))
	case "launchPermission":
		permissions := make(map[string]api.LaunchPermission, len(image.LaunchPermissions)+len(add))
		for _, permission := range image.LaunchPermissions {
			k, _ := launchPermissionKey(permission)
			permissions[k] = permission
		}
		for _, permission := range add {
			if str(permission.Group) == "all" {
				for _, mapping := range image.Data.BlockDeviceMappings {
					if mapping.Ebs != nil && boolValue(mapping.Ebs.Encrypted) {
						return nil, failure("InvalidParameter", "Images with encrypted snapshots cannot be made public.")
					}
				}
			}
			k, _ := launchPermissionKey(permission)
			permissions[k] = permission
		}
		for _, permission := range remove {
			k, _ := launchPermissionKey(permission)
			delete(permissions, k)
		}
		image.LaunchPermissions = make(api.LaunchPermissionList, 0, len(permissions))
		for _, permission := range permissions {
			image.LaunchPermissions = append(image.LaunchPermissions, permission)
		}
		slices.SortFunc(image.LaunchPermissions, func(a, b api.LaunchPermission) int {
			ak, _ := launchPermissionKey(a)
			bk, _ := launchPermissionKey(b)
			return strings.Compare(ak, bk)
		})
		_, public := permissions["group:all"]
		image.Data.Public = new(api.Boolean(public))
	}
	if err := tx.PutImage(image); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

func (s *Service) resetImageAttribute(ctx context.Context, tx Transaction, in *api.ResetImageAttributeRequest) (*emptyResult, error) {
	image, err := ownedImage(ctx, tx, str(in.ImageId))
	if err != nil {
		return nil, err
	}
	if str(in.Attribute) != "launchPermission" {
		return nil, failure("InvalidRequest", "Only launchPermission can be reset.")
	}
	if err := s.authorizeImage(ctx, "ResetImageAttribute", image, map[string][]string{"ec2:Attribute": {"launchPermission"}}); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	image.LaunchPermissions = api.LaunchPermissionList{}
	image.Data.Public = new(api.Boolean(false))
	if err := tx.PutImage(image); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}
