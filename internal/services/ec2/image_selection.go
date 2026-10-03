package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/ec2"
)

func imagePageItem(image api.Image) pageItem {
	fields := map[string][]string{
		"architecture": {str(image.Architecture)}, "boot-mode": {str(image.BootMode)}, "creation-date": {str(image.CreationDate)},
		"description": {str(image.Description)}, "hypervisor": {str(image.Hypervisor)}, "image-id": {str(image.ImageId)},
		"image-type": {str(image.ImageType)}, "is-public": {strconv.FormatBool(boolValue(image.Public))},
		"kernel-id": {str(image.KernelId)}, "manifest-location": {str(image.ImageLocation)}, "name": {str(image.Name)},
		"owner-alias": {str(image.ImageOwnerAlias)}, "owner-id": {str(image.OwnerId)}, "platform": {str(image.Platform)},
		"public-ssm-parameter-name": {str(image.PublicSsmParameterName)}, "ramdisk-id": {str(image.RamdiskId)},
		"root-device-name": {str(image.RootDeviceName)}, "root-device-type": {str(image.RootDeviceType)},
		"source-image-id": {str(image.SourceImageId)}, "source-image-region": {str(image.SourceImageRegion)},
		"source-instance-id": {str(image.SourceInstanceId)}, "state": {str(image.State)},
		"sriov-net-support": {str(image.SriovNetSupport)}, "virtualization-type": {str(image.VirtualizationType)},
	}
	for name, value := range map[string]*api.Boolean{"ena-support": image.EnaSupport, "free-tier-eligible": image.FreeTierEligible, "image-allowed": image.ImageAllowed} {
		if value != nil {
			fields[name] = []string{strconv.FormatBool(bool(*value))}
		}
	}
	if image.StateReason != nil {
		fields["state-reason-code"] = []string{str(image.StateReason.Code)}
		fields["state-reason-message"] = []string{str(image.StateReason.Message)}
	}
	for _, product := range image.ProductCodes {
		fields["product-code"] = append(fields["product-code"], str(product.ProductCodeId))
		fields["product-code.type"] = append(fields["product-code.type"], str(product.ProductCodeType))
	}
	for _, mapping := range image.BlockDeviceMappings {
		fields["block-device-mapping.device-name"] = append(fields["block-device-mapping.device-name"], str(mapping.DeviceName))
		if ebs := mapping.Ebs; ebs != nil {
			fields["block-device-mapping.snapshot-id"] = append(fields["block-device-mapping.snapshot-id"], str(ebs.SnapshotId))
			fields["block-device-mapping.volume-type"] = append(fields["block-device-mapping.volume-type"], str(ebs.VolumeType))
			if ebs.VolumeSize != nil {
				fields["block-device-mapping.volume-size"] = append(fields["block-device-mapping.volume-size"], strconv.Itoa(int(*ebs.VolumeSize)))
			}
			if ebs.Encrypted != nil {
				fields["block-device-mapping.encrypted"] = append(fields["block-device-mapping.encrypted"], strconv.FormatBool(bool(*ebs.Encrypted)))
			}
			if ebs.DeleteOnTermination != nil {
				fields["block-device-mapping.delete-on-termination"] = append(fields["block-device-mapping.delete-on-termination"], strconv.FormatBool(bool(*ebs.DeleteOnTermination)))
			}
		}
	}
	return pageItem{ID: str(image.ImageId), Tags: image.Tags, Fields: fields}
}

func (s *Service) describeImages(ctx context.Context, tx Transaction, in *api.DescribeImagesRequest) (*api.DescribeImagesResult, error) {
	if err := s.authorize(ctx, "DescribeImages", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if in.MaxResults != nil && (*in.MaxResults < 5 || *in.MaxResults > 1000) {
		return nil, failure("InvalidParameterValue", "MaxResults must be between 5 and 1000.")
	}
	if len(in.ImageIds) > 0 && (in.MaxResults != nil || in.NextToken != nil) {
		return nil, failure("InvalidParameterCombination", "ImageIds cannot be combined with pagination.")
	}
	allowed := map[string]bool{}
	for _, name := range strings.Fields("architecture boot-mode creation-date description ena-support free-tier-eligible hypervisor image-allowed image-id image-type is-public kernel-id manifest-location name owner-alias owner-id platform product-code product-code.type public-ssm-parameter-name ramdisk-id root-device-name root-device-type source-image-id source-image-region source-instance-id state state-reason-code state-reason-message sriov-net-support virtualization-type block-device-mapping.delete-on-termination block-device-mapping.device-name block-device-mapping.snapshot-id block-device-mapping.volume-size block-device-mapping.volume-type block-device-mapping.encrypted tag-key tag-value") {
		allowed[name] = true
	}
	for _, filter := range in.Filters {
		if !allowed[str(filter.Name)] && !strings.HasPrefix(str(filter.Name), "tag:") {
			return nil, failure("InvalidParameterValue", "The filter '"+str(filter.Name)+"' is invalid")
		}
	}
	for _, owner := range in.Owners {
		if owner != "self" && owner != "amazon" && owner != "aws-marketplace" && owner != "aws-backup-vault" && !validImageAccount(string(owner)) {
			return nil, failure("InvalidParameterValue", "Invalid image owner.")
		}
	}
	for _, user := range in.ExecutableUsers {
		if user != "self" && user != "all" && !validImageAccount(string(user)) {
			return nil, failure("InvalidParameterValue", "Invalid executable user.")
		}
	}
	wanted := make(map[string]bool, len(in.ImageIds))
	for _, id := range in.ImageIds {
		if err := validateImageID(string(id)); err != nil {
			return nil, err
		}
		wanted[string(id)] = true
	}
	selection, _ := json.Marshal(struct {
		Filters              api.FilterList
		Owners               api.OwnerStringList
		Executable           api.ExecutableByStringList
		Deprecated, Disabled bool
	}{in.Filters, in.Owners, in.ExecutableUsers, boolValue(in.IncludeDeprecated), boolValue(in.IncludeDisabled)})
	digest := fmt.Sprintf("%x", sha256.Sum256(selection))
	cursor := pageToken{Scope: scopeFor(ctx), Operation: "DescribeImages", Selection: digest}
	if str(in.NextToken) != "" {
		body, err := base64.RawURLEncoding.DecodeString(str(in.NextToken))
		var prior pageToken
		if err != nil || json.Unmarshal(body, &prior) != nil || prior.Scope != cursor.Scope || prior.Operation != cursor.Operation || prior.Selection != digest || prior.After == "" {
			return nil, failure("InvalidParameterValue", "The nextToken is invalid.")
		}
		cursor = prior
	}
	images, err := tx.RegionalImages(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	slices.SortFunc(images, func(a, b ImageRecord) int { return strings.Compare(a.Key.ID, b.Key.ID) })
	found := make(map[string]bool, len(wanted))
	visible := images[:0]
	for _, image := range images {
		found[image.Key.ID] = true
		if !imageVisible(image, scopeFor(ctx).AccountID) {
			continue
		}
		if str(image.Data.State) == "deregistered" {
			continue
		}
		if str(image.Data.State) == "disabled" && !boolValue(in.IncludeDisabled) {
			continue
		}
		if image.Key.Scope.AccountID != scopeFor(ctx).AccountID {
			image.Data.Tags = nil
			image.Data.DeregistrationProtection = nil
			if !boolValue(in.IncludeDeprecated) {
				if at, err := time.Parse(time.RFC3339, str(image.Data.DeprecationTime)); err == nil && !at.After(s.clock.Now()) {
					continue
				}
			}
		}
		visible = append(visible, image)
	}
	for _, id := range in.ImageIds {
		if !found[string(id)] {
			return nil, imageNotFound(string(id))
		}
	}
	compiled := compileFilters(in.Filters)
	limit := len(visible) + 1
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	out := &api.DescribeImagesResult{Images: api.ImageList{}}
	for _, image := range visible {
		if image.Key.ID <= cursor.After || len(wanted) > 0 && !wanted[image.Key.ID] {
			continue
		}
		ownerMatch := len(in.Owners) == 0
		for _, owner := range in.Owners {
			if string(owner) == image.Key.Scope.AccountID || owner == "self" && image.Key.Scope.AccountID == scopeFor(ctx).AccountID || string(owner) == str(image.Data.ImageOwnerAlias) {
				ownerMatch = true
			}
		}
		if !ownerMatch {
			continue
		}
		executableMatch := len(in.ExecutableUsers) == 0
		for _, user := range in.ExecutableUsers {
			account := string(user)
			if account == "self" {
				account = scopeFor(ctx).AccountID
			}
			if account == scopeFor(ctx).AccountID && imageVisible(image, account) {
				executableMatch = true
			}
			for _, permission := range image.LaunchPermissions {
				if user == "all" && str(permission.Group) == "all" || account == str(permission.UserId) {
					executableMatch = true
				}
			}
		}
		if !executableMatch || !matchesFilters(imagePageItem(image.Data), compiled) {
			continue
		}
		if len(out.Images) == limit {
			cursor.After = str(out.Images[len(out.Images)-1].ImageId)
			body, _ := json.Marshal(cursor)
			out.NextToken = new(api.String(base64.RawURLEncoding.EncodeToString(body)))
			break
		}
		out.Images = append(out.Images, image.Data)
	}
	return out, nil
}
