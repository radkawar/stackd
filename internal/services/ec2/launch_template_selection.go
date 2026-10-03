package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/ec2"
)

// Template cursors bind all selectors, not just filters: changing a template or
// version range must not continue a different resource's scan.
func launchTemplatePage(ctx context.Context, action string, selection any, filters api.FilterList, maximum *int32, token *api.String, items []pageItem) ([]string, *api.String, error) {
	limit := 200
	if maximum != nil {
		limit = int(*maximum)
	}
	if limit < 1 || limit > 200 {
		return nil, nil, failure("InvalidParameterValue", "MaxResults must be between 1 and 200.")
	}
	allowed := allowedFilters(action)
	for _, f := range filters {
		if !allowed[str(f.Name)] && !(allowed["tag:"] && strings.HasPrefix(str(f.Name), "tag:")) {
			return nil, nil, failure("InvalidParameterValue", "The filter '"+str(f.Name)+"' is invalid")
		}
	}
	encoded, _ := json.Marshal(selection)
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	cursor := pageToken{Scope: scopeFor(ctx), Operation: action, Selection: digest}
	if str(token) != "" {
		raw, err := base64.RawURLEncoding.DecodeString(str(token))
		if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Scope != scopeFor(ctx) || cursor.Operation != action || cursor.Selection != digest || cursor.After == "" {
			return nil, nil, failure("InvalidParameterValue", "The nextToken is invalid.")
		}
	}
	slices.SortFunc(items, func(a, b pageItem) int { return strings.Compare(a.ID, b.ID) })
	compiled := compileFilters(filters)
	out := []string{}
	for _, item := range items {
		if item.ID <= cursor.After || !matchesFilters(item, compiled) {
			continue
		}
		if len(out) == limit {
			cursor.After = out[len(out)-1]
			raw, _ := json.Marshal(cursor)
			return out, new(api.String(base64.RawURLEncoding.EncodeToString(raw))), nil
		}
		out = append(out, item.ID)
	}
	return out, nil, nil
}
func (s *Service) describeLaunchTemplates(ctx context.Context, tx Transaction, in *api.DescribeLaunchTemplatesRequest) (*api.DescribeLaunchTemplatesResult, error) {
	if err := s.authorize(ctx, "DescribeLaunchTemplates", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if len(in.LaunchTemplateIds) > 0 && len(in.LaunchTemplateNames) > 0 {
		return nil, failure("InvalidParameterCombination", "Either provide launch template IDs or launch template names.")
	}
	rows, err := tx.LaunchTemplates(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, id := range in.LaunchTemplateIds {
		v, err := selectLaunchTemplate(ctx, tx, string(id), "")
		if err != nil {
			return nil, err
		}
		wanted[v.Key.ID] = true
	}
	for _, name := range in.LaunchTemplateNames {
		v, err := selectLaunchTemplate(ctx, tx, "", string(name))
		if err != nil {
			return nil, err
		}
		wanted[v.Key.ID] = true
	}
	items := []pageItem{}
	values := map[string]api.LaunchTemplate{}
	for _, v := range rows {
		if len(wanted) > 0 && !wanted[v.Key.ID] {
			continue
		}
		items = append(items, pageItem{ID: v.Key.ID, Tags: v.Data.Tags, Fields: map[string][]string{"launch-template-name": {str(v.Data.LaunchTemplateName)}, "create-time": {v.Data.CreateTime.Format(time.RFC3339)}}})
		values[v.Key.ID] = v.Data
	}
	selection := *in
	selection.NextToken, selection.MaxResults, selection.DryRun = nil, nil, nil
	ids, next, err := launchTemplatePage(ctx, "DescribeLaunchTemplates", selection, in.Filters, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeLaunchTemplatesResult{LaunchTemplates: api.LaunchTemplateSet{}, NextToken: next}
	for _, id := range ids {
		out.LaunchTemplates = append(out.LaunchTemplates, values[id])
	}
	return out, nil
}
func (s *Service) describeLaunchTemplateVersions(ctx context.Context, tx Transaction, in *api.DescribeLaunchTemplateVersionsRequest) (*api.DescribeLaunchTemplateVersionsResult, error) {
	if err := s.authorize(ctx, "DescribeLaunchTemplateVersions", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if len(in.Versions) > 0 && (in.MinVersion != nil || in.MaxVersion != nil) {
		return nil, failure("InvalidParameterCombination", "Minimum or maximum version filter is not applicable when given a list of versions.")
	}
	var templates []LaunchTemplateRecord
	if str(in.LaunchTemplateId) != "" || str(in.LaunchTemplateName) != "" {
		v, err := selectLaunchTemplate(ctx, tx, str(in.LaunchTemplateId), str(in.LaunchTemplateName))
		if err != nil {
			return nil, err
		}
		templates = []LaunchTemplateRecord{v}
	} else {
		if len(in.Versions) == 0 {
			return nil, failure("MissingParameter", "Specify a launch template, or request $Default and/or $Latest versions for all launch templates.")
		}
		for _, v := range in.Versions {
			if v != "$Latest" && v != "$Default" {
				return nil, failure("InvalidParameterValue", "Only $Default and $Latest may be selected without a launch template.")
			}
		}
		var err error
		templates, err = tx.LaunchTemplates(scopeFor(ctx))
		if err != nil {
			return nil, err
		}
	}
	minVersion, maxVersion := int64(1), int64(math.MaxInt64)
	for _, bound := range []struct {
		raw    *api.String
		target *int64
	}{{in.MinVersion, &minVersion}, {in.MaxVersion, &maxVersion}} {
		if bound.raw != nil {
			n, err := strconv.ParseInt(str(bound.raw), 10, 64)
			if err != nil || n < 1 {
				return nil, failure("InvalidParameterValue", "Version bounds must be positive numbers.")
			}
			*bound.target = n
		}
	}
	if minVersion > maxVersion {
		return nil, failure("InvalidParameterValue", "Minimum version must not exceed maximum version.")
	}
	items := []pageItem{}
	values := map[string]api.LaunchTemplateVersion{}
	for _, template := range templates {
		versions, err := tx.LaunchTemplateVersions(template.Key)
		if err != nil {
			return nil, err
		}
		wanted := map[int64]int{}
		for _, raw := range in.Versions {
			v, err := selectLaunchTemplateVersion(tx, template, string(raw))
			if err != nil {
				return nil, err
			}
			wanted[v.Key.Number]++
		}
		for _, v := range versions {
			if v.Key.Number < minVersion || v.Key.Number > maxVersion || (len(wanted) > 0 && wanted[v.Key.Number] == 0) {
				continue
			}
			if boolValue(in.ResolveAlias) && strings.HasPrefix(str(v.Data.ImageId), "resolve:ssm:") {
				return nil, unsupported("Resolving SSM image aliases in launch templates is not implemented.")
			}
			copies := 1
			if len(wanted) > 0 {
				copies = wanted[v.Key.Number]
			}
			result := launchTemplateVersionResult(template, v)
			for occurrence := range copies {
				id := fmt.Sprintf("%s/%019d/%010d", template.Key.ID, math.MaxInt64-v.Key.Number, occurrence)
				items = append(items, launchTemplateVersionItem(id, result))
				values[id] = result
			}
		}
	}
	selection := *in
	selection.NextToken, selection.MaxResults, selection.DryRun = nil, nil, nil
	ids, next, err := launchTemplatePage(ctx, "DescribeLaunchTemplateVersions", selection, in.Filters, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeLaunchTemplateVersionsResult{LaunchTemplateVersions: api.LaunchTemplateVersionSet{}, NextToken: next}
	for _, id := range ids {
		out.LaunchTemplateVersions = append(out.LaunchTemplateVersions, values[id])
	}
	return out, nil
}
func launchTemplateVersionItem(id string, v api.LaunchTemplateVersion) pageItem {
	d := v.LaunchTemplateData
	fields := map[string][]string{"create-time": {v.CreateTime.Format(time.RFC3339)}, "image-id": {str(d.ImageId)}, "instance-type": {str(d.InstanceType)}, "is-default-version": {strconv.FormatBool(boolValue(v.DefaultVersion))}, "kernel-id": {str(d.KernelId)}, "ram-disk-id": {str(d.RamDiskId)}}
	if d.EbsOptimized != nil {
		fields["ebs-optimized"] = []string{strconv.FormatBool(boolValue(d.EbsOptimized))}
	}
	if m := d.MetadataOptions; m != nil {
		fields["http-endpoint"] = []string{str(m.HttpEndpoint)}
		fields["http-protocol-ipv4"] = []string{str(m.HttpEndpoint)}
		fields["http-tokens"] = []string{str(m.HttpTokens)}
	}
	if p := d.Placement; p != nil {
		fields["host-resource-group-arn"] = []string{str(p.HostResourceGroupArn)}
	}
	if p := d.IamInstanceProfile; p != nil {
		fields["iam-instance-profile"] = []string{str(p.Arn)}
	}
	for _, license := range d.LicenseSpecifications {
		fields["license-configuration-arn"] = append(fields["license-configuration-arn"], str(license.LicenseConfigurationArn))
	}
	for _, network := range d.NetworkInterfaces {
		if network.NetworkCardIndex != nil {
			fields["network-card-index"] = append(fields["network-card-index"], strconv.Itoa(int(*network.NetworkCardIndex)))
		}
	}
	return pageItem{ID: id, Fields: fields}
}
