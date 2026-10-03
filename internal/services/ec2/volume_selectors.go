package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

// SelectVolumePage applies EC2 filters and scoped cursors to owner-projected disks.
func SelectVolumePage(ctx context.Context, in *api.DescribeVolumesRequest, rows api.VolumeList) (*api.DescribeVolumesResult, error) {
	selected, next, err := selectVolumeRows(ctx, "DescribeVolumes", in.VolumeIds, in.Filters, in.MaxResults, in.NextToken, rows,
		func(v *api.Volume) string { return str(v.VolumeId) }, volumePageItem)
	if err != nil {
		return nil, err
	}
	return &api.DescribeVolumesResult{Volumes: selected, NextToken: next}, nil
}

// SelectVolumeModificationPage selects the owner's latest modification records.
func SelectVolumeModificationPage(ctx context.Context, in *api.DescribeVolumesModificationsRequest, rows api.VolumeModificationList) (*api.DescribeVolumesModificationsResult, error) {
	selected, next, err := selectVolumeRows(ctx, "DescribeVolumesModifications", in.VolumeIds, in.Filters, in.MaxResults, in.NextToken, rows,
		func(v *api.VolumeModification) string { return str(v.VolumeId) }, volumeModificationPageItem)
	if err != nil {
		return nil, err
	}
	return &api.DescribeVolumesModificationsResult{VolumesModifications: selected, NextToken: next}, nil
}

// SelectVolumeStatusPage selects status projections without deriving disk health.
func SelectVolumeStatusPage(ctx context.Context, in *api.DescribeVolumeStatusRequest, rows api.VolumeStatusList) (*api.DescribeVolumeStatusResult, error) {
	selected, next, err := selectVolumeRows(ctx, "DescribeVolumeStatus", in.VolumeIds, in.Filters, in.MaxResults, in.NextToken, rows,
		func(v *api.VolumeStatusItem) string { return str(v.VolumeId) }, volumeStatusPageItem)
	if err != nil {
		return nil, err
	}
	return &api.DescribeVolumeStatusResult{VolumeStatuses: selected, NextToken: next}, nil
}

func volumeSelectorFields(operation string) string {
	switch operation {
	case "DescribeVolumes":
		return "attachment.attach-time attachment.delete-on-termination attachment.device attachment.instance-id attachment.status availability-zone availability-zone-id create-time encrypted fast-restored multi-attach-enabled operator.managed operator.principal size snapshot-id status tag-key tag-value volume-id volume-type"
	case "DescribeVolumesModifications":
		return "modification-state original-iops original-size original-volume-type original-multi-attach-enabled start-time target-iops target-size target-volume-type target-multi-attach-enabled volume-id"
	case "DescribeVolumeStatus":
		return "action.code action.description action.event-id availability-zone event.description event.event-id event.event-type event.not-after event.not-before volume-status.details-name volume-status.details-status volume-status.status"
	}
	return ""
}

// Disk describe APIs share EC2's filter compiler and pageToken representation,
// with native volume bounds and status scan-before-filter pagination.
func selectVolumeRows[T any](ctx context.Context, operation string, ids api.VolumeIdStringList, filters api.FilterList, max *api.Integer, token *api.String, rows []T, identify func(*T) string, project func(*T) pageItem) ([]T, *api.String, error) {
	if len(ids) > 0 && (max != nil || str(token) != "") {
		parameter := "volumeIdsSet"
		if operation == "DescribeVolumesModifications" {
			parameter = "volumeModificationSet"
		}
		pageParameter := "nextToken"
		if max != nil {
			pageParameter = "maxResults"
		}
		return nil, nil, failure("InvalidParameterCombination", "The parameter "+parameter+" cannot be used with the parameter "+pageParameter)
	}
	if max != nil && *max < 5 {
		parameter := "maxResults"
		if operation == "DescribeVolumesModifications" {
			parameter = "MaxResults"
		}
		return nil, nil, failure("InvalidParameterValue", fmt.Sprintf("Value ( %d ) for parameter %s is invalid. Expecting a value greater than 5.", *max, parameter))
	}
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[string(id)] = true
		found := false
		for i := range rows {
			if identify(&rows[i]) == string(id) {
				found = true
				break
			}
		}
		if !found {
			if operation == "DescribeVolumesModifications" {
				return nil, nil, failure("InvalidVolumeModification.NotFound", "Modification for volume '"+string(id)+"' does not exist.")
			}
			return nil, nil, failure("InvalidVolume.NotFound", "The volume '"+string(id)+"' does not exist.")
		}
	}
	allowed := " " + volumeSelectorFields(operation) + " "
	for _, filter := range filters {
		name := str(filter.Name)
		if !(operation == "DescribeVolumes" && strings.HasPrefix(name, "tag:")) && (name == "" || strings.ContainsAny(name, " \t\r\n") || !strings.Contains(allowed, " "+name+" ")) {
			return nil, nil, failure("InvalidParameterValue", "The filter '"+name+"' is invalid")
		}
	}
	encoded, _ := json.Marshal(filters)
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	cursor := pageToken{Scope: scopeFor(ctx), Operation: operation, Selection: digest}
	if str(token) != "" {
		raw, err := base64.RawURLEncoding.DecodeString(str(token))
		var prior pageToken
		if err != nil || json.Unmarshal(raw, &prior) != nil || prior.Scope != cursor.Scope || prior.Operation != operation || prior.Selection == "" || prior.After == "" || operation != "DescribeVolumes" && prior.Selection != digest {
			message := "Unable to parse pagination token"
			if operation == "DescribeVolumesModifications" {
				message = "Value ( " + str(token) + " ) for parameter NextToken is invalid. The token is Invalid."
			}
			return nil, nil, failure("InvalidParameterValue", message)
		}
		cursor = prior
		// Native volume cursors resume the scan even when filters change.
		cursor.Selection = digest
	}
	sort.Slice(rows, func(i, j int) bool { return identify(&rows[i]) < identify(&rows[j]) })
	compiled := compileFilters(filters)
	var scanFilters []compiledFilter
	if operation == "DescribeVolumes" {
		for _, filter := range compiled {
			if filter.name != "tag-key" && filter.name != "tag-value" && !strings.HasPrefix(filter.name, "tag:") {
				scanFilters = append(scanFilters, filter)
			}
		}
	}
	limit := len(rows) + 1
	if max != nil {
		limit = int(*max)
	}
	selected := []T{}
	scanned := 0
	last := cursor.After
	for i := range rows {
		id := identify(&rows[i])
		if id <= cursor.After || len(wanted) > 0 && !wanted[id] {
			continue
		}
		var item pageItem
		if len(compiled) > 0 {
			item = project(&rows[i])
		}
		if len(scanFilters) > 0 && !matchesFilters(item, scanFilters) {
			continue
		}
		matched := len(compiled) == 0 || matchesFilters(item, compiled)
		// Volume tags and status filters apply after the scoped scan. An
		// empty filtered page can therefore retain a continuation token.
		if operation == "DescribeVolumesModifications" && !matched {
			continue
		}
		if scanned == limit {
			cursor.After = last
			raw, _ := json.Marshal(cursor)
			return selected, new(api.String(base64.RawURLEncoding.EncodeToString(raw))), nil
		}
		scanned++
		last = id
		if matched {
			selected = append(selected, rows[i])
		}
	}
	return selected, nil, nil
}

func volumeFilterInteger(v *api.Integer) string {
	if v == nil {
		return ""
	}
	return strconv.FormatInt(int64(*v), 10)
}

func volumeFilterTime(v *api.DateTime) string {
	if v == nil {
		return ""
	}
	return v.UTC().Format("2006-01-02T15:04:05.000Z")
}

func volumePageItem(v *api.Volume) pageItem {
	fields := map[string][]string{
		"volume-id": {str(v.VolumeId)}, "availability-zone": {str(v.AvailabilityZone)}, "availability-zone-id": {str(v.AvailabilityZoneId)},
		"create-time": {volumeFilterTime(v.CreateTime)}, "encrypted": {strconv.FormatBool(boolValue(v.Encrypted))},
		"fast-restored": {strconv.FormatBool(boolValue(v.FastRestored))}, "multi-attach-enabled": {strconv.FormatBool(boolValue(v.MultiAttachEnabled))},
		"size": {volumeFilterInteger(v.Size)}, "snapshot-id": {str(v.SnapshotId)}, "status": {str(v.State)}, "volume-type": {str(v.VolumeType)},
		"operator.managed": {strconv.FormatBool(v.Operator != nil && boolValue(v.Operator.Managed))},
	}
	if v.Operator != nil {
		fields["operator.principal"] = []string{str(v.Operator.Principal)}
	}
	for _, attachment := range v.Attachments {
		fields["attachment.attach-time"] = append(fields["attachment.attach-time"], volumeFilterTime(attachment.AttachTime))
		fields["attachment.delete-on-termination"] = append(fields["attachment.delete-on-termination"], strconv.FormatBool(boolValue(attachment.DeleteOnTermination)))
		fields["attachment.device"] = append(fields["attachment.device"], str(attachment.Device))
		fields["attachment.instance-id"] = append(fields["attachment.instance-id"], str(attachment.InstanceId))
		fields["attachment.status"] = append(fields["attachment.status"], str(attachment.State))
	}
	return pageItem{ID: str(v.VolumeId), Tags: v.Tags, Fields: fields}
}

func volumeModificationPageItem(v *api.VolumeModification) pageItem {
	return pageItem{ID: str(v.VolumeId), Fields: map[string][]string{
		"volume-id": {str(v.VolumeId)}, "modification-state": {str(v.ModificationState)}, "start-time": {volumeFilterTime(v.StartTime)},
		"original-iops": {volumeFilterInteger(v.OriginalIops)}, "original-size": {volumeFilterInteger(v.OriginalSize)}, "original-volume-type": {str(v.OriginalVolumeType)},
		"original-multi-attach-enabled": {strconv.FormatBool(boolValue(v.OriginalMultiAttachEnabled))},
		"target-iops":                   {volumeFilterInteger(v.TargetIops)}, "target-size": {volumeFilterInteger(v.TargetSize)}, "target-volume-type": {str(v.TargetVolumeType)},
		"target-multi-attach-enabled": {strconv.FormatBool(boolValue(v.TargetMultiAttachEnabled))},
	}}
}

func volumeStatusPageItem(v *api.VolumeStatusItem) pageItem {
	fields := map[string][]string{"availability-zone": {str(v.AvailabilityZone)}}
	if v.VolumeStatus != nil {
		fields["volume-status.status"] = []string{str(v.VolumeStatus.Status)}
		for _, detail := range v.VolumeStatus.Details {
			fields["volume-status.details-name"] = append(fields["volume-status.details-name"], str(detail.Name))
			fields["volume-status.details-status"] = append(fields["volume-status.details-status"], str(detail.Status))
		}
	}
	for _, action := range v.Actions {
		fields["action.code"] = append(fields["action.code"], str(action.Code))
		fields["action.description"] = append(fields["action.description"], str(action.Description))
		fields["action.event-id"] = append(fields["action.event-id"], str(action.EventId))
	}
	for _, event := range v.Events {
		fields["event.description"] = append(fields["event.description"], str(event.Description))
		fields["event.event-id"] = append(fields["event.event-id"], str(event.EventId))
		fields["event.event-type"] = append(fields["event.event-type"], str(event.EventType))
		fields["event.not-after"] = append(fields["event.not-after"], volumeFilterTime(event.NotAfter))
		fields["event.not-before"] = append(fields["event.not-before"], volumeFilterTime(event.NotBefore))
	}
	return pageItem{ID: str(v.VolumeId), Fields: fields}
}
