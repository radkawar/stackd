package ec2

import (
	"context"
	"encoding/base64"
	"slices"
	"strconv"

	api "stackd/internal/awsapi/ec2"
)

// instanceProjection reads the current ENI owner without mutating instance
// state or making Describe drive execution. EBS attachments remain instance-owned.
func instanceProjection(ctx context.Context, tx Reader, record InstanceRecord) (api.Instance, error) {
	out := record.Data
	out.Operator = lambdaInstanceOperator(record)
	out.PublicIpAddress, out.PublicDnsName = nil, nil
	// Admission reserves EBS relationships before a VMM attaches those disks.
	// Keep them in the owner record for cleanup/IAM, not in the pre-boot response.
	if instanceState(record) == "pending" && !record.RuntimePrepared {
		out.BlockDeviceMappings = api.InstanceBlockDeviceMappingList{}
	}
	out.NetworkInterfaces = slices.Clone(record.Data.NetworkInterfaces)
	for i, attached := range out.NetworkInterfaces {
		eni, err := tx.NetworkInterface(ResourceKey{Scope: record.Key.Scope, ID: str(attached.NetworkInterfaceId)})
		if err != nil {
			return out, err
		}
		if eni.Data.Attachment == nil || str(eni.Data.Attachment.InstanceId) != record.Key.ID {
			return out, failure("IncorrectState", "The instance no longer owns its network interface.")
		}
		eni.Data, err = networkInterfaceProjection(ctx, tx, eni)
		if err != nil {
			return out, err
		}
		out.NetworkInterfaces[i] = instanceNetworkData(eni.Data)
		if eni.Data.Attachment.DeviceIndex != nil && *eni.Data.Attachment.DeviceIndex == 0 {
			out.SubnetId = eni.Data.SubnetId
			out.VpcId = eni.Data.VpcId
			out.PrivateIpAddress = eni.Data.PrivateIpAddress
			out.PrivateDnsName = new(api.String(privateDNSName(record.Key.Scope, str(eni.Data.PrivateIpAddress))))
			out.SourceDestCheck = eni.Data.SourceDestCheck
			out.SecurityGroups = eni.Data.Groups
			if eni.Data.Association != nil {
				out.PublicIpAddress = eni.Data.Association.PublicIp
				out.PublicDnsName = eni.Data.Association.PublicDnsName
			}
		}
	}
	return out, nil
}

func instancePageItem(record InstanceRecord) pageItem {
	d := record.Data
	fields := map[string][]string{
		"instance-id": {record.Key.ID}, "image-id": {str(d.ImageId)}, "instance-type": {str(d.InstanceType)}, "instance-state-name": {instanceState(record)}, "reservation-id": {record.ReservationID}, "subnet-id": {str(d.SubnetId)}, "vpc-id": {str(d.VpcId)}, "private-ip-address": {str(d.PrivateIpAddress)}, "private-dns-name": {str(d.PrivateDnsName)}, "key-name": {str(d.KeyName)}, "client-token": {str(d.ClientToken)}, "root-device-type": {str(d.RootDeviceType)}, "architecture": {str(d.Architecture)}, "virtualization-type": {str(d.VirtualizationType)},
	}
	fields["ip-address"] = []string{str(d.PublicIpAddress)}
	fields["dns-name"] = []string{str(d.PublicDnsName)}
	fields["operator.managed"] = []string{strconv.FormatBool(record.LambdaCapacityProviderARN != "")}
	if record.LambdaCapacityProviderARN != "" {
		fields["operator.principal"] = []string{lambdaManagedOperator}
	}
	if d.State != nil && d.State.Code != nil {
		fields["instance-state-code"] = []string{strconv.Itoa(int(*d.State.Code))}
	}
	if d.StateReason != nil {
		fields["state-reason-code"] = []string{str(d.StateReason.Code)}
		fields["state-reason-message"] = []string{str(d.StateReason.Message)}
	}
	if d.HibernationOptions != nil {
		fields["hibernation-options.configured"] = []string{strconv.FormatBool(boolValue(d.HibernationOptions.Configured))}
	}
	if d.Placement != nil {
		fields["availability-zone"] = []string{str(d.Placement.AvailabilityZone)}
		fields["availability-zone-id"] = []string{str(d.Placement.AvailabilityZoneId)}
	}
	if d.IamInstanceProfile != nil {
		fields["iam-instance-profile.arn"] = []string{str(d.IamInstanceProfile.Arn)}
	}
	if d.MetadataOptions != nil {
		fields["metadata-options.http-tokens"] = []string{str(d.MetadataOptions.HttpTokens)}
		fields["metadata-options.http-endpoint"] = []string{str(d.MetadataOptions.HttpEndpoint)}
		fields["metadata-options.instance-metadata-tags"] = []string{str(d.MetadataOptions.InstanceMetadataTags)}
	}
	for _, g := range d.SecurityGroups {
		fields["group-id"] = append(fields["group-id"], str(g.GroupId))
		fields["group-name"] = append(fields["group-name"], str(g.GroupName))
	}
	for _, n := range d.NetworkInterfaces {
		fields["network-interface.network-interface-id"] = append(fields["network-interface.network-interface-id"], str(n.NetworkInterfaceId))
	}
	for _, m := range d.BlockDeviceMappings {
		if m.Ebs != nil {
			fields["block-device-mapping.volume-id"] = append(fields["block-device-mapping.volume-id"], str(m.Ebs.VolumeId))
		}
	}
	return pageItem{ID: record.Key.ID, Tags: d.Tags, Fields: fields}
}

func (s *Service) describeInstances(ctx context.Context, tx Transaction, in *api.DescribeInstancesRequest) (*api.DescribeInstancesResult, error) {
	if err := s.authorize(ctx, "DescribeInstances", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	records, err := tx.Instances(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	items := make([]pageItem, 0, len(records))
	byID := make(map[string]InstanceRecord, len(records))
	for _, record := range records {
		record.Data, err = instanceProjection(ctx, tx, record)
		if err != nil {
			return nil, err
		}
		items = append(items, instancePageItem(record))
		byID[record.Key.ID] = record
	}
	for _, id := range in.InstanceIds {
		if err := validateInstanceID(string(id)); err != nil {
			return nil, err
		}
	}
	ids, next, err := selectPage(ctx, "DescribeInstances", stringsOf(in.InstanceIds), in.Filters, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeInstancesResult{Reservations: api.ReservationList{}, NextToken: next}
	positions := map[string]int{}
	for _, id := range ids {
		record := byID[id]
		position, exists := positions[record.ReservationID]
		if !exists {
			reservation, err := tx.Reservation(key(ctx, record.ReservationID))
			if err != nil {
				return nil, err
			}
			value := api.Reservation{ReservationId: new(api.String(reservation.Key.ID)), OwnerId: new(api.String(reservation.Key.Scope.AccountID)), Groups: api.GroupIdentifierList{}, Instances: api.InstanceList{}}
			if reservation.RequesterID != "" {
				value.RequesterId = new(api.String(reservation.RequesterID))
			}
			position = len(out.Reservations)
			positions[record.ReservationID] = position
			out.Reservations = append(out.Reservations, value)
		}
		out.Reservations[position].Instances = append(out.Reservations[position].Instances, record.Data)
	}
	return out, nil
}

func unmanagedInstanceOperator() *api.OperatorResponse {
	return &api.OperatorResponse{Managed: new(api.Boolean(false)), HiddenByDefault: new(api.Boolean(false))}
}

func instanceStatus(record InstanceRecord) api.InstanceStatus {
	// TODO: Comeback project scheduled events and application checks from their owning resource lifecycles.
	out := api.InstanceStatus{InstanceId: record.Data.InstanceId, InstanceState: record.Data.State, Operator: lambdaInstanceOperator(record)}
	if record.Data.Placement != nil {
		out.AvailabilityZone = record.Data.Placement.AvailabilityZone
		out.AvailabilityZoneId = record.Data.Placement.AvailabilityZoneId
	}
	if instanceState(record) != "running" {
		out.InstanceStatus = &api.InstanceStatusSummary{Status: new(api.SummaryStatus("not-applicable"))}
		out.SystemStatus = &api.InstanceStatusSummary{Status: new(api.SummaryStatus("not-applicable"))}
	} else {
		out.InstanceStatus = instanceCheckSummary(record.Health.Guest)
		out.SystemStatus = instanceCheckSummary(record.Health.System)
		out.AttachedEbsStatus = ebsCheckSummary(record.Health.AttachedEBS)
	}
	return out
}

func (s *Service) describeInstanceStatus(ctx context.Context, tx Transaction, in *api.DescribeInstanceStatusRequest) (*api.DescribeInstanceStatusResult, error) {
	if err := s.authorize(ctx, "DescribeInstanceStatus", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if len(in.InstanceIds) > 100 {
		return nil, failure("InvalidRequest", strconv.Itoa(len(in.InstanceIds))+" exceeds the maximum number of instance IDs that can be specificied (100). Please specify fewer than 100 instance IDs.")
	}
	if len(in.InstanceIds) > 0 && (in.MaxResults != nil || in.NextToken != nil) {
		return nil, failure("InvalidParameterCombination", "The parameter instanceIdsSet cannot be used with the parameter maxResults/nextToken.")
	}
	if in.MaxResults != nil && *in.MaxResults < 5 {
		return nil, failure("InvalidParameterValue", "Value ( "+strconv.Itoa(int(*in.MaxResults))+" ) for parameter maxResults is invalid. Expecting a value greater than 5.")
	}
	records, err := tx.Instances(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, id := range in.InstanceIds {
		if err := validateInstanceID(string(id)); err != nil {
			return nil, err
		}
	}
	items := make([]pageItem, 0, len(records))
	byID := make(map[string]api.InstanceStatus, len(records))
	for _, record := range records {
		status := instanceStatus(record)
		items = append(items, instanceStatusPageItem(&status))
		byID[record.Key.ID] = status
	}
	filters := in.Filters
	if !boolValue(in.IncludeAllInstances) {
		filters = append(slices.Clone(filters), api.Filter{Name: new(api.String("instance-state-name")), Values: api.ValueStringList{"running"}})
	}
	ids, next, err := selectPageItems(ctx, "DescribeInstanceStatus", stringsOf(in.InstanceIds), filters, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeInstanceStatusResult{InstanceStatuses: api.InstanceStatusList{}, NextToken: next}
	for _, id := range ids {
		out.InstanceStatuses = append(out.InstanceStatuses, byID[id])
	}
	return out, nil
}

func instanceStatusPageItem(status *api.InstanceStatus) pageItem {
	fields := map[string][]string{
		"availability-zone":      {str(status.AvailabilityZone)},
		"availability-zone-id":   {str(status.AvailabilityZoneId)},
		"instance-status.status": {str(status.InstanceStatus.Status)},
		"system-status.status":   {str(status.SystemStatus.Status)},
		"operator.managed":       {strconv.FormatBool(boolValue(status.Operator.Managed))},
	}
	if status.InstanceState != nil {
		fields["instance-state-name"] = []string{str(status.InstanceState.Name)}
		if status.InstanceState.Code != nil {
			fields["instance-state-code"] = []string{strconv.Itoa(int(*status.InstanceState.Code))}
		}
	}
	for _, detail := range status.InstanceStatus.Details {
		fields["instance-status."+str(detail.Name)] = []string{str(detail.Status)}
	}
	for _, detail := range status.SystemStatus.Details {
		fields["system-status."+str(detail.Name)] = []string{str(detail.Status)}
	}
	if status.AttachedEbsStatus != nil {
		fields["attached-ebs-status.status"] = []string{str(status.AttachedEbsStatus.Status)}
	}
	return pageItem{ID: str(status.InstanceId), Fields: fields}
}

func (s *Service) getConsoleOutput(ctx context.Context, tx Transaction, in *api.GetConsoleOutputRequest) (*api.GetConsoleOutputResult, error) {
	records, err := s.instanceCommandTargets(ctx, tx, "GetConsoleOutput", api.InstanceIdStringList{api.InstanceId(str(in.InstanceId))}, in.DryRun)
	if err != nil {
		return nil, err
	}
	record := records[0]
	out := &api.GetConsoleOutputResult{InstanceId: record.Data.InstanceId}
	if !record.ConsoleAt.IsZero() {
		out.Timestamp = new(api.DateTime(record.ConsoleAt))
		out.Output = new(api.String(base64.StdEncoding.EncodeToString(record.Console)))
	}
	return out, nil
}
