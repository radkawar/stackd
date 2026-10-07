package configservice

import (
	"context"
	"slices"
	api "stackd/internal/awsapi/configservice"
	"strings"
	"time"
)

func (s *Service) putChannel(ctx context.Context, in *api.PutDeliveryChannelInput) (*api.PutDeliveryChannelOutput, error) {
	if err := s.authorize(ctx, "PutDeliveryChannel"); err != nil {
		return nil, err
	}
	if in.DeliveryChannel == nil {
		return nil, failure("ValidationException", "DeliveryChannel is required.")
	}
	c := in.DeliveryChannel
	row := Channel{Scope: scopeFor(ctx), Name: value(c.Name), Bucket: value(c.S3BucketName), Prefix: value(c.S3KeyPrefix), KMSKeyARN: value(c.S3KmsKeyArn), TopicARN: value(c.SnsTopicARN), Frequency: "TwentyFour_Hours"}
	if row.Name == "" {
		return nil, failure("InvalidDeliveryChannelNameException", "Delivery channel name is required.")
	}
	if row.Bucket == "" {
		return nil, failure("NoSuchBucketException", "Delivery bucket is required.")
	}
	if c.ConfigSnapshotDeliveryProperties != nil {
		row.Frequency = value(c.ConfigSnapshotDeliveryProperties.DeliveryFrequency)
	}
	if deliveryPeriod(row.Frequency) == 0 {
		return nil, failure("InvalidDeliveryFrequencyException", "Invalid snapshot delivery frequency.")
	}
	var recorder Recorder
	err := s.repository.View(ctx, func(reader Reader) error {
		r, ok, err := reader.Recorder(row.Scope)
		if err != nil {
			return err
		}
		if !ok {
			return failure("NoAvailableConfigurationRecorderException", "A configuration recorder must be configured first.")
		}
		recorder = r
		old, found, err := reader.Channel(row.Scope)
		if err != nil {
			return err
		}
		if found && old.Name != row.Name {
			return failure("MaxNumberOfDeliveryChannelsExceededException", "Only one delivery channel is allowed per account and Region.")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if s.effects == nil {
		return nil, failure("InternalServiceException", "Config delivery owner is not configured.")
	}
	if err := s.effects.ValidateChannel(ctx, recorder, row); err != nil {
		return nil, err
	}
	out := &api.PutDeliveryChannelOutput{}
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		if err := s.authorize(tx.Context(), "PutDeliveryChannel"); err != nil {
			return err
		}
		r, ok, err := tx.Recorder(row.Scope)
		if err != nil {
			return err
		}
		if !ok {
			return failure("NoAvailableConfigurationRecorderException", "A configuration recorder must be configured first.")
		}
		if r.RoleARN != recorder.RoleARN {
			return failure("InvalidRoleException", "Recorder role changed during channel validation.")
		}
		old, found, err := tx.Channel(row.Scope)
		if err != nil {
			return err
		}
		if found && old.Name != row.Name {
			return failure("MaxNumberOfDeliveryChannelsExceededException", "Only one delivery channel is allowed per account and Region.")
		}
		if err := checkCloudFormationOwnership(tx, channelOwnershipARN(row.Scope, row.Name), found); err != nil {
			return err
		}
		row.CFNOwnership = old.CFNOwnership
		if !found {
			row.CFNOwnership = creationOwnership(tx.Context())
		}
		row.LastAttempt, row.LastSuccess, row.Status, row.ErrorCode, row.ErrorMessage = old.LastAttempt, old.LastSuccess, old.Status, old.ErrorCode, old.ErrorMessage
		row.NextDelivery = s.clock.Now().Add(deliveryPeriod(row.Frequency))
		if err := tx.PutChannel(row); err != nil {
			return err
		}
		if err := s.startAdmittedRecorder(tx, r); err != nil {
			return err
		}
		if err := s.schedulePeriodicSnapshot(tx, row); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "PutDeliveryChannel", in, out, nil)
	})
	return out, err
}
func deliveryPeriod(f string) time.Duration {
	switch f {
	case "One_Hour":
		return time.Hour
	case "Three_Hours":
		return 3 * time.Hour
	case "Six_Hours":
		return 6 * time.Hour
	case "Twelve_Hours":
		return 12 * time.Hour
	case "TwentyFour_Hours":
		return 24 * time.Hour
	}
	return 0
}
func channelAPI(c Channel) api.DeliveryChannel {
	out := api.DeliveryChannel{Name: new(api.ChannelName(c.Name)), S3BucketName: new(api.String(c.Bucket)), ConfigSnapshotDeliveryProperties: &api.ConfigSnapshotDeliveryProperties{DeliveryFrequency: new(api.MaximumExecutionFrequency(c.Frequency))}}
	if c.Prefix != "" {
		out.S3KeyPrefix = new(api.String(c.Prefix))
	}
	if c.KMSKeyARN != "" {
		out.S3KmsKeyArn = new(api.String(c.KMSKeyARN))
	}
	if c.TopicARN != "" {
		out.SnsTopicARN = new(api.String(c.TopicARN))
	}
	return out
}
func (s *Service) describeChannels(tx Transaction, in *api.DescribeDeliveryChannelsInput) (*api.DescribeDeliveryChannelsOutput, error) {
	if err := s.authorize(tx.Context(), "DescribeDeliveryChannels"); err != nil {
		return nil, err
	}
	out := &api.DescribeDeliveryChannelsOutput{DeliveryChannels: api.DeliveryChannelList{}}
	c, found, err := tx.Channel(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	if found && (len(in.DeliveryChannelNames) == 0 || slices.Contains(in.DeliveryChannelNames, api.ChannelName(c.Name))) {
		if err := checkCloudFormationClaim(tx.Context(), c.CFNOwnership); err != nil {
			return nil, err
		}
		out.DeliveryChannels = append(out.DeliveryChannels, channelAPI(c))
	}
	return out, nil
}
func exportInfo(deliveries []Delivery, scope Scope, channel, kind string) *api.ConfigExportDeliveryInfo {
	info := &api.ConfigExportDeliveryInfo{}
	var latest *Delivery
	for i := range deliveries {
		d := &deliveries[i]
		if d.Scope != scope || d.ChannelName != channel || d.Kind != kind {
			continue
		}
		if d.Status == "PENDING" && (info.NextDeliveryTime == nil || d.Due.Before(*info.NextDeliveryTime)) {
			info.NextDeliveryTime = &d.Due
		}
		if d.Attempts > 0 && (latest == nil || d.CompletedAt.After(latest.CompletedAt) || d.CompletedAt.Equal(latest.CompletedAt) && d.CreatedAt.After(latest.CreatedAt)) {
			latest = d
		}
		if d.Status == "SUCCESS" && (info.LastSuccessfulTime == nil || d.CompletedAt.After(*info.LastSuccessfulTime)) {
			info.LastSuccessfulTime = &d.CompletedAt
		}
	}
	if latest != nil {
		info.LastAttemptTime = &latest.CompletedAt
		status := "Success"
		if latest.Status != "SUCCESS" {
			status = "Failure"
		}
		info.LastStatus = new(api.DeliveryStatus(status))
		if latest.ErrorCode != "" {
			info.LastErrorCode = new(api.String(latest.ErrorCode))
			info.LastErrorMessage = new(api.String(latest.ErrorMessage))
		}
	}
	return info
}
func (s *Service) describeChannelStatus(tx Transaction, in *api.DescribeDeliveryChannelStatusInput) (*api.DescribeDeliveryChannelStatusOutput, error) {
	if err := s.authorize(tx.Context(), "DescribeDeliveryChannelStatus"); err != nil {
		return nil, err
	}
	out := &api.DescribeDeliveryChannelStatusOutput{DeliveryChannelsStatus: api.DeliveryChannelStatusList{}}
	c, found, err := tx.Channel(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	if !found || len(in.DeliveryChannelNames) > 0 && !slices.Contains(in.DeliveryChannelNames, api.ChannelName(c.Name)) {
		return out, nil
	}
	rows, err := tx.Deliveries()
	if err != nil {
		return nil, err
	}
	status := api.DeliveryChannelStatus{Name: new(api.String(c.Name)), ConfigHistoryDeliveryInfo: exportInfo(rows, c.Scope, c.Name, "ConfigHistory"), ConfigSnapshotDeliveryInfo: exportInfo(rows, c.Scope, c.Name, "ConfigSnapshot"), ConfigStreamDeliveryInfo: &api.ConfigStreamDeliveryInfo{}}
	if c.TopicARN == "" {
		status.ConfigStreamDeliveryInfo.LastStatus = new(api.DeliveryStatus("Not_Applicable"))
	} else {
		stream := exportInfo(rows, c.Scope, c.Name, "ConfigurationItemChangeNotification")
		status.ConfigStreamDeliveryInfo.LastStatus = stream.LastStatus
		status.ConfigStreamDeliveryInfo.LastStatusChangeTime = stream.LastAttemptTime
		status.ConfigStreamDeliveryInfo.LastErrorCode = stream.LastErrorCode
		status.ConfigStreamDeliveryInfo.LastErrorMessage = stream.LastErrorMessage
	}
	out.DeliveryChannelsStatus = append(out.DeliveryChannelsStatus, status)
	return out, nil
}
func (s *Service) deleteChannel(tx Transaction, in *api.DeleteDeliveryChannelInput) (*api.DeleteDeliveryChannelOutput, error) {
	if err := s.authorize(tx.Context(), "DeleteDeliveryChannel"); err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	c, found, err := tx.Channel(scope)
	if err != nil {
		return nil, err
	}
	if !found || c.Name != value(in.DeliveryChannelName) {
		return nil, failure("NoSuchDeliveryChannelException", "The specified delivery channel does not exist.")
	}
	if err := checkCloudFormationClaim(tx.Context(), c.CFNOwnership); err != nil {
		return nil, err
	}
	r, found, err := tx.Recorder(scope)
	if err != nil {
		return nil, err
	}
	if found && r.Recording {
		return nil, failure("LastDeliveryChannelDeleteFailedException", "Stop the configuration recorder before deleting the delivery channel.")
	}
	deliveries, err := tx.Deliveries()
	if err != nil {
		return nil, err
	}
	for _, delivery := range deliveries {
		if delivery.Scope == scope && delivery.ChannelName == c.Name && (delivery.Status == "PENDING" || delivery.Status == "RUNNING") {
			delivery.Status = "CANCELLED"
			if err := tx.PutDelivery(delivery); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.DeleteChannel(scope); err != nil {
		return nil, err
	}
	return &api.DeleteDeliveryChannelOutput{}, nil
}
func (s *Service) deliverSnapshot(tx Transaction, in *api.DeliverConfigSnapshotInput) (*api.DeliverConfigSnapshotOutput, error) {
	if err := s.authorize(tx.Context(), "DeliverConfigSnapshot"); err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	r, found, err := tx.Recorder(scope)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, failure("NoAvailableConfigurationRecorderException", "A configuration recorder is required.")
	}
	if !r.Recording {
		return nil, failure("NoRunningConfigurationRecorderException", "The configuration recorder is not running.")
	}
	c, found, err := tx.Channel(scope)
	if err != nil {
		return nil, err
	}
	if !found || c.Name != value(in.DeliveryChannelName) {
		return nil, failure("NoSuchDeliveryChannelException", "The specified delivery channel does not exist.")
	}
	id := uuid()
	rows, err := tx.Items(scope)
	if err != nil {
		return nil, err
	}
	var last int64
	for _, item := range rows {
		last = max(last, item.Sequence)
	}
	now := s.clock.Now().UTC()
	d := Delivery{Scope: scope, ID: id, ChannelName: c.Name, Kind: "ConfigSnapshot", Due: now, CreatedAt: now, Status: "PENDING", LastSequence: last}
	d.ObjectKey = objectKey(c, d)
	if err := tx.PutDelivery(d); err != nil {
		return nil, err
	}
	return &api.DeliverConfigSnapshotOutput{ConfigSnapshotId: new(api.String(id))}, nil
}
func objectKey(c Channel, d Delivery) string {
	key := "AWSLogs/" + c.AccountID + "/Config/" + c.Region + "/" + d.CreatedAt.Format("2006/1/2") + "/" + d.Kind + "/" + c.AccountID + "_Config_" + c.Region + "_" + d.Kind + "_" + d.CreatedAt.Format("20060102T150405Z") + "_" + d.ID + ".json.gz"
	if c.Prefix != "" {
		key = strings.TrimSuffix(c.Prefix, "/") + "/" + key
	}
	return key
}
