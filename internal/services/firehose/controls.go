package firehose

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/firehose"
	"stackd/internal/scheduler"
)

const DestinationDescriptionID = "destinationId-000000000001"

// The short readiness/deletion delay is a deterministic local policy, not an
// assertion about AWS's asynchronous provisioning duration.
const lifecycleDelay = time.Second

func registerControls(s *Service) {
	registerControl(s, "CreateDeliveryStream", s.createDeliveryStream)
	registerControl(s, "DeleteDeliveryStream", s.deleteDeliveryStream)
	registerControl(s, "DescribeDeliveryStream", s.describeDeliveryStream)
	registerControl(s, "ListDeliveryStreams", s.listDeliveryStreams)
	registerControl(s, "ListTagsForDeliveryStream", s.listTagsForDeliveryStream)
	registerControl(s, "TagDeliveryStream", s.tagDeliveryStream)
	registerControl(s, "UntagDeliveryStream", s.untagDeliveryStream)
	registerControl(s, "UpdateDestination", s.updateDestination)
}

func (s *Service) createDeliveryStream(ctx context.Context, tx Transaction, in *api.CreateDeliveryStreamInput) (*api.CreateDeliveryStreamOutput, error) {
	key := StreamKey{Scope: scopeFor(ctx), Name: value(in.DeliveryStreamName)}
	if key.Name == "" {
		return nil, failure("InvalidArgumentException", "DeliveryStreamName must not be empty")
	}
	tags, err := requestTags(in.Tags)
	if err != nil {
		return nil, err
	}
	if len(tags) > 50 {
		return nil, failure("InvalidArgumentException", "A delivery stream cannot have more than 50 tags")
	}
	if err := s.authorize(ctx, tx, key, "CreateDeliveryStream", requestTagConditions(tags)); err != nil {
		return nil, err
	}
	if _, err := tx.Stream(key); err == nil {
		return nil, failure("ResourceInUseException", fmt.Sprintf("Firehose %s under accountId %s already exists", key.Name, key.AccountID))
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if in.DeliveryStreamEncryptionConfigurationInput != nil {
		// TODO: Comeback — implement Firehose server-side encryption before accepting it.
		return nil, unsupported("delivery stream encryption")
	}
	if in.MSKSourceConfiguration != nil || in.DatabaseSourceConfiguration != nil || in.DirectPutSourceConfiguration != nil {
		// TODO: Comeback — implement MSK/database sources and provisioned DirectPut throughput.
		return nil, unsupported("MSK/database sources and DirectPut throughput configuration")
	}
	kind := value(in.DeliveryStreamType)
	if kind == "" {
		kind = "DirectPut"
	}
	if kind != "DirectPut" && kind != "KinesisStreamAsSource" {
		// TODO: Comeback — implement other source families.
		return nil, unsupported("delivery stream type " + kind)
	}
	if (kind == "KinesisStreamAsSource") != (in.KinesisStreamSourceConfiguration != nil) {
		return nil, failure("InvalidArgumentException", "KinesisStreamSourceConfiguration must be specified exactly when DeliveryStreamType is KinesisStreamAsSource")
	}
	destination, err := createDestination(in)
	if err != nil {
		return nil, err
	}
	roles := append(processorRoleARNs(destination.ProcessingConfiguration), value(destination.RoleARN))
	if destination.S3BackupDescription != nil {
		roles = append(roles, value(destination.S3BackupDescription.RoleARN))
	}
	if err := s.passRole(ctx, key, roles...); err != nil {
		return nil, err
	}
	if err := s.validateDestinations(tx.Context(), key, destination); err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	stream := StreamRecord{Key: key, ID: uuid.NewString(), Status: "CREATING", Version: 1, Created: now, LifecycleDue: now.Add(lifecycleDelay), Destination: destination, Tags: tags}
	if source := in.KinesisStreamSourceConfiguration; source != nil {
		if value(source.RoleARN) == "" || value(source.KinesisStreamARN) == "" {
			return nil, failure("InvalidArgumentException", "A Kinesis source requires KinesisStreamARN and RoleARN")
		}
		if err := s.passRole(ctx, key, value(source.RoleARN)); err != nil {
			return nil, err
		}
		retained := KinesisSourceRecord{ARN: value(source.KinesisStreamARN), RoleARN: value(source.RoleARN), DeliveryStart: now, Due: stream.LifecycleDue}
		if s.source == nil {
			return nil, unsupported("No Kinesis source adapter is configured.")
		}
		metadata, rejected := s.source.Describe(tx.Context(), key, retained)
		if rejected != nil {
			if rejected.StatusCode >= 500 {
				return nil, rejected
			}
			return nil, failure("InvalidArgumentException", rejected.Message)
		}
		if metadata == nil || metadata.StreamCreationTimestamp == nil || metadata.RetentionPeriodHours == nil {
			return nil, failure("InvalidArgumentException", "Kinesis source metadata is incomplete")
		}
		retained.Created = *metadata.StreamCreationTimestamp
		retained.RetentionHours = int32(*metadata.RetentionPeriodHours)
		stream.Source = &retained
	}
	if err := tx.PutStream(stream); err != nil {
		return nil, err
	}
	return &api.CreateDeliveryStreamOutput{DeliveryStreamARN: new(api.DeliveryStreamARN(key.ARN()))}, nil
}

func (s *Service) deleteDeliveryStream(ctx context.Context, tx Transaction, in *api.DeleteDeliveryStreamInput) (*api.DeleteDeliveryStreamOutput, error) {
	stream, err := s.loadStream(ctx, tx, value(in.DeliveryStreamName), "DeleteDeliveryStream")
	if err != nil {
		return nil, err
	}
	if stream.Status == "DELETING" {
		return &api.DeleteDeliveryStreamOutput{}, nil
	}
	if stream.Status != "ACTIVE" {
		return nil, failure("ResourceInUseException", fmt.Sprintf("Firehose %s under account %s cannot be deleted in %s state", stream.Key.Name, stream.Key.AccountID, stream.Status))
	}
	stream.Status = "DELETING"
	stream.LifecycleDue = s.clock.Now().UTC().Add(lifecycleDelay)
	if err := tx.PutStream(stream); err != nil {
		return nil, err
	}
	return &api.DeleteDeliveryStreamOutput{}, nil
}

func (s *Service) describeDeliveryStream(ctx context.Context, tx Transaction, in *api.DescribeDeliveryStreamInput) (*api.DescribeDeliveryStreamOutput, error) {
	stream, err := s.loadStream(ctx, tx, value(in.DeliveryStreamName), "DescribeDeliveryStream")
	if err != nil {
		return nil, err
	}
	description := &api.DeliveryStreamDescription{
		DeliveryStreamName: new(api.DeliveryStreamName(stream.Key.Name)), DeliveryStreamARN: new(api.DeliveryStreamARN(stream.Key.ARN())),
		DeliveryStreamStatus: new(api.DeliveryStreamStatus(stream.Status)), DeliveryStreamType: new(api.DeliveryStreamType("DirectPut")),
		VersionId: new(api.DeliveryStreamVersionId(strconv.FormatInt(stream.Version, 10))), CreateTimestamp: &stream.Created, LastUpdateTimestamp: stream.Updated,
		DeliveryStreamEncryptionConfiguration: &api.DeliveryStreamEncryptionConfiguration{Status: new(api.DeliveryStreamEncryptionStatus("DISABLED"))},
		Destinations:                          api.DestinationDescriptionList{{DestinationId: new(api.DestinationId(DestinationDescriptionID)), S3DestinationDescription: basicDestination(stream.Destination), ExtendedS3DestinationDescription: &stream.Destination}},
		HasMoreDestinations:                   new(api.BooleanObject(false)),
	}
	if source := stream.Source; source != nil {
		description.DeliveryStreamType = new(api.DeliveryStreamType("KinesisStreamAsSource"))
		description.DeliveryStreamEncryptionConfiguration = nil
		description.Source = &api.SourceDescription{KinesisStreamSourceDescription: &api.KinesisStreamSourceDescription{KinesisStreamARN: new(api.KinesisStreamARN(source.ARN)), RoleARN: new(api.RoleARN(source.RoleARN)), DeliveryStartTimestamp: &source.DeliveryStart}}
	}
	// Native Describe returns the sole destination even for an unknown exclusive cursor.
	return &api.DescribeDeliveryStreamOutput{DeliveryStreamDescription: description}, nil
}

func (s *Service) listDeliveryStreams(ctx context.Context, tx Transaction, in *api.ListDeliveryStreamsInput) (*api.ListDeliveryStreamsOutput, error) {
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "firehose:ListDeliveryStreams", ResourceARN: "*", EvaluationTime: &now}); rejected != nil {
		return nil, rejected
	}
	limit := 10
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	if limit < 1 {
		return nil, failure("InvalidArgumentException", "Limit must be positive")
	}
	streams, err := tx.Streams(StreamQuery{Scope: scopeFor(ctx), Type: value(in.DeliveryStreamType), After: value(in.ExclusiveStartDeliveryStreamName), Limit: limit + 1})
	if err != nil {
		return nil, err
	}
	out := &api.ListDeliveryStreamsOutput{DeliveryStreamNames: api.DeliveryStreamNameList{}, HasMoreDeliveryStreams: new(api.BooleanObject(len(streams) > limit))}
	if len(streams) > limit {
		streams = streams[:limit]
	}
	for _, stream := range streams {
		out.DeliveryStreamNames = append(out.DeliveryStreamNames, api.DeliveryStreamName(stream.Key.Name))
	}
	return out, nil
}

func (s *Service) updateDestination(ctx context.Context, tx Transaction, in *api.UpdateDestinationInput) (*api.UpdateDestinationOutput, error) {
	stream, err := s.loadStream(ctx, tx, value(in.DeliveryStreamName), "UpdateDestination")
	if err != nil {
		return nil, err
	}
	if stream.Status != "ACTIVE" {
		return nil, failure("ResourceInUseException", fmt.Sprintf("Cannot update firehose: %s when it is in %s status", stream.Key.Name, stream.Status))
	}
	version := strconv.FormatInt(stream.Version, 10)
	if value(in.CurrentDeliveryStreamVersionId) != version {
		return nil, failure("ConcurrentModificationException", fmt.Sprintf("Cannot update firehose: %s since the current version id: %s and specified version id: %s do not match", stream.Key.Name, version, value(in.CurrentDeliveryStreamVersionId)))
	}
	if value(in.DestinationId) != DestinationDescriptionID {
		return nil, failure("InvalidArgumentException", "Destination Id "+value(in.DestinationId)+" not found")
	}
	update, err := destinationUpdate(in)
	if err != nil {
		return nil, err
	}
	destination, err := mergeDestination(stream.Destination, update)
	if err != nil {
		return nil, err
	}
	if err := validateSourceProcessingUpdate(stream.Destination, destination); err != nil {
		return nil, err
	}
	var roles []string
	if update.RoleARN != nil {
		roles = append(roles, value(update.RoleARN))
	}
	if update.ProcessingConfiguration != nil {
		roles = append(roles, processorRoleARNs(destination.ProcessingConfiguration)...)
	}
	if update.S3BackupUpdate != nil && update.S3BackupUpdate.RoleARN != nil {
		roles = append(roles, value(update.S3BackupUpdate.RoleARN))
	}
	if err := s.passRole(ctx, stream.Key, roles...); err != nil {
		return nil, err
	}
	if err := s.validateDestinations(tx.Context(), stream.Key, destination); err != nil {
		return nil, err
	}
	if reflect.DeepEqual(destination, stream.Destination) {
		return &api.UpdateDestinationOutput{}, nil
	}
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	stream.Destination, stream.Updated = destination, &now
	stream.Version++
	if stream.BufferID != "" {
		buffer, err := tx.Buffer(stream.BufferID)
		if err != nil {
			return nil, err
		}
		if buffer.StreamID == stream.ID && buffer.Configuration == nil {
			buffer.Due = deliveryBufferDue(buffer, destination)
			if err := tx.PutBuffer(buffer); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.PutStream(stream); err != nil {
		return nil, err
	}
	return &api.UpdateDestinationOutput{}, nil
}

type lifecycleJobs struct{ s *Service }

func (j lifecycleJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var stream StreamRecord
	err := j.s.repository.View(ctx, func(r Reader) error { var err error; stream, err = r.NextLifecycle(); return err })
	if errors.Is(err, ErrNotFound) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	return streamJob(stream, stream.LifecycleDue), true, nil
}

func (j lifecycleJobs) Run(ctx context.Context, job scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		stream, err := tx.StreamByID(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if stream.ID != job.Key || uint64(stream.Version) != job.Version || stream.LifecycleDue.IsZero() || stream.LifecycleDue.After(j.s.clock.Now()) {
			return nil
		}
		switch stream.Status {
		case "DELETING":
			return tx.DeleteStream(stream.Key)
		case "CREATING":
			stream.Status, stream.LifecycleDue = "ACTIVE", time.Time{}
			return tx.PutStream(stream)
		default:
			return nil
		}
	})
}
