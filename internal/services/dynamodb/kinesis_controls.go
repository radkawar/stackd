package dynamodb

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/dynamodb"
	kinesisapi "stackd/internal/awsapi/kinesis"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"strings"
)

const KinesisServicePrincipal = "kinesisreplication.dynamodb.amazonaws.com"
const KinesisServiceRoleName = "AWSServiceRoleForDynamoDBKinesisDataStreamsReplication"

// KinesisStreams is the actual target API, never a bypass of target IAM or KMS.
type KinesisStreams interface {
	DescribeStream(context.Context, *kinesisapi.DescribeStreamInput) (*kinesisapi.DescribeStreamOutput, *awswire.Error)
	PutRecords(context.Context, *kinesisapi.PutRecordsInput) (*kinesisapi.PutRecordsOutput, *awswire.Error)
}
type KinesisIdentity interface {
	Context(context.Context, TableKey) (context.Context, error)
}

func registerKinesis(s *Service) {
	registerOperation(s, "EnableKinesisStreamingDestination", s.EnableKinesisStreamingDestination)
	registerOperation(s, "DescribeKinesisStreamingDestination", s.DescribeKinesisStreamingDestination)
	registerOperation(s, "DisableKinesisStreamingDestination", s.DisableKinesisStreamingDestination)
	registerOperation(s, "UpdateKinesisStreamingDestination", s.UpdateKinesisStreamingDestination)
}
func (s *Service) DescribeKinesisStreamingDestination(ctx context.Context, in *api.DescribeKinesisStreamingDestinationInput) (*api.DescribeKinesisStreamingDestinationOutput, *awswire.Error) {
	return runCommand(s, ctx, "DescribeKinesisStreamingDestination", in, s.describeKinesis)
}
func (s *Service) EnableKinesisStreamingDestination(ctx context.Context, in *api.EnableKinesisStreamingDestinationInput) (*api.EnableKinesisStreamingDestinationOutput, *awswire.Error) {
	admission := ""
	return runCommand(s, ctx, "EnableKinesisStreamingDestination", in,
		func(ctx context.Context, tx Transaction, in *api.EnableKinesisStreamingDestinationInput) (*api.EnableKinesisStreamingDestinationOutput, error) {
			return s.enableKinesis(context.WithValue(ctx, kinesisAdmissionKey{}, admission), tx, in)
		},
		func(ctx context.Context) error {
			var table TableRecord
			err := s.repository.View(ctx, func(r Reader) error {
				var err error
				table, err = s.controlTable(r.Context(), r, value(in.TableName), "EnableKinesisStreamingDestination", nil)
				return err
			})
			if err != nil {
				return err
			}
			parsed, err := arn.Parse(value(in.StreamArn))
			if err != nil || parsed.Service != "kinesis" || parsed.Partition != table.Key.Partition || parsed.Region != table.Key.Region || parsed.AccountID != table.Key.AccountID || !strings.HasPrefix(parsed.Resource, "stream/") || s.kinesis == nil {
				return nil
			}
			metadata := awsctx.FromContext(ctx)
			metadata.ParentEventID = apievents.EventID(ctx)
			ctx = awsctx.WithMetadata(ctx, metadata)
			_, rejected := s.kinesis.PutRecords(ctx, &kinesisapi.PutRecordsInput{StreamARN: new(kinesisapi.StreamARN(value(in.StreamArn))), DryRun: new(kinesisapi.BooleanObject(true)), Records: kinesisapi.PutRecordsRequestEntryList{{Data: kinesisapi.Data{0}, PartitionKey: new(kinesisapi.PartitionKey("DynamoDBDestinationValidation"))}}})
			if rejected == nil || rejected.Code != "DryRunOperationException" {
				admission = "User does not have a permission to use kinesis stream"
			}
			return nil
		})
}

type kinesisAdmissionKey struct{}

func (s *Service) DisableKinesisStreamingDestination(ctx context.Context, in *api.DisableKinesisStreamingDestinationInput) (*api.DisableKinesisStreamingDestinationOutput, *awswire.Error) {
	return runCommand(s, ctx, "DisableKinesisStreamingDestination", in, s.disableKinesis)
}
func (s *Service) UpdateKinesisStreamingDestination(ctx context.Context, in *api.UpdateKinesisStreamingDestinationInput) (*api.UpdateKinesisStreamingDestinationOutput, *awswire.Error) {
	return runCommand(s, ctx, "UpdateKinesisStreamingDestination", in, s.updateKinesis)
}

func destinationStateError(message string) error {
	return failure("ValidationException", "Table is not in a valid state to enable Kinesis Streaming Destination: "+message)
}
func destinationPrecision(p string) string {
	if p == "" {
		return "MILLISECOND"
	}
	return p
}
func validateDestinationPrecision(p string) error {
	if p != "MILLISECOND" && p != "MICROSECOND" {
		return failure("ValidationException", "ApproximateCreationDateTimePrecision must be MILLISECOND or MICROSECOND")
	}
	return nil
}
func destinationFor(ds []KinesisDestination, table TableRecord, stream string) (KinesisDestination, bool) {
	for _, d := range ds {
		if d.PhysicalName == table.PhysicalName && d.Table == table.Key && d.StreamARN == stream && !d.Superseded {
			return d, true
		}
	}
	return KinesisDestination{}, false
}

func (s *Service) enableKinesis(ctx context.Context, tx Transaction, in *api.EnableKinesisStreamingDestinationInput) (*api.EnableKinesisStreamingDestinationOutput, error) {
	table, err := s.controlTable(ctx, tx, value(in.TableName), "EnableKinesisStreamingDestination", nil)
	if err != nil {
		return nil, err
	}
	if err = transitionAvailable(table); err != nil {
		return nil, err
	}
	// Destination records are native table-stream captures.
	if err = s.requireEngine(); err != nil {
		return nil, err
	}
	stream := value(in.StreamArn)
	if len(stream) < 37 || len(stream) > 1024 {
		return nil, failure("ValidationException", "StreamArn must have length between 37 and 1024")
	}
	precision := ""
	if cfg := in.EnableKinesisStreamingConfiguration; cfg != nil && cfg.ApproximateCreationDateTimePrecision != nil {
		precision = value(cfg.ApproximateCreationDateTimePrecision)
		if err = validateDestinationPrecision(precision); err != nil {
			return nil, err
		}
	}
	ds, err := tx.KinesisDestinations()
	if err != nil {
		return nil, err
	}
	for _, d := range ds {
		if d.PhysicalName == table.PhysicalName && !d.Superseded && (d.Status == "ACTIVE" || d.Status == "ENABLING" || d.Status == "UPDATING") {
			return nil, destinationStateError("EnableKinesisStreamingDestination must be DISABLED or ENABLE_FAILED to perform ENABLE operation.")
		}
	}
	if s.kinesis == nil || s.kinesisIdentity == nil || s.roles == nil {
		return nil, errors.New("DynamoDB Kinesis integration is not configured")
	}
	if err = s.roles.EnsureServiceLinkedRole(tx.Context(), KinesisServicePrincipal); err != nil {
		return nil, err
	}
	// Retain only the decision, not caller credentials or session policies. The
	// native API admits ENABLING even when this prerequisite is denied.
	admission, _ := ctx.Value(kinesisAdmissionKey{}).(string)
	for _, action := range []string{"PutRecords", "DescribeStream", "ListStreams"} {
		resource := stream
		if action == "ListStreams" {
			resource = "*"
		}
		if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "kinesis:" + action, ResourceARN: resource}); rejected != nil {
			admission = "User does not have a permission to use kinesis stream"
			break
		}
	}
	if old, ok := destinationFor(ds, table, stream); ok {
		old.Superseded = true
		// A replacement pipeline overlaps the retiring one only briefly. The
		// envelope and precision still belong to each accepted subscription.
		overlap := s.clock.Now().Add(5 * time.Second)
		if old.CaptureUntil.After(overlap) {
			old.CaptureUntil = overlap
			if old.Status == "DISABLED" {
				old.Due = overlap
			}
		}
		if err = tx.PutKinesisDestination(old); err != nil {
			return nil, err
		}
	}
	d := KinesisDestination{ID: uuid.NewString(), Table: table.Key, PhysicalName: table.PhysicalName, StreamARN: stream, Status: "ENABLING", Precision: precision, AdmissionFailure: admission, Due: s.clock.Now().Add(time.Second)}
	if err = tx.PutKinesisDestination(d); err != nil {
		return nil, err
	}
	cfg := &api.EnableKinesisStreamingConfiguration{}
	if precision != "" {
		cfg.ApproximateCreationDateTimePrecision = new(api.ApproximateCreationDateTimePrecision(precision))
	}
	return &api.EnableKinesisStreamingDestinationOutput{TableName: new(api.TableName(table.Key.Name)), StreamArn: new(api.StreamArn(stream)), DestinationStatus: new(api.DestinationStatusENABLING), EnableKinesisStreamingConfiguration: cfg}, nil
}
func (s *Service) describeKinesis(ctx context.Context, tx Transaction, in *api.DescribeKinesisStreamingDestinationInput) (*api.DescribeKinesisStreamingDestinationOutput, error) {
	table, err := s.controlTable(ctx, tx, value(in.TableName), "DescribeKinesisStreamingDestination", nil)
	if err != nil {
		return nil, err
	}
	ds, err := tx.KinesisDestinations()
	if err != nil {
		return nil, err
	}
	out := &api.DescribeKinesisStreamingDestinationOutput{TableName: new(api.TableName(table.Key.Name)), KinesisDataStreamDestinations: api.KinesisDataStreamDestinations{}}
	for _, d := range ds {
		if d.PhysicalName != table.PhysicalName || d.Superseded {
			continue
		}
		v := api.KinesisDataStreamDestination{StreamArn: new(api.StreamArn(d.StreamARN)), DestinationStatus: new(api.DestinationStatus(d.Status))}
		p := d.Precision
		if d.PendingPrecision != "" {
			p = d.PendingPrecision
		}
		if p != "" && d.Status != "DISABLED" && d.Status != "ENABLE_FAILED" {
			v.ApproximateCreationDateTimePrecision = new(api.ApproximateCreationDateTimePrecision(p))
		}
		if d.Description != "" {
			v.DestinationStatusDescription = new(api.String(d.Description))
		}
		out.KinesisDataStreamDestinations = append(out.KinesisDataStreamDestinations, v)
	}
	return out, nil
}
func (s *Service) disableKinesis(ctx context.Context, tx Transaction, in *api.DisableKinesisStreamingDestinationInput) (*api.DisableKinesisStreamingDestinationOutput, error) {
	table, err := s.controlTable(ctx, tx, value(in.TableName), "DisableKinesisStreamingDestination", nil)
	if err != nil {
		return nil, err
	}
	ds, err := tx.KinesisDestinations()
	if err != nil {
		return nil, err
	}
	d, ok := destinationFor(ds, table, value(in.StreamArn))
	if !ok || d.Status != "ACTIVE" && d.Status != "DISABLING" {
		return nil, destinationStateError("KinesisStreamingDestination must be ACTIVE to perform DISABLE operation.")
	}
	if d.Status == "ACTIVE" {
		d.Status = "DISABLING"
		d.Due = s.clock.Now().Add(time.Second)
		// Native delivery is asynchronous beyond DISABLED and overlaps a new enable.
		// This finite drain window is a simulator timing policy, not an AWS SLA.
		d.CaptureUntil = s.clock.Now().Add(5 * time.Minute)
		if err = tx.PutKinesisDestination(d); err != nil {
			return nil, err
		}
	}
	return &api.DisableKinesisStreamingDestinationOutput{TableName: new(api.TableName(table.Key.Name)), StreamArn: new(api.StreamArn(d.StreamARN)), DestinationStatus: new(api.DestinationStatusDISABLING)}, nil
}
func (s *Service) updateKinesis(ctx context.Context, tx Transaction, in *api.UpdateKinesisStreamingDestinationInput) (*api.UpdateKinesisStreamingDestinationOutput, error) {
	table, err := s.controlTable(ctx, tx, value(in.TableName), "UpdateKinesisStreamingDestination", nil)
	if err != nil {
		return nil, err
	}
	if err = s.requireEngine(); err != nil {
		return nil, err
	}
	ds, err := tx.KinesisDestinations()
	if err != nil {
		return nil, err
	}
	d, ok := destinationFor(ds, table, value(in.StreamArn))
	if !ok {
		return nil, destinationStateError("No streaming destination with streamArn: " + value(in.StreamArn) + " found for table with tableName: " + table.Key.Name)
	}
	if d.Status != "ACTIVE" {
		return nil, destinationStateError("Kinesis streaming is not in ACTIVE state. Updates are only allowed in ACTIVE state.")
	}
	if in.UpdateKinesisStreamingConfiguration == nil || in.UpdateKinesisStreamingConfiguration.ApproximateCreationDateTimePrecision == nil {
		return nil, failure("ValidationException", "Streaming destination cannot be updated with given parameters: UpdateKinesisStreamingConfiguration cannot be null or contain only null values")
	}
	p := value(in.UpdateKinesisStreamingConfiguration.ApproximateCreationDateTimePrecision)
	if err = validateDestinationPrecision(p); err != nil {
		return nil, err
	}
	if p == destinationPrecision(d.Precision) {
		return nil, failure("ValidationException", "Invalid Request: Precision is already set to the desired value of "+p)
	}
	d.PendingPrecision = p
	d.Status = "UPDATING"
	d.Due = s.clock.Now().Add(time.Second)
	if err = tx.PutKinesisDestination(d); err != nil {
		return nil, err
	}
	return &api.UpdateKinesisStreamingDestinationOutput{TableName: new(api.TableName(table.Key.Name)), StreamArn: new(api.StreamArn(d.StreamARN)), DestinationStatus: new(api.DestinationStatusUPDATING), UpdateKinesisStreamingConfiguration: &api.UpdateKinesisStreamingConfiguration{ApproximateCreationDateTimePrecision: new(api.ApproximateCreationDateTimePrecision(p))}}, nil
}
