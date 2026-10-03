package lambda

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

type documentDBMappingControl struct{ s *Service }

var documentDBCollectionName = regexp.MustCompile(`^[_a-zA-Z0-9][^$\x00]*$`)

func (c documentDBMappingControl) createSettings(in *api.CreateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	v := EventSourceMappingSettings{BatchSize: 100, BatchingWindow: 500 * time.Millisecond, DocumentDB: &DocumentDBMappingSettings{FullDocument: "Default", StartingPosition: value(in.StartingPosition)}}
	if len(in.Topics) > 0 || len(in.Queues) > 0 || in.SelfManagedEventSource != nil {
		return v, mappingParameter("Topics, Queues and SelfManagedEventSource do not apply to DocumentDB.")
	}
	if v.DocumentDB.StartingPosition == "" {
		v.DocumentDB.StartingPosition = "LATEST"
	}
	switch v.DocumentDB.StartingPosition {
	case "LATEST", "TRIM_HORIZON":
	case "AT_TIMESTAMP":
		if in.StartingPositionTimestamp == nil {
			return v, mappingParameter("StartingPositionTimestamp is required for AT_TIMESTAMP.")
		}
		stamp := time.Time(*in.StartingPositionTimestamp)
		if stamp.Before(time.Unix(0, 0)) || stamp.After(c.s.clock.Now()) {
			return v, mappingParameter("StartingPositionTimestamp must be between the Unix epoch and the present.")
		}
		v.DocumentDB.StartingPositionTimestamp = stamp
	default:
		return v, mappingParameter("StartingPosition must be TRIM_HORIZON, LATEST or AT_TIMESTAMP for DocumentDB.")
	}
	if config := in.DocumentDBEventSourceConfig; config != nil {
		v.DocumentDB.Database = value(config.DatabaseName)
		v.DocumentDB.Collection = value(config.CollectionName)
		if config.CollectionName != nil && v.DocumentDB.Collection == "" {
			return v, mappingParameter("CollectionName must not be empty when specified.")
		}
	}
	return applyDocumentDBMappingSettings(v, mappingSettingsInput(in))
}

func (c documentDBMappingControl) updateSettings(v EventSourceMappingSettings, in *api.UpdateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	if config := in.DocumentDBEventSourceConfig; config != nil {
		if config.DatabaseName != nil && config.CollectionName != nil {
			return v, mappingParameter("Invalid parameters: databaseName, collectionName")
		}
		if config.DatabaseName != nil {
			return v, mappingParameter("Invalid parameters: databaseName")
		}
		if config.CollectionName != nil {
			return v, mappingParameter("Invalid parameters: collectionName")
		}
	}
	v.DocumentDB = cloneDocumentDBMappingSettings(v.DocumentDB)
	return applyDocumentDBMappingSettings(v, in)
}

func applyDocumentDBMappingSettings(v EventSourceMappingSettings, in *api.UpdateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	d := v.DocumentDB
	// AWS explicitly excludes DocumentDB from event filtering. Database/collection
	// selection is a native watch scope, not a second Lambda filtering convention.
	if in.FilterCriteria != nil || in.KMSKeyArn != nil {
		return v, mappingParameter("Event filtering is not supported for DocumentDB event sources.")
	}
	if in.ScalingConfig != nil || in.ProvisionedPollerConfig != nil || in.AmazonManagedKafkaEventSourceConfig != nil || in.SelfManagedKafkaEventSourceConfig != nil || in.ParallelizationFactor != nil || in.TumblingWindowInSeconds != nil || in.LoggingConfig != nil || in.DestinationConfig != nil || len(in.FunctionResponseTypes) > 0 || in.MaximumRetryAttempts != nil || in.MaximumRecordAgeInSeconds != nil || in.BisectBatchOnFunctionError != nil {
		return v, mappingParameter("The supplied configuration does not apply to DocumentDB event sources.")
	}
	if config := in.DocumentDBEventSourceConfig; config != nil {
		if config.FullDocument != nil {
			d.FullDocument = value(config.FullDocument)
		}
	}
	if d.Database == "" || len(d.Database) > 63 || strings.ContainsAny(d.Database, "/. \"$\x00") {
		return v, mappingParameter("A valid DocumentDB DatabaseName is required.")
	}
	if d.Collection != "" && (len(d.Collection) > 57 || strings.HasPrefix(d.Collection, "system.") || !documentDBCollectionName.MatchString(d.Collection)) {
		return v, mappingParameter("Invalid DocumentDB CollectionName.")
	}
	if d.FullDocument != "Default" && d.FullDocument != "UpdateLookup" {
		return v, mappingParameter("FullDocument must be Default or UpdateLookup.")
	}
	if in.SourceAccessConfigurations != nil {
		if len(in.SourceAccessConfigurations) != 1 || value(in.SourceAccessConfigurations[0].Type) != "BASIC_AUTH" {
			return v, mappingParameter("DocumentDB requires one BASIC_AUTH source access configuration.")
		}
		parsed, err := arn.Parse(value(in.SourceAccessConfigurations[0].URI))
		if err != nil || parsed.Service != "secretsmanager" || !strings.HasPrefix(parsed.Resource, "secret:") {
			return v, mappingParameter("BASIC_AUTH requires a Secrets Manager secret ARN.")
		}
		d.SecretARN = parsed.String()
	}
	if d.SecretARN == "" {
		return v, mappingParameter("DocumentDB requires BASIC_AUTH credentials in Secrets Manager.")
	}
	var wire *awswire.Error
	v, wire = applyCommonMappingSettings(v, in)
	if wire != nil {
		return v, wire
	}
	if v.BatchSize < 1 || v.BatchSize > 10000 || v.BatchingWindow < 0 || v.BatchingWindow > 300*time.Second {
		return v, mappingParameter("DocumentDB BatchSize must be between 1 and 10000 and batching window between 0 and 300 seconds.")
	}
	return v, nil
}

func (c documentDBMappingControl) preflight(ctx context.Context, f FunctionRecord, key EventSourceMappingKey, source string, settings EventSourceMappingSettings, _ *api.UpdateEventSourceMappingInput) *awswire.Error {
	parsed, err := arn.Parse(source)
	if err != nil || parsed.Service != "rds" || !strings.HasPrefix(parsed.Resource, "cluster:") || strings.TrimPrefix(parsed.Resource, "cluster:") == "" {
		return mappingParameter("EventSourceArn must identify a DocumentDB cluster.")
	}
	if parsed.Partition != f.Key.Partition || parsed.AccountID != f.Key.Account || parsed.Region != f.Key.Region {
		return mappingParameter("DocumentDB source and function must be in the same account and Region.")
	}
	if f.Timeout > 840 {
		return mappingParameter("DocumentDB requires a function timeout of no more than 840 seconds.")
	}
	if c.s.documentDB == nil {
		return unsupported("DocumentDB event sources require a configured native DocumentDB source adapter.")
	}
	var checkpoint DocumentDBCheckpoint
	err = c.s.repository.View(ctx, func(r Reader) error {
		var err error
		checkpoint, err = r.DocumentDBCheckpoint(key)
		if err == ErrNotFound {
			return nil
		}
		return err
	})
	if err != nil {
		return sourceWireError(err)
	}
	incarnation, err := c.s.documentDB.Check(ctx, f.Key, f.Role, EventSourceMappingRecord{Key: key, EventSourceARN: source, Settings: settings}, checkpoint)
	if err != nil {
		return streamMappingPreflightError(sourceWireError(err))
	}
	settings.DocumentDB.Incarnation = incarnation
	return nil
}
func (c documentDBMappingControl) createTransition(v *EventSourceMappingRecord, enabled bool) {
	(streamMappingControl{s: c.s}).createTransition(v, enabled)
}
func (c documentDBMappingControl) updateTransition(v *EventSourceMappingRecord, enabled *api.Enabled) {
	(streamMappingControl{s: c.s}).updateTransition(v, enabled)
}
func documentDBMappingConfiguration(v EventSourceMappingRecord, out *api.EventSourceMappingConfiguration) {
	d := v.Settings.DocumentDB
	out.DocumentDBEventSourceConfig = &api.DocumentDBEventSourceConfig{DatabaseName: new(api.DatabaseName(d.Database)), FullDocument: new(api.FullDocument(d.FullDocument))}
	if d.Collection != "" {
		out.DocumentDBEventSourceConfig.CollectionName = new(api.CollectionName(d.Collection))
	}
	out.SourceAccessConfigurations = api.SourceAccessConfigurations{{Type: new(api.SourceAccessTypeBASIC_AUTH), URI: new(api.URI(d.SecretARN))}}
	out.StartingPosition = new(api.EventSourcePosition(d.StartingPosition))
	if !d.StartingPositionTimestamp.IsZero() {
		out.StartingPositionTimestamp = new(api.Date(d.StartingPositionTimestamp))
	}
	out.LastProcessingResult = new(api.String(v.LastProcessingResult))
}
