package firehose

import (
	"database/sql"
	"errors"

	api "stackd/internal/awsapi/firehose"
	"stackd/storage/sqlite/firehose/internal/sqlcgen"
)

func (r reader) configuration(id string) (api.ExtendedS3DestinationDescription, error) {
	v, err := r.q.GetConfiguration(r.ctx, id)
	if err != nil {
		return api.ExtendedS3DestinationDescription{}, missing(err)
	}
	out, err := r.configurationRow(v)
	if err != nil {
		return out, err
	}
	backupRow, err := r.q.GetBackupConfiguration(r.ctx, sql.NullString{String: id, Valid: true})
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	backup, err := r.configurationRow(backupRow)
	if err != nil {
		return out, err
	}
	out.S3BackupDescription = &api.S3DestinationDescription{
		BucketARN: backup.BucketARN, RoleARN: backup.RoleARN, Prefix: backup.Prefix,
		ErrorOutputPrefix: backup.ErrorOutputPrefix, CompressionFormat: backup.CompressionFormat,
		BufferingHints: backup.BufferingHints, CloudWatchLoggingOptions: backup.CloudWatchLoggingOptions,
		EncryptionConfiguration: backup.EncryptionConfiguration,
	}
	return out, nil
}

func (r reader) configurationRow(v sqlcgen.FirehoseConfiguration) (api.ExtendedS3DestinationDescription, error) {
	out := api.ExtendedS3DestinationDescription{
		BucketARN:         stringPointer[api.BucketARN](v.BucketArn),
		RoleARN:           stringPointer[api.RoleARN](v.RoleArn),
		Prefix:            stringPointer[api.Prefix](v.Prefix),
		ErrorOutputPrefix: stringPointer[api.ErrorOutputPrefix](v.ErrorOutputPrefix),
		CompressionFormat: stringPointer[api.CompressionFormat](v.CompressionFormat),
		CustomTimeZone:    stringPointer[api.CustomTimeZone](v.CustomTimeZone),
		FileExtension:     stringPointer[api.FileExtension](v.FileExtension),
		S3BackupMode:      stringPointer[api.S3BackupMode](v.BackupMode),
	}
	if v.BufferingPresent {
		out.BufferingHints = &api.BufferingHints{IntervalInSeconds: integerPointer[api.IntervalInSeconds](v.IntervalSeconds), SizeInMBs: integerPointer[api.SizeInMBs](v.SizeMbs)}
	}
	if v.LoggingPresent {
		out.CloudWatchLoggingOptions = &api.CloudWatchLoggingOptions{Enabled: boolPointer[api.BooleanObject](v.LoggingEnabled), LogGroupName: stringPointer[api.LogGroupName](v.LogGroup), LogStreamName: stringPointer[api.LogStreamName](v.LogStream)}
	}
	if v.EncryptionPresent {
		out.EncryptionConfiguration = &api.EncryptionConfiguration{NoEncryptionConfig: stringPointer[api.NoEncryptionConfig](v.NoEncryption)}
		if v.KmsKeyArn.Valid {
			out.EncryptionConfiguration.KMSEncryptionConfig = &api.KMSEncryptionConfig{AWSKMSKeyARN: stringPointer[api.AWSKMSKeyARN](v.KmsKeyArn)}
		}
	}
	if v.ProcessingPresent {
		processing := &api.ProcessingConfiguration{Enabled: boolPointer[api.BooleanObject](v.ProcessingEnabled)}
		if v.ProcessorsPresent {
			processing.Processors = api.ProcessorList{}
		}
		processors, err := r.q.ListProcessors(r.ctx, v.ID)
		if err != nil {
			return out, err
		}
		parameters, err := r.q.ListProcessorParameters(r.ctx, v.ID)
		if err != nil {
			return out, err
		}
		next := 0
		for _, processor := range processors {
			item := api.Processor{Type: stringPointer[api.ProcessorType](processor.Type)}
			if processor.ParametersPresent {
				item.Parameters = api.ProcessorParameterList{}
			}
			for next < len(parameters) && parameters[next].ProcessorPosition == processor.Position {
				parameter := parameters[next]
				item.Parameters = append(item.Parameters, api.ProcessorParameter{ParameterName: stringPointer[api.ProcessorParameterName](parameter.Name), ParameterValue: stringPointer[api.ProcessorParameterValue](parameter.Value)})
				next++
			}
			processing.Processors = append(processing.Processors, item)
		}
		out.ProcessingConfiguration = processing
	}
	return out, nil
}

func (w writer) putConfiguration(id, streamID string, bufferID sql.NullString, v api.ExtendedS3DestinationDescription) error {
	if err := w.putConfigurationRow(id, streamID, bufferID, sql.NullString{}, v); err != nil {
		return err
	}
	parentID := sql.NullString{String: id, Valid: true}
	if v.S3BackupDescription == nil {
		return w.q.DeleteBackupConfiguration(w.ctx, parentID)
	}
	backup := v.S3BackupDescription
	return w.putConfigurationRow("backup:"+id, streamID, bufferID, parentID, api.ExtendedS3DestinationDescription{
		BucketARN: backup.BucketARN, RoleARN: backup.RoleARN, Prefix: backup.Prefix,
		ErrorOutputPrefix: backup.ErrorOutputPrefix, CompressionFormat: backup.CompressionFormat,
		BufferingHints: backup.BufferingHints, CloudWatchLoggingOptions: backup.CloudWatchLoggingOptions,
		EncryptionConfiguration: backup.EncryptionConfiguration,
	})
}

func (w writer) putConfigurationRow(id, streamID string, bufferID, parentID sql.NullString, v api.ExtendedS3DestinationDescription) error {
	row := sqlcgen.PutConfigurationParams{
		ID: id, StreamID: streamID, BufferID: bufferID, ParentConfigurationID: parentID,
		BucketArn: nullableString(v.BucketARN), RoleArn: nullableString(v.RoleARN),
		Prefix: nullableString(v.Prefix), ErrorOutputPrefix: nullableString(v.ErrorOutputPrefix),
		CompressionFormat: nullableString(v.CompressionFormat), CustomTimeZone: nullableString(v.CustomTimeZone),
		FileExtension: nullableString(v.FileExtension), BackupMode: nullableString(v.S3BackupMode),
		BufferingPresent: v.BufferingHints != nil, LoggingPresent: v.CloudWatchLoggingOptions != nil,
		EncryptionPresent: v.EncryptionConfiguration != nil, ProcessingPresent: v.ProcessingConfiguration != nil,
	}
	if hints := v.BufferingHints; hints != nil {
		row.IntervalSeconds = nullableInteger(hints.IntervalInSeconds)
		row.SizeMbs = nullableInteger(hints.SizeInMBs)
	}
	if logging := v.CloudWatchLoggingOptions; logging != nil {
		row.LoggingEnabled = nullableBool(logging.Enabled)
		row.LogGroup = nullableString(logging.LogGroupName)
		row.LogStream = nullableString(logging.LogStreamName)
	}
	if encryption := v.EncryptionConfiguration; encryption != nil {
		row.NoEncryption = nullableString(encryption.NoEncryptionConfig)
		if encryption.KMSEncryptionConfig != nil {
			row.KmsKeyArn = nullableString(encryption.KMSEncryptionConfig.AWSKMSKeyARN)
		}
	}
	if processing := v.ProcessingConfiguration; processing != nil {
		row.ProcessingEnabled = nullableBool(processing.Enabled)
		row.ProcessorsPresent = processing.Processors != nil
	}
	if err := w.q.PutConfiguration(w.ctx, row); err != nil {
		return err
	}
	if err := w.q.DeleteProcessors(w.ctx, id); err != nil {
		return err
	}
	if processing := v.ProcessingConfiguration; processing != nil {
		for i, processor := range processing.Processors {
			if err := w.q.PutProcessor(w.ctx, sqlcgen.PutProcessorParams{ConfigurationID: id, Position: int64(i), Type: nullableString(processor.Type), ParametersPresent: processor.Parameters != nil}); err != nil {
				return err
			}
			for j, parameter := range processor.Parameters {
				if err := w.q.PutProcessorParameter(w.ctx, sqlcgen.PutProcessorParameterParams{ConfigurationID: id, ProcessorPosition: int64(i), Position: int64(j), Name: nullableString(parameter.ParameterName), Value: nullableString(parameter.ParameterValue)}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
