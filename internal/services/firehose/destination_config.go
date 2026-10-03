package firehose

import (
	api "stackd/internal/awsapi/firehose"
	"stackd/internal/awswire"
)

func createDestination(in *api.CreateDeliveryStreamInput) (api.ExtendedS3DestinationDescription, error) {
	if in.S3DestinationConfiguration != nil && in.ExtendedS3DestinationConfiguration != nil {
		return api.ExtendedS3DestinationDescription{}, failure("InvalidArgumentException", "Exactly one of S3DestinationConfiguration or ExtendedS3DestinationConfiguration must be specified.")
	}
	if in.AmazonOpenSearchServerlessDestinationConfiguration != nil || in.AmazonopensearchserviceDestinationConfiguration != nil || in.ElasticsearchDestinationConfiguration != nil || in.HttpEndpointDestinationConfiguration != nil || in.IcebergDestinationConfiguration != nil || in.RedshiftDestinationConfiguration != nil || in.SnowflakeDestinationConfiguration != nil || in.SplunkDestinationConfiguration != nil {
		// TODO: Comeback — implement non-S3 delivery before admitting these destinations.
		return api.ExtendedS3DestinationDescription{}, unsupported("non-S3 destinations")
	}
	var update api.ExtendedS3DestinationUpdate
	if v := in.S3DestinationConfiguration; v != nil {
		update = basicDestinationUpdate(api.S3DestinationUpdate{BucketARN: v.BucketARN, BufferingHints: v.BufferingHints, CloudWatchLoggingOptions: v.CloudWatchLoggingOptions, CompressionFormat: v.CompressionFormat, EncryptionConfiguration: v.EncryptionConfiguration, ErrorOutputPrefix: v.ErrorOutputPrefix, Prefix: v.Prefix, RoleARN: v.RoleARN})
	} else if v := in.ExtendedS3DestinationConfiguration; v != nil {
		update = api.ExtendedS3DestinationUpdate{BucketARN: v.BucketARN, BufferingHints: v.BufferingHints, CloudWatchLoggingOptions: v.CloudWatchLoggingOptions, CompressionFormat: v.CompressionFormat, CustomTimeZone: v.CustomTimeZone, DataFormatConversionConfiguration: v.DataFormatConversionConfiguration, DynamicPartitioningConfiguration: v.DynamicPartitioningConfiguration, EncryptionConfiguration: v.EncryptionConfiguration, ErrorOutputPrefix: v.ErrorOutputPrefix, FileExtension: v.FileExtension, Prefix: v.Prefix, ProcessingConfiguration: v.ProcessingConfiguration, RoleARN: v.RoleARN, S3BackupMode: v.S3BackupMode}
		if backup := v.S3BackupConfiguration; backup != nil {
			update.S3BackupUpdate = &api.S3DestinationUpdate{BucketARN: backup.BucketARN, BufferingHints: backup.BufferingHints, CloudWatchLoggingOptions: backup.CloudWatchLoggingOptions, CompressionFormat: backup.CompressionFormat, EncryptionConfiguration: backup.EncryptionConfiguration, ErrorOutputPrefix: backup.ErrorOutputPrefix, Prefix: backup.Prefix, RoleARN: backup.RoleARN}
		}
	} else {
		return api.ExtendedS3DestinationDescription{}, failure("InvalidArgumentException", "Exactly one destination configuration is supported for a Firehose")
	}
	return mergeDestination(defaultDestination(), update)
}

func defaultDestination() api.ExtendedS3DestinationDescription {
	return api.ExtendedS3DestinationDescription{
		BufferingHints:           &api.BufferingHints{SizeInMBs: new(api.SizeInMBs(5)), IntervalInSeconds: new(api.IntervalInSeconds(300))},
		CompressionFormat:        new(api.CompressionFormat("UNCOMPRESSED")),
		EncryptionConfiguration:  &api.EncryptionConfiguration{NoEncryptionConfig: new(api.NoEncryptionConfig("NoEncryption"))},
		CloudWatchLoggingOptions: &api.CloudWatchLoggingOptions{Enabled: new(api.BooleanObject(false))},
		S3BackupMode:             new(api.S3BackupMode("Disabled")),
	}
}

func destinationUpdate(in *api.UpdateDestinationInput) (api.ExtendedS3DestinationUpdate, error) {
	if in.S3DestinationUpdate != nil && in.ExtendedS3DestinationUpdate != nil {
		return api.ExtendedS3DestinationUpdate{}, failure("InvalidArgumentException", "Exactly one of s3DestinationUpdate or extendedS3DestinationUpdate must be specified.")
	}
	if in.AmazonOpenSearchServerlessDestinationUpdate != nil || in.AmazonopensearchserviceDestinationUpdate != nil || in.ElasticsearchDestinationUpdate != nil || in.HttpEndpointDestinationUpdate != nil || in.IcebergDestinationUpdate != nil || in.RedshiftDestinationUpdate != nil || in.SnowflakeDestinationUpdate != nil || in.SplunkDestinationUpdate != nil {
		// TODO: Comeback — implement non-S3 destination updates.
		return api.ExtendedS3DestinationUpdate{}, unsupported("non-S3 destination updates")
	}
	if in.S3DestinationUpdate != nil {
		return basicDestinationUpdate(*in.S3DestinationUpdate), nil
	}
	if in.ExtendedS3DestinationUpdate != nil {
		return *in.ExtendedS3DestinationUpdate, nil
	}
	return api.ExtendedS3DestinationUpdate{}, failure("InvalidArgumentException", "At least one destination or source configuration update must be provided")
}

func basicDestinationUpdate(v api.S3DestinationUpdate) api.ExtendedS3DestinationUpdate {
	return api.ExtendedS3DestinationUpdate{BucketARN: v.BucketARN, BufferingHints: v.BufferingHints, CloudWatchLoggingOptions: v.CloudWatchLoggingOptions, CompressionFormat: v.CompressionFormat, EncryptionConfiguration: v.EncryptionConfiguration, ErrorOutputPrefix: v.ErrorOutputPrefix, Prefix: v.Prefix, RoleARN: v.RoleARN}
}

func mergeDestination(out api.ExtendedS3DestinationDescription, v api.ExtendedS3DestinationUpdate) (api.ExtendedS3DestinationDescription, error) {
	if value(out.S3BackupMode) == "Enabled" && value(v.S3BackupMode) == "Disabled" {
		return out, failure("InvalidArgumentException", "Disabling S3 backup is not currently supported.")
	}
	if v.DataFormatConversionConfiguration != nil || v.DynamicPartitioningConfiguration != nil {
		// TODO: Comeback — implement format conversion and dynamic partitioning.
		return out, unsupported("data format conversion and dynamic partitioning")
	}
	if v.BucketARN != nil {
		out.BucketARN = v.BucketARN
	}
	if v.RoleARN != nil {
		out.RoleARN = v.RoleARN
	}
	if v.Prefix != nil {
		out.Prefix = v.Prefix
	}
	if v.ErrorOutputPrefix != nil {
		out.ErrorOutputPrefix = v.ErrorOutputPrefix
	}
	if v.CompressionFormat != nil {
		out.CompressionFormat = v.CompressionFormat
	}
	if v.CustomTimeZone != nil {
		out.CustomTimeZone = v.CustomTimeZone
	}
	if v.FileExtension != nil {
		out.FileExtension = v.FileExtension
	}
	if v.S3BackupMode != nil {
		out.S3BackupMode = v.S3BackupMode
	}
	if v.EncryptionConfiguration != nil {
		out.EncryptionConfiguration = v.EncryptionConfiguration
	}
	processing, err := normalizeProcessing(out.ProcessingConfiguration, v.ProcessingConfiguration, value(out.RoleARN))
	if err != nil {
		return out, err
	}
	out.ProcessingConfiguration = processing
	if v.BufferingHints != nil {
		hints := *out.BufferingHints
		if v.BufferingHints.IntervalInSeconds != nil {
			hints.IntervalInSeconds = v.BufferingHints.IntervalInSeconds
		}
		if v.BufferingHints.SizeInMBs != nil {
			hints.SizeInMBs = v.BufferingHints.SizeInMBs
		}
		out.BufferingHints = &hints
	}
	if v.CloudWatchLoggingOptions != nil {
		logging := *out.CloudWatchLoggingOptions
		if v.CloudWatchLoggingOptions.Enabled != nil {
			logging.Enabled = v.CloudWatchLoggingOptions.Enabled
		}
		if v.CloudWatchLoggingOptions.LogGroupName != nil {
			logging.LogGroupName = v.CloudWatchLoggingOptions.LogGroupName
		}
		if v.CloudWatchLoggingOptions.LogStreamName != nil {
			logging.LogStreamName = v.CloudWatchLoggingOptions.LogStreamName
		}
		out.CloudWatchLoggingOptions = &logging
	}
	if v.S3BackupUpdate != nil {
		backup := defaultDestination()
		if out.S3BackupDescription != nil {
			backup = extendedBackup(*out.S3BackupDescription)
		}
		backup, err := mergeDestination(backup, basicDestinationUpdate(*v.S3BackupUpdate))
		if err != nil {
			return out, err
		}
		if *backup.BufferingHints.IntervalInSeconds < 60 {
			return out, failure("InvalidArgumentException", "S3 backup buffering interval must be between 60 and 900 seconds.")
		}
		out.S3BackupDescription = basicDestination(backup)
	}
	if value(out.S3BackupMode) == "Enabled" && out.S3BackupDescription == nil {
		return out, failure("InvalidArgumentException", "An enabled S3 backup requires an S3 backup configuration.")
	}
	if err := validateDestination(out); err != nil {
		return out, err
	}
	return out, nil
}

func validateDestination(v api.ExtendedS3DestinationDescription) *awswire.Error {
	if value(v.RoleARN) == "" || value(v.BucketARN) == "" {
		return failure("InvalidArgumentException", "An S3 destination requires RoleARN and BucketARN")
	}
	encryption := v.EncryptionConfiguration
	if (encryption.KMSEncryptionConfig != nil) == (encryption.NoEncryptionConfig != nil) {
		return failure("InvalidArgumentException", "Exactly one encryption configuration must be specified")
	}
	if encryption.NoEncryptionConfig != nil && value(encryption.NoEncryptionConfig) != "NoEncryption" {
		return failure("InvalidArgumentException", "Invalid no-encryption configuration")
	}
	if v.CloudWatchLoggingOptions.Enabled != nil && bool(*v.CloudWatchLoggingOptions.Enabled) && (value(v.CloudWatchLoggingOptions.LogGroupName) == "" || value(v.CloudWatchLoggingOptions.LogStreamName) == "") {
		return failure("InvalidArgumentException", "Enabled CloudWatch logging requires LogGroupName and LogStreamName")
	}
	return validateDeliveryConfiguration(v)
}

func basicDestination(v api.ExtendedS3DestinationDescription) *api.S3DestinationDescription {
	return &api.S3DestinationDescription{BucketARN: v.BucketARN, BufferingHints: v.BufferingHints, CloudWatchLoggingOptions: v.CloudWatchLoggingOptions, CompressionFormat: v.CompressionFormat, EncryptionConfiguration: v.EncryptionConfiguration, ErrorOutputPrefix: v.ErrorOutputPrefix, Prefix: v.Prefix, RoleARN: v.RoleARN}
}

func extendedBackup(v api.S3DestinationDescription) api.ExtendedS3DestinationDescription {
	return api.ExtendedS3DestinationDescription{BucketARN: v.BucketARN, BufferingHints: v.BufferingHints, CloudWatchLoggingOptions: v.CloudWatchLoggingOptions, CompressionFormat: v.CompressionFormat, EncryptionConfiguration: v.EncryptionConfiguration, ErrorOutputPrefix: v.ErrorOutputPrefix, Prefix: v.Prefix, RoleARN: v.RoleARN}
}
