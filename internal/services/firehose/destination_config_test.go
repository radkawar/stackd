package firehose

import (
	"errors"
	"testing"

	api "stackd/internal/awsapi/firehose"
	"stackd/internal/awswire"
)

func TestDisabledDestinationModesCreateAndUpdate(t *testing.T) {
	// Terraform 6.68 emits the explicit disabled conversion block even when
	// there is no conversion configuration in HCL. This is ordinary AWS input,
	// not a provider-specific exception: Enabled=false disables native effects.
	conversion := &api.DataFormatConversionConfiguration{Enabled: new(api.BooleanObject(false)), InputFormatConfiguration: &api.InputFormatConfiguration{}, OutputFormatConfiguration: &api.OutputFormatConfiguration{}, SchemaConfiguration: &api.SchemaConfiguration{}}
	partitioning := &api.DynamicPartitioningConfiguration{Enabled: new(api.BooleanObject(false)), RetryOptions: &api.RetryOptions{DurationInSeconds: new(api.RetryDurationInSeconds(300))}}
	created, err := createDestination(&api.CreateDeliveryStreamInput{ExtendedS3DestinationConfiguration: &api.ExtendedS3DestinationConfiguration{
		BucketARN: new(api.BucketARN("arn:aws:s3:::owned")), RoleARN: new(api.RoleARN("arn:aws:iam::123456789012:role/delivery")),
		DataFormatConversionConfiguration: conversion, DynamicPartitioningConfiguration: partitioning,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if created.DataFormatConversionConfiguration == nil || bool(*created.DataFormatConversionConfiguration.Enabled) || created.DynamicPartitioningConfiguration == nil || bool(*created.DynamicPartitioningConfiguration.Enabled) {
		t.Fatalf("disabled configurations did not remain disabled: %+v", created)
	}
	update := api.ExtendedS3DestinationUpdate{Prefix: new(api.Prefix("revision-2/")), CompressionFormat: new(api.CompressionFormat("GZIP")), DataFormatConversionConfiguration: &api.DataFormatConversionConfiguration{Enabled: new(api.BooleanObject(false))}, DynamicPartitioningConfiguration: &api.DynamicPartitioningConfiguration{Enabled: new(api.BooleanObject(false))}}
	updated, err := mergeDestination(created, update)
	if err != nil {
		t.Fatal(err)
	}
	if value(updated.Prefix) != "revision-2/" || value(updated.CompressionFormat) != "GZIP" {
		t.Fatal("ordinary destination update was rejected or lost")
	}
	if updated.DataFormatConversionConfiguration.SchemaConfiguration == nil || updated.DataFormatConversionConfiguration.InputFormatConfiguration == nil || updated.DataFormatConversionConfiguration.OutputFormatConfiguration == nil {
		t.Fatal("disabling conversion removed its retained configuration details")
	}
	if updated.DynamicPartitioningConfiguration.RetryOptions == nil || *updated.DynamicPartitioningConfiguration.RetryOptions.DurationInSeconds != 300 {
		t.Fatal("disabled partitioning update removed retained retry settings")
	}
	canonical, err := mergeDestination(updated, api.ExtendedS3DestinationUpdate{DataFormatConversionConfiguration: &api.DataFormatConversionConfiguration{Enabled: new(api.BooleanObject(false))}})
	if err != nil || bool(*canonical.DataFormatConversionConfiguration.Enabled) {
		t.Fatalf("canonical provider-disabled block failed: %+v, %v", canonical, err)
	}
}

func TestEnabledDestinationModesRemainUnavailable(t *testing.T) {
	for name, update := range map[string]api.ExtendedS3DestinationUpdate{
		"conversion-enabled":           {DataFormatConversionConfiguration: &api.DataFormatConversionConfiguration{Enabled: new(api.BooleanObject(true))}},
		"conversion-default-enabled":   {DataFormatConversionConfiguration: &api.DataFormatConversionConfiguration{}},
		"dynamic-partitioning-enabled": {DynamicPartitioningConfiguration: &api.DynamicPartitioningConfiguration{Enabled: new(api.BooleanObject(true))}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := mergeDestination(defaultDestination(), update)
			var rejected *awswire.Error
			if !errors.As(err, &rejected) || rejected.Code != "NotImplementedException" {
				t.Fatalf("unavailable native mode was admitted: %v", err)
			}
		})
	}
}
