package athena

import (
	api "stackd/internal/awsapi/athena"
	domain "stackd/storage/athena"
	"stackd/storage/sqlite/athena/internal/sqlcgen"
)

func (r reader) WorkGroup(key domain.ResourceKey) (domain.WorkGroupRecord, error) {
	row, err := r.q.GetWorkGroup(r.ctx, sqlcgen.GetWorkGroupParams{KeyScopePartition: key.Scope.Partition, KeyScopeAccountID: key.Scope.AccountID, KeyScopeRegion: key.Scope.Region, KeyName: key.Name})
	if err != nil {
		return domain.WorkGroupRecord{}, missing(err)
	}
	return r.workGroup(&row)
}

func (r reader) WorkGroups(query domain.ResourceQuery) ([]domain.WorkGroupRecord, error) {
	rows, err := r.q.ListWorkGroups(r.ctx, sqlcgen.ListWorkGroupsParams{Partition: query.Scope.Partition, AccountID: query.Scope.AccountID, Region: query.Scope.Region, AfterName: query.After, RowLimit: rowLimit(query.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.WorkGroupRecord, 0, len(rows))
	for i := range rows {
		value, err := r.workGroup(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

func (w writer) DeleteWorkGroup(key domain.ResourceKey) error {
	// Executions belong to the workgroup incarnation, not a later group with the
	// same name. The service fences active engines before entering this deletion.
	if err := w.q.DeleteWorkGroupQueries(w.ctx, sqlcgen.DeleteWorkGroupQueriesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, WorkGroup: key.Name}); err != nil {
		return err
	}
	return w.q.DeleteWorkGroup(w.ctx, sqlcgen.DeleteWorkGroupParams{KeyScopePartition: key.Scope.Partition, KeyScopeAccountID: key.Scope.AccountID, KeyScopeRegion: key.Scope.Region, KeyName: key.Name})
}

func (r reader) workGroup(row *sqlcgen.AthenaWorkGroup) (domain.WorkGroupRecord, error) {
	var out domain.WorkGroupRecord
	out.Key.Scope.Partition = row.KeyScopePartition
	out.Key.Scope.AccountID = row.KeyScopeAccountID
	out.Key.Scope.Region = row.KeyScopeRegion
	out.Key.Name = row.KeyName
	if row.DataConfigurationPresent {
		out.Data.Configuration = &api.WorkGroupConfiguration{}
		out.Data.Configuration.AdditionalConfiguration = stringPointer[api.NameString](row.DataConfigurationAdditionalConfiguration)
		out.Data.Configuration.BytesScannedCutoffPerQuery = integerPointer[api.BytesScannedCutoffValue](row.DataConfigurationBytesScannedCutoffPerQuery)
		if row.DataConfigurationCustomerContentEncryptionConfigurationPresent {
			out.Data.Configuration.CustomerContentEncryptionConfiguration = &api.CustomerContentEncryptionConfiguration{}
			out.Data.Configuration.CustomerContentEncryptionConfiguration.KmsKey = stringPointer[api.KmsKey](row.DataConfigurationCustomerContentEncryptionConfigurationKmsKey)
		}
		out.Data.Configuration.EnableMinimumEncryptionConfiguration = boolPointer[api.BoxedBoolean](row.DataConfigurationEnableMinimumEncryptionConfiguration)
		out.Data.Configuration.EnforceWorkGroupConfiguration = boolPointer[api.BoxedBoolean](row.DataConfigurationEnforceWorkGroupConfiguration)
		if row.DataConfigurationEngineConfigurationPresent {
			out.Data.Configuration.EngineConfiguration = &api.EngineConfiguration{}
			if row.DataConfigurationEngineConfigurationAdditionalConfigsPresent {
				values, err := r.workGroupDataConfigurationEngineConfigurationAdditionalConfigs(row.ID)
				if err != nil {
					return out, err
				}
				out.Data.Configuration.EngineConfiguration.AdditionalConfigs = values
			}
			if row.DataConfigurationEngineConfigurationClassificationsPresent {
				values, err := r.workGroupDataConfigurationEngineConfigurationClassifications(row.ID)
				if err != nil {
					return out, err
				}
				out.Data.Configuration.EngineConfiguration.Classifications = values
			}
			out.Data.Configuration.EngineConfiguration.CoordinatorDpuSize = integerPointer[api.CoordinatorDpuSize](row.DataConfigurationEngineConfigurationCoordinatorDpuSize)
			out.Data.Configuration.EngineConfiguration.DefaultExecutorDpuSize = integerPointer[api.DefaultExecutorDpuSize](row.DataConfigurationEngineConfigurationDefaultExecutorDpuSize)
			out.Data.Configuration.EngineConfiguration.MaxConcurrentDpus = integerPointer[api.MaxConcurrentDpus](row.DataConfigurationEngineConfigurationMaxConcurrentDpus)
			if row.DataConfigurationEngineConfigurationSparkPropertiesPresent {
				values, err := r.workGroupDataConfigurationEngineConfigurationSparkProperties(row.ID)
				if err != nil {
					return out, err
				}
				out.Data.Configuration.EngineConfiguration.SparkProperties = values
			}
		}
		if row.DataConfigurationEngineVersionPresent {
			out.Data.Configuration.EngineVersion = &api.EngineVersion{}
			out.Data.Configuration.EngineVersion.EffectiveEngineVersion = stringPointer[api.NameString](row.DataConfigurationEngineVersionEffectiveEngineVersion)
			out.Data.Configuration.EngineVersion.SelectedEngineVersion = stringPointer[api.NameString](row.DataConfigurationEngineVersionSelectedEngineVersion)
		}
		out.Data.Configuration.ExecutionRole = stringPointer[api.RoleArn](row.DataConfigurationExecutionRole)
		if row.DataConfigurationIdentityCenterConfigurationPresent {
			out.Data.Configuration.IdentityCenterConfiguration = &api.IdentityCenterConfiguration{}
			out.Data.Configuration.IdentityCenterConfiguration.EnableIdentityCenter = boolPointer[api.BoxedBoolean](row.DataConfigurationIdentityCenterConfigurationEnableIdentityCenter)
			out.Data.Configuration.IdentityCenterConfiguration.IdentityCenterInstanceArn = stringPointer[api.IdentityCenterInstanceArn](row.DataConfigurationIdentityCenterConfigurationIdentityCenterInstanceArn)
		}
		if row.DataConfigurationManagedQueryResultsConfigurationPresent {
			out.Data.Configuration.ManagedQueryResultsConfiguration = &api.ManagedQueryResultsConfiguration{}
			out.Data.Configuration.ManagedQueryResultsConfiguration.Enabled = boolPointer[api.Boolean](row.DataConfigurationManagedQueryResultsConfigurationEnabled)
			if row.DataConfigurationManagedQueryResultsConfigurationEncryptionConfigurationPresent {
				out.Data.Configuration.ManagedQueryResultsConfiguration.EncryptionConfiguration = &api.ManagedQueryResultsEncryptionConfiguration{}
				out.Data.Configuration.ManagedQueryResultsConfiguration.EncryptionConfiguration.KmsKey = stringPointer[api.KmsKey](row.DataConfigurationManagedQueryResultsConfigurationEncryptionConfigurationKmsKey)
			}
		}
		if row.DataConfigurationMonitoringConfigurationPresent {
			out.Data.Configuration.MonitoringConfiguration = &api.MonitoringConfiguration{}
			if row.DataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationPresent {
				out.Data.Configuration.MonitoringConfiguration.CloudWatchLoggingConfiguration = &api.CloudWatchLoggingConfiguration{}
				out.Data.Configuration.MonitoringConfiguration.CloudWatchLoggingConfiguration.Enabled = boolPointer[api.BoxedBoolean](row.DataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationEnabled)
				out.Data.Configuration.MonitoringConfiguration.CloudWatchLoggingConfiguration.LogGroup = stringPointer[api.LogGroupName](row.DataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogGroup)
				out.Data.Configuration.MonitoringConfiguration.CloudWatchLoggingConfiguration.LogStreamNamePrefix = stringPointer[api.LogStreamNamePrefix](row.DataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogStreamNamePrefix)
				if row.DataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesPresent {
					values, err := r.workGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypes(row.ID)
					if err != nil {
						return out, err
					}
					out.Data.Configuration.MonitoringConfiguration.CloudWatchLoggingConfiguration.LogTypes = values
				}
			}
			if row.DataConfigurationMonitoringConfigurationManagedLoggingConfigurationPresent {
				out.Data.Configuration.MonitoringConfiguration.ManagedLoggingConfiguration = &api.ManagedLoggingConfiguration{}
				out.Data.Configuration.MonitoringConfiguration.ManagedLoggingConfiguration.Enabled = boolPointer[api.BoxedBoolean](row.DataConfigurationMonitoringConfigurationManagedLoggingConfigurationEnabled)
				out.Data.Configuration.MonitoringConfiguration.ManagedLoggingConfiguration.KmsKey = stringPointer[api.KmsKey](row.DataConfigurationMonitoringConfigurationManagedLoggingConfigurationKmsKey)
			}
			if row.DataConfigurationMonitoringConfigurationS3LoggingConfigurationPresent {
				out.Data.Configuration.MonitoringConfiguration.S3LoggingConfiguration = &api.S3LoggingConfiguration{}
				out.Data.Configuration.MonitoringConfiguration.S3LoggingConfiguration.Enabled = boolPointer[api.BoxedBoolean](row.DataConfigurationMonitoringConfigurationS3LoggingConfigurationEnabled)
				out.Data.Configuration.MonitoringConfiguration.S3LoggingConfiguration.KmsKey = stringPointer[api.KmsKey](row.DataConfigurationMonitoringConfigurationS3LoggingConfigurationKmsKey)
				out.Data.Configuration.MonitoringConfiguration.S3LoggingConfiguration.LogLocation = stringPointer[api.S3OutputLocation](row.DataConfigurationMonitoringConfigurationS3LoggingConfigurationLogLocation)
			}
		}
		out.Data.Configuration.PublishCloudWatchMetricsEnabled = boolPointer[api.BoxedBoolean](row.DataConfigurationPublishCloudWatchMetricsEnabled)
		if row.DataConfigurationQueryResultsS3AccessGrantsConfigurationPresent {
			out.Data.Configuration.QueryResultsS3AccessGrantsConfiguration = &api.QueryResultsS3AccessGrantsConfiguration{}
			out.Data.Configuration.QueryResultsS3AccessGrantsConfiguration.AuthenticationType = stringPointer[api.AuthenticationType](row.DataConfigurationQueryResultsS3AccessGrantsConfigurationAuthenticationType)
			out.Data.Configuration.QueryResultsS3AccessGrantsConfiguration.CreateUserLevelPrefix = boolPointer[api.BoxedBoolean](row.DataConfigurationQueryResultsS3AccessGrantsConfigurationCreateUserLevelPrefix)
			out.Data.Configuration.QueryResultsS3AccessGrantsConfiguration.EnableS3AccessGrants = boolPointer[api.BoxedBoolean](row.DataConfigurationQueryResultsS3AccessGrantsConfigurationEnableS3AccessGrants)
		}
		out.Data.Configuration.RequesterPaysEnabled = boolPointer[api.BoxedBoolean](row.DataConfigurationRequesterPaysEnabled)
		if row.DataConfigurationResultConfigurationPresent {
			out.Data.Configuration.ResultConfiguration = &api.ResultConfiguration{}
			if row.DataConfigurationResultConfigurationAclConfigurationPresent {
				out.Data.Configuration.ResultConfiguration.AclConfiguration = &api.AclConfiguration{}
				out.Data.Configuration.ResultConfiguration.AclConfiguration.S3AclOption = stringPointer[api.S3AclOption](row.DataConfigurationResultConfigurationAclConfigurationS3AclOption)
			}
			if row.DataConfigurationResultConfigurationEncryptionConfigurationPresent {
				out.Data.Configuration.ResultConfiguration.EncryptionConfiguration = &api.EncryptionConfiguration{}
				out.Data.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption = stringPointer[api.EncryptionOption](row.DataConfigurationResultConfigurationEncryptionConfigurationEncryptionOption)
				out.Data.Configuration.ResultConfiguration.EncryptionConfiguration.KmsKey = stringPointer[api.String](row.DataConfigurationResultConfigurationEncryptionConfigurationKmsKey)
			}
			out.Data.Configuration.ResultConfiguration.ExpectedBucketOwner = stringPointer[api.AwsAccountId](row.DataConfigurationResultConfigurationExpectedBucketOwner)
			out.Data.Configuration.ResultConfiguration.OutputLocation = stringPointer[api.ResultOutputLocation](row.DataConfigurationResultConfigurationOutputLocation)
		}
	}
	out.Data.CreationTime = timePointer(row.DataCreationTime)
	out.Data.Description = stringPointer[api.WorkGroupDescriptionString](row.DataDescription)
	out.Data.IdentityCenterApplicationArn = stringPointer[api.IdentityCenterApplicationArn](row.DataIdentityCenterApplicationArn)
	out.Data.Name = stringPointer[api.WorkGroupName](row.DataName)
	out.Data.State = stringPointer[api.WorkGroupState](row.DataState)
	if row.TagsPresent {
		values, err := r.workGroupTags(row.ID)
		if err != nil {
			return out, err
		}
		out.Tags = values
	}
	return out, nil
}

func (w writer) PutWorkGroup(v domain.WorkGroupRecord) error {
	var p sqlcgen.PutWorkGroupParams
	p.KeyScopePartition = v.Key.Scope.Partition
	p.KeyScopeAccountID = v.Key.Scope.AccountID
	p.KeyScopeRegion = v.Key.Scope.Region
	p.KeyName = v.Key.Name
	if v.Data.Configuration != nil {
		p.DataConfigurationPresent = true
		p.DataConfigurationAdditionalConfiguration = nullableString(v.Data.Configuration.AdditionalConfiguration)
		p.DataConfigurationBytesScannedCutoffPerQuery = nullableInteger(v.Data.Configuration.BytesScannedCutoffPerQuery)
		if v.Data.Configuration.CustomerContentEncryptionConfiguration != nil {
			p.DataConfigurationCustomerContentEncryptionConfigurationPresent = true
			p.DataConfigurationCustomerContentEncryptionConfigurationKmsKey = nullableString(v.Data.Configuration.CustomerContentEncryptionConfiguration.KmsKey)
		}
		p.DataConfigurationEnableMinimumEncryptionConfiguration = nullableBool(v.Data.Configuration.EnableMinimumEncryptionConfiguration)
		p.DataConfigurationEnforceWorkGroupConfiguration = nullableBool(v.Data.Configuration.EnforceWorkGroupConfiguration)
		if v.Data.Configuration.EngineConfiguration != nil {
			p.DataConfigurationEngineConfigurationPresent = true
			p.DataConfigurationEngineConfigurationAdditionalConfigsPresent = v.Data.Configuration.EngineConfiguration.AdditionalConfigs != nil
			p.DataConfigurationEngineConfigurationClassificationsPresent = v.Data.Configuration.EngineConfiguration.Classifications != nil
			p.DataConfigurationEngineConfigurationCoordinatorDpuSize = nullableInteger(v.Data.Configuration.EngineConfiguration.CoordinatorDpuSize)
			p.DataConfigurationEngineConfigurationDefaultExecutorDpuSize = nullableInteger(v.Data.Configuration.EngineConfiguration.DefaultExecutorDpuSize)
			p.DataConfigurationEngineConfigurationMaxConcurrentDpus = nullableInteger(v.Data.Configuration.EngineConfiguration.MaxConcurrentDpus)
			p.DataConfigurationEngineConfigurationSparkPropertiesPresent = v.Data.Configuration.EngineConfiguration.SparkProperties != nil
		}
		if v.Data.Configuration.EngineVersion != nil {
			p.DataConfigurationEngineVersionPresent = true
			p.DataConfigurationEngineVersionEffectiveEngineVersion = nullableString(v.Data.Configuration.EngineVersion.EffectiveEngineVersion)
			p.DataConfigurationEngineVersionSelectedEngineVersion = nullableString(v.Data.Configuration.EngineVersion.SelectedEngineVersion)
		}
		p.DataConfigurationExecutionRole = nullableString(v.Data.Configuration.ExecutionRole)
		if v.Data.Configuration.IdentityCenterConfiguration != nil {
			p.DataConfigurationIdentityCenterConfigurationPresent = true
			p.DataConfigurationIdentityCenterConfigurationEnableIdentityCenter = nullableBool(v.Data.Configuration.IdentityCenterConfiguration.EnableIdentityCenter)
			p.DataConfigurationIdentityCenterConfigurationIdentityCenterInstanceArn = nullableString(v.Data.Configuration.IdentityCenterConfiguration.IdentityCenterInstanceArn)
		}
		if v.Data.Configuration.ManagedQueryResultsConfiguration != nil {
			p.DataConfigurationManagedQueryResultsConfigurationPresent = true
			p.DataConfigurationManagedQueryResultsConfigurationEnabled = nullableBool(v.Data.Configuration.ManagedQueryResultsConfiguration.Enabled)
			if v.Data.Configuration.ManagedQueryResultsConfiguration.EncryptionConfiguration != nil {
				p.DataConfigurationManagedQueryResultsConfigurationEncryptionConfigurationPresent = true
				p.DataConfigurationManagedQueryResultsConfigurationEncryptionConfigurationKmsKey = nullableString(v.Data.Configuration.ManagedQueryResultsConfiguration.EncryptionConfiguration.KmsKey)
			}
		}
		if v.Data.Configuration.MonitoringConfiguration != nil {
			p.DataConfigurationMonitoringConfigurationPresent = true
			if v.Data.Configuration.MonitoringConfiguration.CloudWatchLoggingConfiguration != nil {
				p.DataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationPresent = true
				p.DataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationEnabled = nullableBool(v.Data.Configuration.MonitoringConfiguration.CloudWatchLoggingConfiguration.Enabled)
				p.DataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogGroup = nullableString(v.Data.Configuration.MonitoringConfiguration.CloudWatchLoggingConfiguration.LogGroup)
				p.DataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogStreamNamePrefix = nullableString(v.Data.Configuration.MonitoringConfiguration.CloudWatchLoggingConfiguration.LogStreamNamePrefix)
				p.DataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesPresent = v.Data.Configuration.MonitoringConfiguration.CloudWatchLoggingConfiguration.LogTypes != nil
			}
			if v.Data.Configuration.MonitoringConfiguration.ManagedLoggingConfiguration != nil {
				p.DataConfigurationMonitoringConfigurationManagedLoggingConfigurationPresent = true
				p.DataConfigurationMonitoringConfigurationManagedLoggingConfigurationEnabled = nullableBool(v.Data.Configuration.MonitoringConfiguration.ManagedLoggingConfiguration.Enabled)
				p.DataConfigurationMonitoringConfigurationManagedLoggingConfigurationKmsKey = nullableString(v.Data.Configuration.MonitoringConfiguration.ManagedLoggingConfiguration.KmsKey)
			}
			if v.Data.Configuration.MonitoringConfiguration.S3LoggingConfiguration != nil {
				p.DataConfigurationMonitoringConfigurationS3LoggingConfigurationPresent = true
				p.DataConfigurationMonitoringConfigurationS3LoggingConfigurationEnabled = nullableBool(v.Data.Configuration.MonitoringConfiguration.S3LoggingConfiguration.Enabled)
				p.DataConfigurationMonitoringConfigurationS3LoggingConfigurationKmsKey = nullableString(v.Data.Configuration.MonitoringConfiguration.S3LoggingConfiguration.KmsKey)
				p.DataConfigurationMonitoringConfigurationS3LoggingConfigurationLogLocation = nullableString(v.Data.Configuration.MonitoringConfiguration.S3LoggingConfiguration.LogLocation)
			}
		}
		p.DataConfigurationPublishCloudWatchMetricsEnabled = nullableBool(v.Data.Configuration.PublishCloudWatchMetricsEnabled)
		if v.Data.Configuration.QueryResultsS3AccessGrantsConfiguration != nil {
			p.DataConfigurationQueryResultsS3AccessGrantsConfigurationPresent = true
			p.DataConfigurationQueryResultsS3AccessGrantsConfigurationAuthenticationType = nullableString(v.Data.Configuration.QueryResultsS3AccessGrantsConfiguration.AuthenticationType)
			p.DataConfigurationQueryResultsS3AccessGrantsConfigurationCreateUserLevelPrefix = nullableBool(v.Data.Configuration.QueryResultsS3AccessGrantsConfiguration.CreateUserLevelPrefix)
			p.DataConfigurationQueryResultsS3AccessGrantsConfigurationEnableS3AccessGrants = nullableBool(v.Data.Configuration.QueryResultsS3AccessGrantsConfiguration.EnableS3AccessGrants)
		}
		p.DataConfigurationRequesterPaysEnabled = nullableBool(v.Data.Configuration.RequesterPaysEnabled)
		if v.Data.Configuration.ResultConfiguration != nil {
			p.DataConfigurationResultConfigurationPresent = true
			if v.Data.Configuration.ResultConfiguration.AclConfiguration != nil {
				p.DataConfigurationResultConfigurationAclConfigurationPresent = true
				p.DataConfigurationResultConfigurationAclConfigurationS3AclOption = nullableString(v.Data.Configuration.ResultConfiguration.AclConfiguration.S3AclOption)
			}
			if v.Data.Configuration.ResultConfiguration.EncryptionConfiguration != nil {
				p.DataConfigurationResultConfigurationEncryptionConfigurationPresent = true
				p.DataConfigurationResultConfigurationEncryptionConfigurationEncryptionOption = nullableString(v.Data.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption)
				p.DataConfigurationResultConfigurationEncryptionConfigurationKmsKey = nullableString(v.Data.Configuration.ResultConfiguration.EncryptionConfiguration.KmsKey)
			}
			p.DataConfigurationResultConfigurationExpectedBucketOwner = nullableString(v.Data.Configuration.ResultConfiguration.ExpectedBucketOwner)
			p.DataConfigurationResultConfigurationOutputLocation = nullableString(v.Data.Configuration.ResultConfiguration.OutputLocation)
		}
	}
	p.DataCreationTime = nullableTime(v.Data.CreationTime)
	p.DataDescription = nullableString(v.Data.Description)
	p.DataIdentityCenterApplicationArn = nullableString(v.Data.IdentityCenterApplicationArn)
	p.DataName = nullableString(v.Data.Name)
	p.DataState = nullableString(v.Data.State)
	p.TagsPresent = v.Tags != nil
	id, err := w.q.PutWorkGroup(w.ctx, p)
	if err != nil {
		return err
	}
	if err := w.q.DeleteWorkGroupDataConfigurationEngineConfigurationAdditionalConfigs(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteWorkGroupDataConfigurationEngineConfigurationClassifications(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteWorkGroupDataConfigurationEngineConfigurationSparkProperties(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypes(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteWorkGroupTags(w.ctx, id); err != nil {
		return err
	}
	if v.Data.Configuration != nil {
		if v.Data.Configuration.EngineConfiguration != nil {
			if err := w.putWorkGroupDataConfigurationEngineConfigurationAdditionalConfigs(id, v.Data.Configuration.EngineConfiguration.AdditionalConfigs); err != nil {
				return err
			}
			if err := w.putWorkGroupDataConfigurationEngineConfigurationClassifications(id, v.Data.Configuration.EngineConfiguration.Classifications); err != nil {
				return err
			}
			if err := w.putWorkGroupDataConfigurationEngineConfigurationSparkProperties(id, v.Data.Configuration.EngineConfiguration.SparkProperties); err != nil {
				return err
			}
		}
		if v.Data.Configuration.MonitoringConfiguration != nil {
			if v.Data.Configuration.MonitoringConfiguration.CloudWatchLoggingConfiguration != nil {
				if err := w.putWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypes(id, v.Data.Configuration.MonitoringConfiguration.CloudWatchLoggingConfiguration.LogTypes); err != nil {
					return err
				}
			}
		}
	}
	if err := w.putWorkGroupTags(id, v.Tags); err != nil {
		return err
	}
	return nil
}

func (r reader) workGroupDataConfigurationEngineConfigurationAdditionalConfigs(parentID int64) (api.ParametersMap, error) {
	rows, err := r.q.ListWorkGroupDataConfigurationEngineConfigurationAdditionalConfigs(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.ParametersMap, len(rows))
	for i := range rows {
		row := &rows[i]
		value := api.ParametersMapValue(row.Value)
		out[api.KeyString(row.MapKey)] = value
	}
	return out, nil
}

func (w writer) putWorkGroupDataConfigurationEngineConfigurationAdditionalConfigs(parentID int64, values api.ParametersMap) error {
	for key, value := range values {
		p := sqlcgen.PutWorkGroupDataConfigurationEngineConfigurationAdditionalConfigsParams{ParentID: parentID}
		p.MapKey = string(key)
		p.Value = string(value)
		if err := w.q.PutWorkGroupDataConfigurationEngineConfigurationAdditionalConfigs(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) workGroupDataConfigurationEngineConfigurationClassifications(parentID int64) (api.ClassificationList, error) {
	rows, err := r.q.ListWorkGroupDataConfigurationEngineConfigurationClassifications(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.ClassificationList, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		var value api.Classification
		value.Name = stringPointer[api.NameString](row.ValueName)
		if row.ValuePropertiesPresent {
			values, err := r.workGroupDataConfigurationEngineConfigurationClassificationsValueProperties(row.ID)
			if err != nil {
				return out, err
			}
			value.Properties = values
		}
		out = append(out, value)
	}
	return out, nil
}

func (w writer) putWorkGroupDataConfigurationEngineConfigurationClassifications(parentID int64, values api.ClassificationList) error {
	for i := range values {
		value := &values[i]
		p := sqlcgen.PutWorkGroupDataConfigurationEngineConfigurationClassificationsParams{ParentID: parentID, Position: int64(i)}
		p.ValueName = nullableString(value.Name)
		p.ValuePropertiesPresent = value.Properties != nil
		id, err := w.q.PutWorkGroupDataConfigurationEngineConfigurationClassifications(w.ctx, p)
		if err != nil {
			return err
		}
		if err := w.putWorkGroupDataConfigurationEngineConfigurationClassificationsValueProperties(id, value.Properties); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) workGroupDataConfigurationEngineConfigurationClassificationsValueProperties(parentID int64) (api.ParametersMap, error) {
	rows, err := r.q.ListWorkGroupDataConfigurationEngineConfigurationClassificationsValueProperties(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.ParametersMap, len(rows))
	for i := range rows {
		row := &rows[i]
		value := api.ParametersMapValue(row.Value)
		out[api.KeyString(row.MapKey)] = value
	}
	return out, nil
}

func (w writer) putWorkGroupDataConfigurationEngineConfigurationClassificationsValueProperties(parentID int64, values api.ParametersMap) error {
	for key, value := range values {
		p := sqlcgen.PutWorkGroupDataConfigurationEngineConfigurationClassificationsValuePropertiesParams{ParentID: parentID}
		p.MapKey = string(key)
		p.Value = string(value)
		if err := w.q.PutWorkGroupDataConfigurationEngineConfigurationClassificationsValueProperties(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) workGroupDataConfigurationEngineConfigurationSparkProperties(parentID int64) (api.ParametersMap, error) {
	rows, err := r.q.ListWorkGroupDataConfigurationEngineConfigurationSparkProperties(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.ParametersMap, len(rows))
	for i := range rows {
		row := &rows[i]
		value := api.ParametersMapValue(row.Value)
		out[api.KeyString(row.MapKey)] = value
	}
	return out, nil
}

func (w writer) putWorkGroupDataConfigurationEngineConfigurationSparkProperties(parentID int64, values api.ParametersMap) error {
	for key, value := range values {
		p := sqlcgen.PutWorkGroupDataConfigurationEngineConfigurationSparkPropertiesParams{ParentID: parentID}
		p.MapKey = string(key)
		p.Value = string(value)
		if err := w.q.PutWorkGroupDataConfigurationEngineConfigurationSparkProperties(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) workGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypes(parentID int64) (api.LogTypesMap, error) {
	rows, err := r.q.ListWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypes(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.LogTypesMap, len(rows))
	for i := range rows {
		row := &rows[i]
		var value api.LogTypeValuesList
		if row.ValuePresent {
			values, err := r.workGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesValue(row.ID)
			if err != nil {
				return out, err
			}
			value = values
		}
		out[api.LogTypeKey(row.MapKey)] = value
	}
	return out, nil
}

func (w writer) putWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypes(parentID int64, values api.LogTypesMap) error {
	for key, value := range values {
		p := sqlcgen.PutWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesParams{ParentID: parentID}
		p.MapKey = string(key)
		p.ValuePresent = value != nil
		id, err := w.q.PutWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypes(w.ctx, p)
		if err != nil {
			return err
		}
		if err := w.putWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesValue(id, value); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) workGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesValue(parentID int64) (api.LogTypeValuesList, error) {
	rows, err := r.q.ListWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesValue(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.LogTypeValuesList, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		value := api.LogTypeValue(row.Value)
		out = append(out, value)
	}
	return out, nil
}

func (w writer) putWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesValue(parentID int64, values api.LogTypeValuesList) error {
	for i := range values {
		value := values[i]
		p := sqlcgen.PutWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesValueParams{ParentID: parentID, Position: int64(i)}
		p.Value = string(value)
		if err := w.q.PutWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesValue(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) workGroupTags(parentID int64) (map[string]string, error) {
	rows, err := r.q.ListWorkGroupTags(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for i := range rows {
		row := &rows[i]
		value := row.Value
		out[row.MapKey] = value
	}
	return out, nil
}

func (w writer) putWorkGroupTags(parentID int64, values map[string]string) error {
	for key, value := range values {
		p := sqlcgen.PutWorkGroupTagsParams{ParentID: parentID}
		p.MapKey = key
		p.Value = value
		if err := w.q.PutWorkGroupTags(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}
