package athena

import (
	api "stackd/internal/awsapi/athena"
	domain "stackd/storage/athena"
	"stackd/storage/sqlite/athena/internal/sqlcgen"
)

func (r reader) Query(key domain.ResourceKey) (domain.QueryRecord, error) {
	row, err := r.q.GetQuery(r.ctx, sqlcgen.GetQueryParams{KeyScopePartition: key.Scope.Partition, KeyScopeAccountID: key.Scope.AccountID, KeyScopeRegion: key.Scope.Region, KeyName: key.Name})
	if err != nil {
		return domain.QueryRecord{}, missing(err)
	}
	return r.query(&row)
}

func (r reader) Queries(query domain.ResourceQuery) ([]domain.QueryRecord, error) {
	rows, err := r.q.ListQuerys(r.ctx, sqlcgen.ListQuerysParams{Partition: query.Scope.Partition, AccountID: query.Scope.AccountID, Region: query.Scope.Region, AfterName: query.After, RowLimit: rowLimit(query.Limit), WorkGroup: query.WorkGroup})
	if err != nil {
		return nil, err
	}
	out := make([]domain.QueryRecord, 0, len(rows))
	for i := range rows {
		value, err := r.query(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

func (r reader) QueryByToken(scope domain.Scope, token string) (domain.QueryRecord, error) {
	row, err := r.q.GetQueryByToken(r.ctx, sqlcgen.GetQueryByTokenParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Token: token})
	if err != nil {
		return domain.QueryRecord{}, missing(err)
	}
	return r.query(&row)
}

func (r reader) NextQuery() (domain.QueryRecord, error) {
	row, err := r.q.NextQuery(r.ctx)
	if err != nil {
		return domain.QueryRecord{}, missing(err)
	}
	return r.query(&row)
}

func (r reader) ActiveQueries() ([]domain.QueryRecord, error) {
	rows, err := r.q.ActiveQueries(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.QueryRecord, 0, len(rows))
	for i := range rows {
		value, err := r.query(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

func (r reader) query(row *sqlcgen.AthenaQuery) (domain.QueryRecord, error) {
	var out domain.QueryRecord
	out.Key.Scope.Partition = row.KeyScopePartition
	out.Key.Scope.AccountID = row.KeyScopeAccountID
	out.Key.Scope.Region = row.KeyScopeRegion
	out.Key.Name = row.KeyName
	if row.DataEngineVersionPresent {
		out.Data.EngineVersion = &api.EngineVersion{}
		out.Data.EngineVersion.EffectiveEngineVersion = stringPointer[api.NameString](row.DataEngineVersionEffectiveEngineVersion)
		out.Data.EngineVersion.SelectedEngineVersion = stringPointer[api.NameString](row.DataEngineVersionSelectedEngineVersion)
	}
	if row.DataExecutionParametersPresent {
		values, err := r.queryDataExecutionParameters(row.ID)
		if err != nil {
			return out, err
		}
		out.Data.ExecutionParameters = values
	}
	if row.DataManagedQueryResultsConfigurationPresent {
		out.Data.ManagedQueryResultsConfiguration = &api.ManagedQueryResultsConfiguration{}
		out.Data.ManagedQueryResultsConfiguration.Enabled = boolPointer[api.Boolean](row.DataManagedQueryResultsConfigurationEnabled)
		if row.DataManagedQueryResultsConfigurationEncryptionConfigurationPresent {
			out.Data.ManagedQueryResultsConfiguration.EncryptionConfiguration = &api.ManagedQueryResultsEncryptionConfiguration{}
			out.Data.ManagedQueryResultsConfiguration.EncryptionConfiguration.KmsKey = stringPointer[api.KmsKey](row.DataManagedQueryResultsConfigurationEncryptionConfigurationKmsKey)
		}
	}
	out.Data.Query = stringPointer[api.QueryString](row.DataQuery)
	if row.DataQueryExecutionContextPresent {
		out.Data.QueryExecutionContext = &api.QueryExecutionContext{}
		out.Data.QueryExecutionContext.Catalog = stringPointer[api.CatalogNameString](row.DataQueryExecutionContextCatalog)
		out.Data.QueryExecutionContext.Database = stringPointer[api.DatabaseString](row.DataQueryExecutionContextDatabase)
	}
	out.Data.QueryExecutionId = stringPointer[api.QueryExecutionId](row.DataQueryExecutionID)
	if row.DataQueryResultsS3AccessGrantsConfigurationPresent {
		out.Data.QueryResultsS3AccessGrantsConfiguration = &api.QueryResultsS3AccessGrantsConfiguration{}
		out.Data.QueryResultsS3AccessGrantsConfiguration.AuthenticationType = stringPointer[api.AuthenticationType](row.DataQueryResultsS3AccessGrantsConfigurationAuthenticationType)
		out.Data.QueryResultsS3AccessGrantsConfiguration.CreateUserLevelPrefix = boolPointer[api.BoxedBoolean](row.DataQueryResultsS3AccessGrantsConfigurationCreateUserLevelPrefix)
		out.Data.QueryResultsS3AccessGrantsConfiguration.EnableS3AccessGrants = boolPointer[api.BoxedBoolean](row.DataQueryResultsS3AccessGrantsConfigurationEnableS3AccessGrants)
	}
	if row.DataResultConfigurationPresent {
		out.Data.ResultConfiguration = &api.ResultConfiguration{}
		if row.DataResultConfigurationAclConfigurationPresent {
			out.Data.ResultConfiguration.AclConfiguration = &api.AclConfiguration{}
			out.Data.ResultConfiguration.AclConfiguration.S3AclOption = stringPointer[api.S3AclOption](row.DataResultConfigurationAclConfigurationS3AclOption)
		}
		if row.DataResultConfigurationEncryptionConfigurationPresent {
			out.Data.ResultConfiguration.EncryptionConfiguration = &api.EncryptionConfiguration{}
			out.Data.ResultConfiguration.EncryptionConfiguration.EncryptionOption = stringPointer[api.EncryptionOption](row.DataResultConfigurationEncryptionConfigurationEncryptionOption)
			out.Data.ResultConfiguration.EncryptionConfiguration.KmsKey = stringPointer[api.String](row.DataResultConfigurationEncryptionConfigurationKmsKey)
		}
		out.Data.ResultConfiguration.ExpectedBucketOwner = stringPointer[api.AwsAccountId](row.DataResultConfigurationExpectedBucketOwner)
		out.Data.ResultConfiguration.OutputLocation = stringPointer[api.ResultOutputLocation](row.DataResultConfigurationOutputLocation)
	}
	if row.DataResultReuseConfigurationPresent {
		out.Data.ResultReuseConfiguration = &api.ResultReuseConfiguration{}
		if row.DataResultReuseConfigurationResultReuseByAgeConfigurationPresent {
			out.Data.ResultReuseConfiguration.ResultReuseByAgeConfiguration = &api.ResultReuseByAgeConfiguration{}
			out.Data.ResultReuseConfiguration.ResultReuseByAgeConfiguration.Enabled = boolPointer[api.Boolean](row.DataResultReuseConfigurationResultReuseByAgeConfigurationEnabled)
			out.Data.ResultReuseConfiguration.ResultReuseByAgeConfiguration.MaxAgeInMinutes = integerPointer[api.Age](row.DataResultReuseConfigurationResultReuseByAgeConfigurationMaxAgeInMinutes)
		}
	}
	out.Data.StatementType = stringPointer[api.StatementType](row.DataStatementType)
	if row.DataStatisticsPresent {
		out.Data.Statistics = &api.QueryExecutionStatistics{}
		out.Data.Statistics.DataManifestLocation = stringPointer[api.String](row.DataStatisticsDataManifestLocation)
		out.Data.Statistics.DataScannedInBytes = integerPointer[api.Long](row.DataStatisticsDataScannedInBytes)
		out.Data.Statistics.DpuCount = floatPointer[api.DpuCount](row.DataStatisticsDpuCount)
		out.Data.Statistics.EngineExecutionTimeInMillis = integerPointer[api.Long](row.DataStatisticsEngineExecutionTimeInMillis)
		out.Data.Statistics.QueryPlanningTimeInMillis = integerPointer[api.Long](row.DataStatisticsQueryPlanningTimeInMillis)
		out.Data.Statistics.QueryQueueTimeInMillis = integerPointer[api.Long](row.DataStatisticsQueryQueueTimeInMillis)
		if row.DataStatisticsResultReuseInformationPresent {
			out.Data.Statistics.ResultReuseInformation = &api.ResultReuseInformation{}
			out.Data.Statistics.ResultReuseInformation.ReusedPreviousResult = boolPointer[api.Boolean](row.DataStatisticsResultReuseInformationReusedPreviousResult)
		}
		out.Data.Statistics.ServicePreProcessingTimeInMillis = integerPointer[api.Long](row.DataStatisticsServicePreProcessingTimeInMillis)
		out.Data.Statistics.ServiceProcessingTimeInMillis = integerPointer[api.Long](row.DataStatisticsServiceProcessingTimeInMillis)
		out.Data.Statistics.TotalExecutionTimeInMillis = integerPointer[api.Long](row.DataStatisticsTotalExecutionTimeInMillis)
	}
	if row.DataStatusPresent {
		out.Data.Status = &api.QueryExecutionStatus{}
		if row.DataStatusAthenaErrorPresent {
			out.Data.Status.AthenaError = &api.AthenaError{}
			out.Data.Status.AthenaError.ErrorCategory = integerPointer[api.ErrorCategory](row.DataStatusAthenaErrorErrorCategory)
			out.Data.Status.AthenaError.ErrorMessage = stringPointer[api.String](row.DataStatusAthenaErrorErrorMessage)
			out.Data.Status.AthenaError.ErrorType = integerPointer[api.ErrorType](row.DataStatusAthenaErrorErrorType)
			out.Data.Status.AthenaError.Retryable = boolPointer[api.Boolean](row.DataStatusAthenaErrorRetryable)
		}
		out.Data.Status.CompletionDateTime = timePointer(row.DataStatusCompletionDateTime)
		out.Data.Status.State = stringPointer[api.QueryExecutionState](row.DataStatusState)
		out.Data.Status.StateChangeReason = stringPointer[api.String](row.DataStatusStateChangeReason)
		out.Data.Status.SubmissionDateTime = timePointer(row.DataStatusSubmissionDateTime)
	}
	out.Data.SubstatementType = stringPointer[api.String](row.DataSubstatementType)
	out.Data.WorkGroup = stringPointer[api.WorkGroupName](row.DataWorkGroup)
	out.Token = row.Token
	out.Fingerprint = row.Fingerprint
	out.Caller.AccountID = row.CallerAccountID
	out.Caller.Region = row.CallerRegion
	out.Caller.Partition = row.CallerPartition
	out.Caller.AccessKeyID = row.CallerAccessKeyID
	out.Caller.RequestID = row.CallerRequestID
	out.Caller.ParentEventID = row.CallerParentEventID
	out.Caller.TraceHeader = row.CallerTraceHeader
	out.Caller.PrincipalARN = row.CallerPrincipalArn
	out.Caller.PrincipalID = row.CallerPrincipalID
	out.Caller.UserName = row.CallerUserName
	out.Caller.SessionType = row.CallerSessionType
	out.Caller.IssuerARN = row.CallerIssuerArn
	out.Caller.IssuerID = row.CallerIssuerID
	if row.CallerSessionPoliciesPresent {
		values, err := r.queryCallerSessionPolicies(row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.SessionPolicies = values
	}
	if row.CallerSessionPolicyArNsPresent {
		values, err := r.queryCallerSessionPolicyARNs(row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.SessionPolicyARNs = values
	}
	out.Caller.HasSessionPolicy = row.CallerHasSessionPolicy
	if row.CallerSessionContextPresent {
		values, err := r.queryCallerSessionContext(row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.SessionContext = values
	}
	out.Caller.FederatedProvider = row.CallerFederatedProvider
	if row.CallerSessionTagsPresent {
		values, err := r.queryCallerSessionTags(row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.SessionTags = values
	}
	if row.CallerTransitiveTagKeysPresent {
		values, err := r.queryCallerTransitiveTagKeys(row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.TransitiveTagKeys = values
	}
	out.Caller.SourceIdentity = row.CallerSourceIdentity
	out.Caller.MFAPresent = row.CallerMfaPresent
	out.Caller.MFAAuthenticatedAt = row.CallerMfaAuthenticatedAt.UTC()
	out.Caller.TokenIssueTime = row.CallerTokenIssueTime.UTC()
	if row.CallerCalledViaPresent {
		values, err := r.queryCallerCalledVia(row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.CalledVia = values
	}
	out.Caller.TransportKnown = row.CallerTransportKnown
	out.Caller.SourceIP = row.CallerSourceIp
	out.Caller.SecureTransport = row.CallerSecureTransport
	out.Caller.UserAgent = row.CallerUserAgent
	out.Caller.SignatureVersion = row.CallerSignatureVersion
	out.Caller.AuthenticationMethod = row.CallerAuthenticationMethod
	out.Caller.ServicePrincipal.Name = row.CallerServicePrincipalName
	out.Caller.ServicePrincipal.SourceARN = row.CallerServicePrincipalSourceArn
	out.Caller.ServicePrincipal.Type = row.CallerServicePrincipalType
	if row.CallerServicePrincipalAliasesPresent {
		values, err := r.queryCallerServicePrincipalAliases(row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.ServicePrincipal.Aliases = values
	}
	out.Caller.InvokedBy = row.CallerInvokedBy
	out.Caller.InScopeOf.IssuerType = row.CallerInScopeOfIssuerType
	out.Caller.InScopeOf.CredentialsIssuedTo = row.CallerInScopeOfCredentialsIssuedTo
	out.ParentEventID = row.ParentEventID
	out.Version = row.Version
	out.Due = row.Due.UTC()
	out.Started = timePointer(row.Started)
	out.EngineID = row.EngineID
	if row.ColumnsPresent {
		values, err := r.queryColumns(row.ID)
		if err != nil {
			return out, err
		}
		out.Columns = values
	}
	out.UpdateCount = row.UpdateCount
	out.PublishMetrics = row.PublishMetrics
	out.RequesterPays = row.RequesterPays
	out.BytesCutoff = row.BytesCutoff
	return out, nil
}

func (w writer) PutQuery(v domain.QueryRecord) error {
	var p sqlcgen.PutQueryParams
	p.KeyScopePartition = v.Key.Scope.Partition
	p.KeyScopeAccountID = v.Key.Scope.AccountID
	p.KeyScopeRegion = v.Key.Scope.Region
	p.KeyName = v.Key.Name
	if v.Data.EngineVersion != nil {
		p.DataEngineVersionPresent = true
		p.DataEngineVersionEffectiveEngineVersion = nullableString(v.Data.EngineVersion.EffectiveEngineVersion)
		p.DataEngineVersionSelectedEngineVersion = nullableString(v.Data.EngineVersion.SelectedEngineVersion)
	}
	p.DataExecutionParametersPresent = v.Data.ExecutionParameters != nil
	if v.Data.ManagedQueryResultsConfiguration != nil {
		p.DataManagedQueryResultsConfigurationPresent = true
		p.DataManagedQueryResultsConfigurationEnabled = nullableBool(v.Data.ManagedQueryResultsConfiguration.Enabled)
		if v.Data.ManagedQueryResultsConfiguration.EncryptionConfiguration != nil {
			p.DataManagedQueryResultsConfigurationEncryptionConfigurationPresent = true
			p.DataManagedQueryResultsConfigurationEncryptionConfigurationKmsKey = nullableString(v.Data.ManagedQueryResultsConfiguration.EncryptionConfiguration.KmsKey)
		}
	}
	p.DataQuery = nullableString(v.Data.Query)
	if v.Data.QueryExecutionContext != nil {
		p.DataQueryExecutionContextPresent = true
		p.DataQueryExecutionContextCatalog = nullableString(v.Data.QueryExecutionContext.Catalog)
		p.DataQueryExecutionContextDatabase = nullableString(v.Data.QueryExecutionContext.Database)
	}
	p.DataQueryExecutionID = nullableString(v.Data.QueryExecutionId)
	if v.Data.QueryResultsS3AccessGrantsConfiguration != nil {
		p.DataQueryResultsS3AccessGrantsConfigurationPresent = true
		p.DataQueryResultsS3AccessGrantsConfigurationAuthenticationType = nullableString(v.Data.QueryResultsS3AccessGrantsConfiguration.AuthenticationType)
		p.DataQueryResultsS3AccessGrantsConfigurationCreateUserLevelPrefix = nullableBool(v.Data.QueryResultsS3AccessGrantsConfiguration.CreateUserLevelPrefix)
		p.DataQueryResultsS3AccessGrantsConfigurationEnableS3AccessGrants = nullableBool(v.Data.QueryResultsS3AccessGrantsConfiguration.EnableS3AccessGrants)
	}
	if v.Data.ResultConfiguration != nil {
		p.DataResultConfigurationPresent = true
		if v.Data.ResultConfiguration.AclConfiguration != nil {
			p.DataResultConfigurationAclConfigurationPresent = true
			p.DataResultConfigurationAclConfigurationS3AclOption = nullableString(v.Data.ResultConfiguration.AclConfiguration.S3AclOption)
		}
		if v.Data.ResultConfiguration.EncryptionConfiguration != nil {
			p.DataResultConfigurationEncryptionConfigurationPresent = true
			p.DataResultConfigurationEncryptionConfigurationEncryptionOption = nullableString(v.Data.ResultConfiguration.EncryptionConfiguration.EncryptionOption)
			p.DataResultConfigurationEncryptionConfigurationKmsKey = nullableString(v.Data.ResultConfiguration.EncryptionConfiguration.KmsKey)
		}
		p.DataResultConfigurationExpectedBucketOwner = nullableString(v.Data.ResultConfiguration.ExpectedBucketOwner)
		p.DataResultConfigurationOutputLocation = nullableString(v.Data.ResultConfiguration.OutputLocation)
	}
	if v.Data.ResultReuseConfiguration != nil {
		p.DataResultReuseConfigurationPresent = true
		if v.Data.ResultReuseConfiguration.ResultReuseByAgeConfiguration != nil {
			p.DataResultReuseConfigurationResultReuseByAgeConfigurationPresent = true
			p.DataResultReuseConfigurationResultReuseByAgeConfigurationEnabled = nullableBool(v.Data.ResultReuseConfiguration.ResultReuseByAgeConfiguration.Enabled)
			p.DataResultReuseConfigurationResultReuseByAgeConfigurationMaxAgeInMinutes = nullableInteger(v.Data.ResultReuseConfiguration.ResultReuseByAgeConfiguration.MaxAgeInMinutes)
		}
	}
	p.DataStatementType = nullableString(v.Data.StatementType)
	if v.Data.Statistics != nil {
		p.DataStatisticsPresent = true
		p.DataStatisticsDataManifestLocation = nullableString(v.Data.Statistics.DataManifestLocation)
		p.DataStatisticsDataScannedInBytes = nullableInteger(v.Data.Statistics.DataScannedInBytes)
		p.DataStatisticsDpuCount = nullableFloat(v.Data.Statistics.DpuCount)
		p.DataStatisticsEngineExecutionTimeInMillis = nullableInteger(v.Data.Statistics.EngineExecutionTimeInMillis)
		p.DataStatisticsQueryPlanningTimeInMillis = nullableInteger(v.Data.Statistics.QueryPlanningTimeInMillis)
		p.DataStatisticsQueryQueueTimeInMillis = nullableInteger(v.Data.Statistics.QueryQueueTimeInMillis)
		if v.Data.Statistics.ResultReuseInformation != nil {
			p.DataStatisticsResultReuseInformationPresent = true
			p.DataStatisticsResultReuseInformationReusedPreviousResult = nullableBool(v.Data.Statistics.ResultReuseInformation.ReusedPreviousResult)
		}
		p.DataStatisticsServicePreProcessingTimeInMillis = nullableInteger(v.Data.Statistics.ServicePreProcessingTimeInMillis)
		p.DataStatisticsServiceProcessingTimeInMillis = nullableInteger(v.Data.Statistics.ServiceProcessingTimeInMillis)
		p.DataStatisticsTotalExecutionTimeInMillis = nullableInteger(v.Data.Statistics.TotalExecutionTimeInMillis)
	}
	if v.Data.Status != nil {
		p.DataStatusPresent = true
		if v.Data.Status.AthenaError != nil {
			p.DataStatusAthenaErrorPresent = true
			p.DataStatusAthenaErrorErrorCategory = nullableInteger(v.Data.Status.AthenaError.ErrorCategory)
			p.DataStatusAthenaErrorErrorMessage = nullableString(v.Data.Status.AthenaError.ErrorMessage)
			p.DataStatusAthenaErrorErrorType = nullableInteger(v.Data.Status.AthenaError.ErrorType)
			p.DataStatusAthenaErrorRetryable = nullableBool(v.Data.Status.AthenaError.Retryable)
		}
		p.DataStatusCompletionDateTime = nullableTime(v.Data.Status.CompletionDateTime)
		p.DataStatusState = nullableString(v.Data.Status.State)
		p.DataStatusStateChangeReason = nullableString(v.Data.Status.StateChangeReason)
		p.DataStatusSubmissionDateTime = nullableTime(v.Data.Status.SubmissionDateTime)
	}
	p.DataSubstatementType = nullableString(v.Data.SubstatementType)
	p.DataWorkGroup = nullableString(v.Data.WorkGroup)
	p.Token = v.Token
	p.Fingerprint = v.Fingerprint
	p.CallerAccountID = v.Caller.AccountID
	p.CallerRegion = v.Caller.Region
	p.CallerPartition = v.Caller.Partition
	p.CallerAccessKeyID = v.Caller.AccessKeyID
	p.CallerRequestID = v.Caller.RequestID
	p.CallerParentEventID = v.Caller.ParentEventID
	p.CallerTraceHeader = v.Caller.TraceHeader
	p.CallerPrincipalArn = v.Caller.PrincipalARN
	p.CallerPrincipalID = v.Caller.PrincipalID
	p.CallerUserName = v.Caller.UserName
	p.CallerSessionType = v.Caller.SessionType
	p.CallerIssuerArn = v.Caller.IssuerARN
	p.CallerIssuerID = v.Caller.IssuerID
	p.CallerSessionPoliciesPresent = v.Caller.SessionPolicies != nil
	p.CallerSessionPolicyArNsPresent = v.Caller.SessionPolicyARNs != nil
	p.CallerHasSessionPolicy = v.Caller.HasSessionPolicy
	p.CallerSessionContextPresent = v.Caller.SessionContext != nil
	p.CallerFederatedProvider = v.Caller.FederatedProvider
	p.CallerSessionTagsPresent = v.Caller.SessionTags != nil
	p.CallerTransitiveTagKeysPresent = v.Caller.TransitiveTagKeys != nil
	p.CallerSourceIdentity = v.Caller.SourceIdentity
	p.CallerMfaPresent = v.Caller.MFAPresent
	p.CallerMfaAuthenticatedAt = v.Caller.MFAAuthenticatedAt.UTC()
	p.CallerTokenIssueTime = v.Caller.TokenIssueTime.UTC()
	p.CallerCalledViaPresent = v.Caller.CalledVia != nil
	p.CallerTransportKnown = v.Caller.TransportKnown
	p.CallerSourceIp = v.Caller.SourceIP
	p.CallerSecureTransport = v.Caller.SecureTransport
	p.CallerUserAgent = v.Caller.UserAgent
	p.CallerSignatureVersion = v.Caller.SignatureVersion
	p.CallerAuthenticationMethod = v.Caller.AuthenticationMethod
	p.CallerServicePrincipalName = v.Caller.ServicePrincipal.Name
	p.CallerServicePrincipalSourceArn = v.Caller.ServicePrincipal.SourceARN
	p.CallerServicePrincipalType = v.Caller.ServicePrincipal.Type
	p.CallerServicePrincipalAliasesPresent = v.Caller.ServicePrincipal.Aliases != nil
	p.CallerInvokedBy = v.Caller.InvokedBy
	p.CallerInScopeOfIssuerType = v.Caller.InScopeOf.IssuerType
	p.CallerInScopeOfCredentialsIssuedTo = v.Caller.InScopeOf.CredentialsIssuedTo
	p.ParentEventID = v.ParentEventID
	p.Version = v.Version
	p.Due = v.Due.UTC()
	p.Started = nullableTime(v.Started)
	p.EngineID = v.EngineID
	p.ColumnsPresent = v.Columns != nil
	p.UpdateCount = v.UpdateCount
	p.PublishMetrics = v.PublishMetrics
	p.RequesterPays = v.RequesterPays
	p.BytesCutoff = v.BytesCutoff
	id, err := w.q.PutQuery(w.ctx, p)
	if err != nil {
		return err
	}
	if err := w.q.DeleteQueryDataExecutionParameters(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteQueryCallerSessionPolicies(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteQueryCallerSessionPolicyARNs(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteQueryCallerSessionContext(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteQueryCallerSessionTags(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteQueryCallerTransitiveTagKeys(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteQueryCallerCalledVia(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteQueryCallerServicePrincipalAliases(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.DeleteQueryColumns(w.ctx, id); err != nil {
		return err
	}
	if err := w.putQueryDataExecutionParameters(id, v.Data.ExecutionParameters); err != nil {
		return err
	}
	if err := w.putQueryCallerSessionPolicies(id, v.Caller.SessionPolicies); err != nil {
		return err
	}
	if err := w.putQueryCallerSessionPolicyARNs(id, v.Caller.SessionPolicyARNs); err != nil {
		return err
	}
	if err := w.putQueryCallerSessionContext(id, v.Caller.SessionContext); err != nil {
		return err
	}
	if err := w.putQueryCallerSessionTags(id, v.Caller.SessionTags); err != nil {
		return err
	}
	if err := w.putQueryCallerTransitiveTagKeys(id, v.Caller.TransitiveTagKeys); err != nil {
		return err
	}
	if err := w.putQueryCallerCalledVia(id, v.Caller.CalledVia); err != nil {
		return err
	}
	if err := w.putQueryCallerServicePrincipalAliases(id, v.Caller.ServicePrincipal.Aliases); err != nil {
		return err
	}
	if err := w.putQueryColumns(id, v.Columns); err != nil {
		return err
	}
	return nil
}

func (r reader) queryDataExecutionParameters(parentID int64) (api.ExecutionParameters, error) {
	rows, err := r.q.ListQueryDataExecutionParameters(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.ExecutionParameters, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		value := api.ExecutionParameter(row.Value)
		out = append(out, value)
	}
	return out, nil
}

func (w writer) putQueryDataExecutionParameters(parentID int64, values api.ExecutionParameters) error {
	for i := range values {
		value := values[i]
		p := sqlcgen.PutQueryDataExecutionParametersParams{ParentID: parentID, Position: int64(i)}
		p.Value = string(value)
		if err := w.q.PutQueryDataExecutionParameters(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) queryCallerSessionPolicies(parentID int64) ([]string, error) {
	rows, err := r.q.ListQueryCallerSessionPolicies(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		value := row.Value
		out = append(out, value)
	}
	return out, nil
}

func (w writer) putQueryCallerSessionPolicies(parentID int64, values []string) error {
	for i := range values {
		value := values[i]
		p := sqlcgen.PutQueryCallerSessionPoliciesParams{ParentID: parentID, Position: int64(i)}
		p.Value = value
		if err := w.q.PutQueryCallerSessionPolicies(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) queryCallerSessionPolicyARNs(parentID int64) ([]string, error) {
	rows, err := r.q.ListQueryCallerSessionPolicyARNs(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		value := row.Value
		out = append(out, value)
	}
	return out, nil
}

func (w writer) putQueryCallerSessionPolicyARNs(parentID int64, values []string) error {
	for i := range values {
		value := values[i]
		p := sqlcgen.PutQueryCallerSessionPolicyARNsParams{ParentID: parentID, Position: int64(i)}
		p.Value = value
		if err := w.q.PutQueryCallerSessionPolicyARNs(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) queryCallerSessionContext(parentID int64) (map[string][]string, error) {
	rows, err := r.q.ListQueryCallerSessionContext(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(rows))
	for i := range rows {
		row := &rows[i]
		var value []string
		if row.ValuePresent {
			values, err := r.queryCallerSessionContextValue(row.ID)
			if err != nil {
				return out, err
			}
			value = values
		}
		out[row.MapKey] = value
	}
	return out, nil
}

func (w writer) putQueryCallerSessionContext(parentID int64, values map[string][]string) error {
	for key, value := range values {
		p := sqlcgen.PutQueryCallerSessionContextParams{ParentID: parentID}
		p.MapKey = key
		p.ValuePresent = value != nil
		id, err := w.q.PutQueryCallerSessionContext(w.ctx, p)
		if err != nil {
			return err
		}
		if err := w.putQueryCallerSessionContextValue(id, value); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) queryCallerSessionContextValue(parentID int64) ([]string, error) {
	rows, err := r.q.ListQueryCallerSessionContextValue(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		value := row.Value
		out = append(out, value)
	}
	return out, nil
}

func (w writer) putQueryCallerSessionContextValue(parentID int64, values []string) error {
	for i := range values {
		value := values[i]
		p := sqlcgen.PutQueryCallerSessionContextValueParams{ParentID: parentID, Position: int64(i)}
		p.Value = value
		if err := w.q.PutQueryCallerSessionContextValue(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) queryCallerSessionTags(parentID int64) (map[string]string, error) {
	rows, err := r.q.ListQueryCallerSessionTags(r.ctx, parentID)
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

func (w writer) putQueryCallerSessionTags(parentID int64, values map[string]string) error {
	for key, value := range values {
		p := sqlcgen.PutQueryCallerSessionTagsParams{ParentID: parentID}
		p.MapKey = key
		p.Value = value
		if err := w.q.PutQueryCallerSessionTags(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) queryCallerTransitiveTagKeys(parentID int64) ([]string, error) {
	rows, err := r.q.ListQueryCallerTransitiveTagKeys(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		value := row.Value
		out = append(out, value)
	}
	return out, nil
}

func (w writer) putQueryCallerTransitiveTagKeys(parentID int64, values []string) error {
	for i := range values {
		value := values[i]
		p := sqlcgen.PutQueryCallerTransitiveTagKeysParams{ParentID: parentID, Position: int64(i)}
		p.Value = value
		if err := w.q.PutQueryCallerTransitiveTagKeys(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) queryCallerCalledVia(parentID int64) ([]string, error) {
	rows, err := r.q.ListQueryCallerCalledVia(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		value := row.Value
		out = append(out, value)
	}
	return out, nil
}

func (w writer) putQueryCallerCalledVia(parentID int64, values []string) error {
	for i := range values {
		value := values[i]
		p := sqlcgen.PutQueryCallerCalledViaParams{ParentID: parentID, Position: int64(i)}
		p.Value = value
		if err := w.q.PutQueryCallerCalledVia(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) queryCallerServicePrincipalAliases(parentID int64) ([]string, error) {
	rows, err := r.q.ListQueryCallerServicePrincipalAliases(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		value := row.Value
		out = append(out, value)
	}
	return out, nil
}

func (w writer) putQueryCallerServicePrincipalAliases(parentID int64, values []string) error {
	for i := range values {
		value := values[i]
		p := sqlcgen.PutQueryCallerServicePrincipalAliasesParams{ParentID: parentID, Position: int64(i)}
		p.Value = value
		if err := w.q.PutQueryCallerServicePrincipalAliases(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) queryColumns(parentID int64) (api.ColumnInfoList, error) {
	rows, err := r.q.ListQueryColumns(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.ColumnInfoList, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		var value api.ColumnInfo
		value.CaseSensitive = boolPointer[api.Boolean](row.ValueCaseSensitive)
		value.CatalogName = stringPointer[api.String](row.ValueCatalogName)
		value.Label = stringPointer[api.String](row.ValueLabel)
		value.Name = stringPointer[api.String](row.ValueName)
		value.Nullable = stringPointer[api.ColumnNullable](row.ValueNullable)
		value.Precision = integerPointer[api.Integer](row.ValuePrecision)
		value.Scale = integerPointer[api.Integer](row.ValueScale)
		value.SchemaName = stringPointer[api.String](row.ValueSchemaName)
		value.TableName = stringPointer[api.String](row.ValueTableName)
		value.Type = stringPointer[api.String](row.ValueType)
		out = append(out, value)
	}
	return out, nil
}

func (w writer) putQueryColumns(parentID int64, values api.ColumnInfoList) error {
	for i := range values {
		value := &values[i]
		p := sqlcgen.PutQueryColumnsParams{ParentID: parentID, Position: int64(i)}
		p.ValueCaseSensitive = nullableBool(value.CaseSensitive)
		p.ValueCatalogName = nullableString(value.CatalogName)
		p.ValueLabel = nullableString(value.Label)
		p.ValueName = nullableString(value.Name)
		p.ValueNullable = nullableString(value.Nullable)
		p.ValuePrecision = nullableInteger(value.Precision)
		p.ValueScale = nullableInteger(value.Scale)
		p.ValueSchemaName = nullableString(value.SchemaName)
		p.ValueTableName = nullableString(value.TableName)
		p.ValueType = nullableString(value.Type)
		if err := w.q.PutQueryColumns(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}
