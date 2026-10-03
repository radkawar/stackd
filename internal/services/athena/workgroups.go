package athena

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	api "stackd/internal/awsapi/athena"
)

func registerWorkGroups(s *Service) {
	registerControl(s, "CreateWorkGroup", s.createWorkGroup)
	registerControl(s, "GetWorkGroup", s.getWorkGroup)
	registerControl(s, "ListWorkGroups", s.listWorkGroups)
	registerControl(s, "UpdateWorkGroup", s.updateWorkGroup)
	registerControl(s, "DeleteWorkGroup", s.deleteWorkGroup)
}
func defaultConfiguration() api.WorkGroupConfiguration {
	return api.WorkGroupConfiguration{EnforceWorkGroupConfiguration: new(api.BoxedBoolean(true)), PublishCloudWatchMetricsEnabled: new(api.BoxedBoolean(true)), RequesterPaysEnabled: new(api.BoxedBoolean(false)), EnableMinimumEncryptionConfiguration: new(api.BoxedBoolean(false)), EngineVersion: &api.EngineVersion{SelectedEngineVersion: new(api.NameString("AUTO")), EffectiveEngineVersion: new(api.NameString("Athena engine version 3"))}}
}
func defaultWorkGroup(key ResourceKey, now time.Time) WorkGroupRecord {
	c := defaultConfiguration()
	return WorkGroupRecord{Key: key, Data: api.WorkGroup{Name: new(api.WorkGroupName(key.Name)), State: new(api.WorkGroupState("ENABLED")), CreationTime: &now, Configuration: &c}, Tags: map[string]string{}}
}
func normalizeConfiguration(in *api.WorkGroupConfiguration) (api.WorkGroupConfiguration, error) {
	c := defaultConfiguration()
	if in != nil {
		c = api.CloneWorkGroupConfiguration(*in)
	}
	if c.EnforceWorkGroupConfiguration == nil {
		c.EnforceWorkGroupConfiguration = new(api.BoxedBoolean(true))
	}
	if c.PublishCloudWatchMetricsEnabled == nil {
		c.PublishCloudWatchMetricsEnabled = new(api.BoxedBoolean(true))
	}
	if c.RequesterPaysEnabled == nil {
		c.RequesterPaysEnabled = new(api.BoxedBoolean(false))
	}
	if c.EnableMinimumEncryptionConfiguration == nil {
		c.EnableMinimumEncryptionConfiguration = new(api.BoxedBoolean(false))
	}
	if c.EngineVersion == nil {
		c.EngineVersion = defaultConfiguration().EngineVersion
	}
	version := value(c.EngineVersion.SelectedEngineVersion)
	if version == "" {
		version = "AUTO"
	}
	if version != "AUTO" && version != "Athena engine version 3" {
		// TODO: Comeback Athena engine version 2 and Spark engine workgroups require separately evidenced runtime compatibility.
		return c, unsupported("The selected Athena engine version is not available.")
	}
	c.EngineVersion.SelectedEngineVersion = new(api.NameString(version))
	c.EngineVersion.EffectiveEngineVersion = new(api.NameString("Athena engine version 3"))
	if c.BytesScannedCutoffPerQuery != nil && *c.BytesScannedCutoffPerQuery < 10485760 {
		return c, invalidRequest("BytesScannedCutoffPerQuery must be at least 10485760.")
	}
	if c.ExecutionRole != nil || c.CustomerContentEncryptionConfiguration != nil || c.IdentityCenterConfiguration != nil || c.ManagedQueryResultsConfiguration != nil || c.QueryResultsS3AccessGrantsConfiguration != nil || c.EngineConfiguration != nil || c.MonitoringConfiguration != nil || c.AdditionalConfiguration != nil {
		// TODO: Comeback implement managed results, Identity Center/S3 Access Grants, Spark role/content encryption and capacity engine configuration before accepting these controls.
		return c, unsupported("This workgroup configuration requires an unavailable Athena execution mode.")
	}
	if err := validateResults(c.ResultConfiguration, false); err != nil {
		return c, err
	}
	return c, nil
}
func validateResults(c *api.ResultConfiguration, required bool) error {
	if c == nil {
		if required {
			return invalidRequest("No output location provided. An output location is required either through the Workgroup result configuration or as an API input.")
		}
		return nil
	}
	if location := value(c.OutputLocation); location != "" {
		u, err := url.Parse(location)
		if err != nil || u.Scheme != "s3" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return invalidRequest("OutputLocation must be an S3 URI.")
		}
	} else if required {
		return invalidRequest("No output location provided. An output location is required either through the Workgroup result configuration or as an API input.")
	}
	if e := c.EncryptionConfiguration; e != nil {
		switch value(e.EncryptionOption) {
		case "SSE_S3":
		case "SSE_KMS":
			if value(e.KmsKey) == "" {
				return invalidRequest("KmsKey is required for KMS result encryption.")
			}
		case "CSE_KMS":
			// TODO: Comeback support actual client-side KMS envelope encryption and result decryption; SSE_KMS is not a substitute.
			return unsupported("Client-side KMS query result encryption is unavailable.")
		default:
			return invalidRequest("Invalid result encryption option.")
		}
	}
	if c.AclConfiguration != nil && value(c.AclConfiguration.S3AclOption) != "BUCKET_OWNER_FULL_CONTROL" {
		return invalidRequest("Invalid S3 ACL option.")
	}
	return nil
}
func (s *Service) createWorkGroup(ctx context.Context, tx Transaction, in *api.CreateWorkGroupInput) (*api.CreateWorkGroupOutput, error) {
	key := resourceFor(ctx, value(in.Name))
	if key.Name == "" {
		return nil, invalidRequest("Workgroup name is required.")
	}
	tags, err := requestTags(in.Tags)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "CreateWorkGroup", key.ARN("workgroup"), nil, tagConditions(tags)); err != nil {
		return nil, err
	}
	if _, err := tx.WorkGroup(key); err == nil || key.Name == "primary" {
		return nil, invalidRequest("WorkGroup already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	c, err := normalizeConfiguration(in.Configuration)
	if err != nil {
		return nil, err
	}
	v := defaultWorkGroup(key, s.clock.Now())
	v.Data.Configuration = &c
	if in.Description != nil {
		v.Data.Description = in.Description
	}
	v.Tags = tags
	if err := tx.PutWorkGroup(v); err != nil {
		return nil, err
	}
	return &api.CreateWorkGroupOutput{}, nil
}
func (s *Service) getWorkGroup(ctx context.Context, tx Transaction, in *api.GetWorkGroupInput) (*api.GetWorkGroupOutput, error) {
	v, err := s.loadWorkGroup(ctx, tx, value(in.WorkGroup), "GetWorkGroup")
	if err != nil {
		return nil, err
	}
	return &api.GetWorkGroupOutput{WorkGroup: &v.Data}, nil
}
func (s *Service) listWorkGroups(ctx context.Context, tx Transaction, in *api.ListWorkGroupsInput) (*api.ListWorkGroupsOutput, error) {
	if err := s.authorize(ctx, "ListWorkGroups", "*", nil, nil); err != nil {
		return nil, err
	}
	key := resourceFor(ctx, "primary")
	if _, err := tx.WorkGroup(key); errors.Is(err, ErrNotFound) {
		if err := tx.PutWorkGroup(defaultWorkGroup(key, s.clock.Now())); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.MaxResults, 50)
	if err != nil {
		return nil, err
	}
	after, err := cursor(key.Scope, "workgroups", "", in.NextToken)
	if err != nil {
		return nil, err
	}
	rows, err := tx.WorkGroups(ResourceQuery{Scope: key.Scope, After: after, Limit: limit + 1})
	if err != nil {
		return nil, err
	}
	out := &api.ListWorkGroupsOutput{WorkGroups: api.WorkGroupsList{}}
	if len(rows) > limit {
		out.NextToken = nextToken(key.Scope, "workgroups", "", rows[limit-1].Key.Name)
		rows = rows[:limit]
	}
	for _, v := range rows {
		out.WorkGroups = append(out.WorkGroups, api.WorkGroupSummary{Name: v.Data.Name, Description: v.Data.Description, CreationTime: v.Data.CreationTime, State: v.Data.State, EngineVersion: v.Data.Configuration.EngineVersion})
	}
	return out, nil
}
func (s *Service) updateWorkGroup(ctx context.Context, tx Transaction, in *api.UpdateWorkGroupInput) (*api.UpdateWorkGroupOutput, error) {
	v, err := s.loadWorkGroup(ctx, tx, value(in.WorkGroup), "UpdateWorkGroup")
	if err != nil {
		return nil, err
	}
	if in.Description != nil {
		v.Data.Description = in.Description
	}
	if in.State != nil {
		if value(in.State) != "ENABLED" && value(in.State) != "DISABLED" {
			return nil, invalidRequest("Invalid workgroup state.")
		}
		if v.Key.Name == "primary" && value(in.State) == "DISABLED" {
			return nil, invalidRequest("The primary workgroup cannot be disabled.")
		}
		v.Data.State = in.State
	}
	if u := in.ConfigurationUpdates; u != nil {
		c := v.Data.Configuration
		if c == nil {
			x := defaultConfiguration()
			c = &x
		}
		if u.EnforceWorkGroupConfiguration != nil {
			c.EnforceWorkGroupConfiguration = u.EnforceWorkGroupConfiguration
		}
		if u.PublishCloudWatchMetricsEnabled != nil {
			c.PublishCloudWatchMetricsEnabled = u.PublishCloudWatchMetricsEnabled
		}
		if u.RequesterPaysEnabled != nil {
			c.RequesterPaysEnabled = u.RequesterPaysEnabled
		}
		if u.EnableMinimumEncryptionConfiguration != nil {
			c.EnableMinimumEncryptionConfiguration = u.EnableMinimumEncryptionConfiguration
		}
		if enabled(u.RemoveBytesScannedCutoffPerQuery) {
			c.BytesScannedCutoffPerQuery = nil
		} else if u.BytesScannedCutoffPerQuery != nil {
			c.BytesScannedCutoffPerQuery = u.BytesScannedCutoffPerQuery
		}
		if u.EngineVersion != nil {
			c.EngineVersion = u.EngineVersion
		}
		if enabled(u.RemoveCustomerContentEncryptionConfiguration) {
			c.CustomerContentEncryptionConfiguration = nil
		} else if u.CustomerContentEncryptionConfiguration != nil {
			c.CustomerContentEncryptionConfiguration = u.CustomerContentEncryptionConfiguration
		}
		if u.ExecutionRole != nil {
			c.ExecutionRole = u.ExecutionRole
		}
		if u.AdditionalConfiguration != nil {
			c.AdditionalConfiguration = u.AdditionalConfiguration
		}
		if u.EngineConfiguration != nil {
			c.EngineConfiguration = u.EngineConfiguration
		}
		if u.MonitoringConfiguration != nil {
			c.MonitoringConfiguration = u.MonitoringConfiguration
		}
		if u.QueryResultsS3AccessGrantsConfiguration != nil {
			c.QueryResultsS3AccessGrantsConfiguration = u.QueryResultsS3AccessGrantsConfiguration
		}
		if u.ManagedQueryResultsConfigurationUpdates != nil {
			return nil, unsupported("Managed query results are unavailable.")
		}
		if r := u.ResultConfigurationUpdates; r != nil {
			if c.ResultConfiguration == nil {
				c.ResultConfiguration = &api.ResultConfiguration{}
			}
			d := c.ResultConfiguration
			if enabled(r.RemoveOutputLocation) {
				d.OutputLocation = nil
			} else if r.OutputLocation != nil {
				d.OutputLocation = r.OutputLocation
			}
			if enabled(r.RemoveEncryptionConfiguration) {
				d.EncryptionConfiguration = nil
			} else if r.EncryptionConfiguration != nil {
				d.EncryptionConfiguration = r.EncryptionConfiguration
			}
			if enabled(r.RemoveExpectedBucketOwner) {
				d.ExpectedBucketOwner = nil
			} else if r.ExpectedBucketOwner != nil {
				d.ExpectedBucketOwner = r.ExpectedBucketOwner
			}
			if enabled(r.RemoveAclConfiguration) {
				d.AclConfiguration = nil
			} else if r.AclConfiguration != nil {
				d.AclConfiguration = r.AclConfiguration
			}
		}
		normalized, err := normalizeConfiguration(c)
		if err != nil {
			return nil, err
		}
		v.Data.Configuration = &normalized
	}
	if err := tx.PutWorkGroup(v); err != nil {
		return nil, err
	}
	return &api.UpdateWorkGroupOutput{}, nil
}
func (s *Service) deleteWorkGroup(ctx context.Context, tx Transaction, in *api.DeleteWorkGroupInput) (*api.DeleteWorkGroupOutput, error) {
	v, err := s.loadWorkGroup(ctx, tx, value(in.WorkGroup), "DeleteWorkGroup")
	if err != nil {
		return nil, err
	}
	if v.Key.Name == "primary" {
		return nil, invalidRequest("The primary workgroup cannot be deleted.")
	}
	filter := ResourceQuery{Scope: v.Key.Scope, WorkGroup: v.Key.Name}
	named, err := tx.NamedQueries(filter)
	if err != nil {
		return nil, err
	}
	prepared, err := tx.PreparedStatements(filter)
	if err != nil {
		return nil, err
	}
	queries, err := tx.Queries(filter)
	if err != nil {
		return nil, err
	}
	if !enabled(in.RecursiveDeleteOption) && (len(named) > 0 || len(prepared) > 0 || len(queries) > 0) {
		return nil, invalidRequest("Workgroup is not empty. Set RecursiveDeleteOption to delete it.")
	}
	for _, q := range queries {
		if queryState(q) == "QUEUED" || queryState(q) == "RUNNING" || q.EngineID != "" {
			return nil, invalidRequest("Workgroup has active query executions or native cleanup in progress.")
		}
	}
	for _, n := range named {
		if err := tx.DeleteNamedQuery(n.Key); err != nil {
			return nil, err
		}
	}
	for _, p := range prepared {
		if err := tx.DeletePreparedStatement(p.Key); err != nil {
			return nil, err
		}
	}
	if err := tx.DeleteWorkGroup(v.Key); err != nil {
		return nil, err
	}
	return &api.DeleteWorkGroupOutput{}, nil
}

func effectiveResults(c *api.WorkGroupConfiguration, in *api.ResultConfiguration) api.ResultConfiguration {
	result := api.ResultConfiguration{}
	if in != nil {
		result = api.CloneResultConfiguration(*in)
	}
	if group := c.ResultConfiguration; group != nil {
		enforce := enabled(c.EnforceWorkGroupConfiguration)
		if group.OutputLocation != nil && (enforce || result.OutputLocation == nil) {
			result.OutputLocation = group.OutputLocation
		}
		if group.EncryptionConfiguration != nil && (enforce || result.EncryptionConfiguration == nil) {
			result.EncryptionConfiguration = group.EncryptionConfiguration
		}
		if group.ExpectedBucketOwner != nil && (enforce || result.ExpectedBucketOwner == nil) {
			result.ExpectedBucketOwner = group.ExpectedBucketOwner
		}
		if group.AclConfiguration != nil && (enforce || result.AclConfiguration == nil) {
			result.AclConfiguration = group.AclConfiguration
		}
	}
	return result
}
func resultObject(location, id string) string {
	return strings.TrimRight(location, "/") + "/" + id + ".csv"
}
