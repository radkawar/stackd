package codebuild

import (
	api "stackd/internal/awsapi/codebuild"
	domain "stackd/storage/codebuild"
	"stackd/storage/sqlite/codebuild/internal/sqlcgen"
)

func (r reader) Project(k domain.ProjectKey) (domain.ProjectRecord, error) {
	row, err := r.q.GetProject(r.ctx, sqlcgen.GetProjectParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ProjectName: k.Name})
	if err != nil {
		return domain.ProjectRecord{}, missing(err)
	}
	return r.project(row)
}

func (r reader) Projects(k domain.Scope) ([]domain.ProjectRecord, error) {
	rows, err := r.q.ListProjects(r.ctx, sqlcgen.ListProjectsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ProjectRecord, len(rows))
	for i, row := range rows {
		out[i], err = r.project(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r reader) project(row sqlcgen.CodebuildProject) (domain.ProjectRecord, error) {
	out := domain.ProjectRecord{
		Key:         domain.ProjectKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.ProjectName},
		BuildNumber: row.BuildNumber,
		Ownership:   row.Ownership,
		Data: api.Project{
			Arn: stringPointer[api.String](row.Arn), Name: stringPointer[api.ProjectName](row.Name),
			AutoRetryLimit: integerPointer[api.WrapperInt](row.AutoRetryLimit), ConcurrentBuildLimit: integerPointer[api.WrapperInt](row.ConcurrentBuildLimit),
			Created: timePointer(row.Created), Description: stringPointer[api.ProjectDescription](row.Description),
			EncryptionKey: stringPointer[api.NonEmptyString](row.EncryptionKey), LastModified: timePointer(row.LastModified),
			ProjectVisibility: stringPointer[api.ProjectVisibilityType](row.ProjectVisibility), PublicProjectAlias: stringPointer[api.NonEmptyString](row.PublicProjectAlias),
			QueuedTimeoutInMinutes: integerPointer[api.TimeOut](row.QueuedTimeoutInMinutes), ResourceAccessRole: stringPointer[api.NonEmptyString](row.ResourceAccessRole),
			ServiceRole: stringPointer[api.NonEmptyString](row.ServiceRole), SourceVersion: stringPointer[api.String](row.SourceVersion),
			TimeoutInMinutes: integerPointer[api.BuildTimeOut](row.TimeoutInMinutes),
		},
	}
	if err := unmarshalFields(
		jsonReadField{row.Artifacts, &out.Data.Artifacts}, jsonReadField{row.Badge, &out.Data.Badge},
		jsonReadField{row.BuildBatchConfig, &out.Data.BuildBatchConfig}, jsonReadField{row.Cache, &out.Data.Cache},
		jsonReadField{row.Environment, &out.Data.Environment}, jsonReadField{row.FileSystemLocations, &out.Data.FileSystemLocations},
		jsonReadField{row.LogsConfig, &out.Data.LogsConfig}, jsonReadField{row.SecondaryArtifacts, &out.Data.SecondaryArtifacts},
		jsonReadField{row.SecondarySources, &out.Data.SecondarySources}, jsonReadField{row.Source, &out.Data.Source},
		jsonReadField{row.VpcConfig, &out.Data.VpcConfig}, jsonReadField{row.Webhook, &out.Data.Webhook},
	); err != nil {
		return domain.ProjectRecord{}, err
	}
	if err := r.projectChildren(&out, row); err != nil {
		return domain.ProjectRecord{}, err
	}
	return out, nil
}

func (w writer) PutProject(v domain.ProjectRecord) error {
	k, d := v.Key, v.Data
	row := sqlcgen.PutProjectParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ProjectName: k.Name, BuildNumber: v.BuildNumber,
		Ownership: v.Ownership,
		Arn:       nullableString(d.Arn), Name: nullableString(d.Name), AutoRetryLimit: nullableInteger(d.AutoRetryLimit),
		ConcurrentBuildLimit: nullableInteger(d.ConcurrentBuildLimit), Created: nullableTime(d.Created), Description: nullableString(d.Description),
		EncryptionKey: nullableString(d.EncryptionKey), LastModified: nullableTime(d.LastModified), ProjectVisibility: nullableString(d.ProjectVisibility),
		PublicProjectAlias: nullableString(d.PublicProjectAlias), QueuedTimeoutInMinutes: nullableInteger(d.QueuedTimeoutInMinutes),
		ResourceAccessRole: nullableString(d.ResourceAccessRole), ServiceRole: nullableString(d.ServiceRole), SourceVersion: nullableString(d.SourceVersion),
		TimeoutInMinutes: nullableInteger(d.TimeoutInMinutes), EnvironmentVariablesPresent: d.Environment != nil && d.Environment.EnvironmentVariables != nil,
		SecondarySourceVersionsPresent: d.SecondarySourceVersions != nil, TagsPresent: d.Tags != nil,
	}
	if err := marshalFields(
		jsonWriteField{&row.Artifacts, d.Artifacts}, jsonWriteField{&row.Badge, d.Badge},
		jsonWriteField{&row.BuildBatchConfig, d.BuildBatchConfig}, jsonWriteField{&row.Cache, d.Cache},
		jsonWriteField{&row.Environment, environmentConfig(d.Environment)}, jsonWriteField{&row.FileSystemLocations, d.FileSystemLocations},
		jsonWriteField{&row.LogsConfig, d.LogsConfig}, jsonWriteField{&row.SecondaryArtifacts, d.SecondaryArtifacts},
		jsonWriteField{&row.SecondarySources, d.SecondarySources}, jsonWriteField{&row.Source, d.Source},
		jsonWriteField{&row.VpcConfig, d.VpcConfig}, jsonWriteField{&row.Webhook, d.Webhook},
	); err != nil {
		return err
	}
	if err := w.q.PutProject(w.ctx, row); err != nil {
		return err
	}
	return w.putProjectChildren(v)
}

func (w writer) DeleteProject(k domain.ProjectKey) error {
	return w.q.DeleteProject(w.ctx, sqlcgen.DeleteProjectParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ProjectName: k.Name})
}

func (r reader) projectChildren(out *domain.ProjectRecord, row sqlcgen.CodebuildProject) error {
	k := out.Key
	if row.TagsPresent {
		tags, err := r.q.ListProjectTags(r.ctx, sqlcgen.ListProjectTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ProjectName: k.Name})
		if err != nil {
			return err
		}
		out.Data.Tags = make(api.TagList, len(tags))
		for i, tag := range tags {
			out.Data.Tags[i] = api.Tag{Key: stringPointer[api.KeyInput](tag.TagKey), Value: stringPointer[api.ValueInput](tag.TagValue)}
		}
	}
	if row.EnvironmentVariablesPresent && out.Data.Environment != nil {
		variables, err := r.q.ListProjectVariables(r.ctx, sqlcgen.ListProjectVariablesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ProjectName: k.Name})
		if err != nil {
			return err
		}
		out.Data.Environment.EnvironmentVariables = make(api.EnvironmentVariables, len(variables))
		for i, variable := range variables {
			out.Data.Environment.EnvironmentVariables[i] = api.EnvironmentVariable{Name: stringPointer[api.NonEmptyString](variable.Name), Value: stringPointer[api.String](variable.Value), Type: stringPointer[api.EnvironmentVariableType](variable.Type)}
		}
	}
	if row.SecondarySourceVersionsPresent {
		versions, err := r.q.ListProjectSourceVersions(r.ctx, sqlcgen.ListProjectSourceVersionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ProjectName: k.Name})
		if err != nil {
			return err
		}
		out.Data.SecondarySourceVersions = make(api.ProjectSecondarySourceVersions, len(versions))
		for i, version := range versions {
			out.Data.SecondarySourceVersions[i] = api.ProjectSourceVersion{SourceIdentifier: stringPointer[api.String](version.SourceIdentifier), SourceVersion: stringPointer[api.String](version.SourceVersion)}
		}
	}
	return nil
}

func (w writer) putProjectChildren(v domain.ProjectRecord) error {
	k := v.Key
	if err := w.q.DeleteProjectTags(w.ctx, sqlcgen.DeleteProjectTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ProjectName: k.Name}); err != nil {
		return err
	}
	for i, tag := range v.Data.Tags {
		if err := w.q.PutProjectTag(w.ctx, sqlcgen.PutProjectTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ProjectName: k.Name, Position: int64(i), TagKey: nullableString(tag.Key), TagValue: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteProjectVariables(w.ctx, sqlcgen.DeleteProjectVariablesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ProjectName: k.Name}); err != nil {
		return err
	}
	if v.Data.Environment != nil {
		for i, variable := range v.Data.Environment.EnvironmentVariables {
			if err := w.q.PutProjectVariable(w.ctx, sqlcgen.PutProjectVariableParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ProjectName: k.Name, Position: int64(i), Name: nullableString(variable.Name), Value: nullableString(variable.Value), Type: nullableString(variable.Type)}); err != nil {
				return err
			}
		}
	}
	if err := w.q.DeleteProjectSourceVersions(w.ctx, sqlcgen.DeleteProjectSourceVersionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ProjectName: k.Name}); err != nil {
		return err
	}
	for i, version := range v.Data.SecondarySourceVersions {
		if err := w.q.PutProjectSourceVersion(w.ctx, sqlcgen.PutProjectSourceVersionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ProjectName: k.Name, Position: int64(i), SourceIdentifier: nullableString(version.SourceIdentifier), SourceVersion: nullableString(version.SourceVersion)}); err != nil {
			return err
		}
	}
	return nil
}
