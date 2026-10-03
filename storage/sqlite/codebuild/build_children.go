package codebuild

import (
	api "stackd/internal/awsapi/codebuild"
	domain "stackd/storage/codebuild"
	"stackd/storage/sqlite/codebuild/internal/sqlcgen"
)

func (r reader) buildChildren(out *domain.BuildRecord, row sqlcgen.CodebuildBuild) error {
	k := out.Key
	if row.EnvironmentVariablesPresent && out.Data.Environment != nil {
		variables, err := r.q.ListBuildVariables(r.ctx, sqlcgen.ListBuildVariablesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.Data.Environment.EnvironmentVariables = make(api.EnvironmentVariables, len(variables))
		for i, variable := range variables {
			out.Data.Environment.EnvironmentVariables[i] = api.EnvironmentVariable{Name: stringPointer[api.NonEmptyString](variable.Name), Value: stringPointer[api.String](variable.Value), Type: stringPointer[api.EnvironmentVariableType](variable.Type)}
		}
	}
	if row.ExportedEnvironmentVariablesPresent {
		variables, err := r.q.ListBuildExportedVariables(r.ctx, sqlcgen.ListBuildExportedVariablesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.Data.ExportedEnvironmentVariables = make(api.ExportedEnvironmentVariables, len(variables))
		for i, variable := range variables {
			out.Data.ExportedEnvironmentVariables[i] = api.ExportedEnvironmentVariable{Name: stringPointer[api.NonEmptyString](variable.Name), Value: stringPointer[api.String](variable.Value)}
		}
	}
	if row.SecondarySourceVersionsPresent {
		versions, err := r.q.ListBuildSourceVersions(r.ctx, sqlcgen.ListBuildSourceVersionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.Data.SecondarySourceVersions = make(api.ProjectSecondarySourceVersions, len(versions))
		for i, version := range versions {
			out.Data.SecondarySourceVersions[i] = api.ProjectSourceVersion{SourceIdentifier: stringPointer[api.String](version.SourceIdentifier), SourceVersion: stringPointer[api.String](version.SourceVersion)}
		}
	}
	if row.ReportArnsPresent {
		reports, err := r.q.ListBuildReportARNs(r.ctx, sqlcgen.ListBuildReportARNsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.Data.ReportArns = make(api.BuildReportArns, len(reports))
		for i, report := range reports {
			out.Data.ReportArns[i] = api.String(report.Arn)
		}
	}
	if row.PhasesPresent {
		phases, err := r.q.ListBuildPhases(r.ctx, sqlcgen.ListBuildPhasesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.Data.Phases = make(api.BuildPhases, len(phases))
		for i, phase := range phases {
			out.Data.Phases[i] = api.BuildPhase{DurationInSeconds: integerPointer[api.WrapperLong](phase.DurationInSeconds), EndTime: timePointer(phase.EndTime), PhaseStatus: stringPointer[api.StatusType](phase.PhaseStatus), PhaseType: stringPointer[api.BuildPhaseType](phase.PhaseType), StartTime: timePointer(phase.StartTime)}
			if phase.ContextsPresent {
				contexts, err := r.q.ListBuildPhaseContexts(r.ctx, sqlcgen.ListBuildPhaseContextsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID, PhasePosition: phase.Position})
				if err != nil {
					return err
				}
				out.Data.Phases[i].Contexts = make(api.PhaseContexts, len(contexts))
				for j, context := range contexts {
					out.Data.Phases[i].Contexts[j] = api.PhaseContext{Message: stringPointer[api.String](context.Message), StatusCode: stringPointer[api.String](context.StatusCode)}
				}
			}
		}
	}
	return nil
}

func (w writer) putBuildChildren(v domain.BuildRecord) error {
	k := v.Key
	if err := w.q.DeleteBuildVariables(w.ctx, sqlcgen.DeleteBuildVariablesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	if v.Data.Environment != nil {
		for i, variable := range v.Data.Environment.EnvironmentVariables {
			if err := w.q.PutBuildVariable(w.ctx, sqlcgen.PutBuildVariableParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID, Position: int64(i), Name: nullableString(variable.Name), Value: nullableString(variable.Value), Type: nullableString(variable.Type)}); err != nil {
				return err
			}
		}
	}
	if err := w.q.DeleteBuildExportedVariables(w.ctx, sqlcgen.DeleteBuildExportedVariablesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, variable := range v.Data.ExportedEnvironmentVariables {
		if err := w.q.PutBuildExportedVariable(w.ctx, sqlcgen.PutBuildExportedVariableParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID, Position: int64(i), Name: nullableString(variable.Name), Value: nullableString(variable.Value)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteBuildSourceVersions(w.ctx, sqlcgen.DeleteBuildSourceVersionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, version := range v.Data.SecondarySourceVersions {
		if err := w.q.PutBuildSourceVersion(w.ctx, sqlcgen.PutBuildSourceVersionParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID, Position: int64(i), SourceIdentifier: nullableString(version.SourceIdentifier), SourceVersion: nullableString(version.SourceVersion)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteBuildReportARNs(w.ctx, sqlcgen.DeleteBuildReportARNsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, arn := range v.Data.ReportArns {
		if err := w.q.PutBuildReportARN(w.ctx, sqlcgen.PutBuildReportARNParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID, Position: int64(i), Arn: string(arn)}); err != nil {
			return err
		}
	}
	// Cascading phase deletion also removes every old context, including contexts
	// belonging to phases omitted by a replacement snapshot.
	if err := w.q.DeleteBuildPhases(w.ctx, sqlcgen.DeleteBuildPhasesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, phase := range v.Data.Phases {
		if err := w.q.PutBuildPhase(w.ctx, sqlcgen.PutBuildPhaseParams{
			Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID, Position: int64(i),
			DurationInSeconds: nullableInteger(phase.DurationInSeconds), EndTime: nullableTime(phase.EndTime), PhaseStatus: nullableString(phase.PhaseStatus),
			PhaseType: nullableString(phase.PhaseType), StartTime: nullableTime(phase.StartTime), ContextsPresent: phase.Contexts != nil,
		}); err != nil {
			return err
		}
		for j, context := range phase.Contexts {
			if err := w.q.PutBuildPhaseContext(w.ctx, sqlcgen.PutBuildPhaseContextParams{
				Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID, PhasePosition: int64(i), Position: int64(j),
				Message: nullableString(context.Message), StatusCode: nullableString(context.StatusCode),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
