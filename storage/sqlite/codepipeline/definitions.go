package codepipeline

import (
	"database/sql"
	"errors"
	api "stackd/internal/awsapi/codepipeline"
	domain "stackd/storage/codepipeline"
	"stackd/storage/sqlite/codepipeline/internal/sqlcgen"
)

func (r reader) Definition(sc domain.Scope, id string, version int32) (domain.Definition, bool, error) {
	row, err := r.q.GetDefinition(r.ctx, sqlcgen.GetDefinitionParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Incarnation: id, Version: int64(version)})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Definition{}, false, nil
	}
	if err != nil {
		return domain.Definition{}, false, err
	}
	d := api.PipelineDeclaration{Name: new(api.PipelineName(row.Name)), RoleArn: new(api.RoleArn(row.RoleArn)), Version: new(api.PipelineVersion(row.Version)), ExecutionMode: new(api.ExecutionMode(row.ExecutionMode)), PipelineType: new(api.PipelineType(row.PipelineType)), ArtifactStore: &api.ArtifactStore{Type: new(api.ArtifactStoreType("S3")), Location: new(api.ArtifactStoreLocation(row.ArtifactBucket))}}
	if row.VariablesPresent != 0 {
		d.Variables = api.PipelineVariableDeclarationList{}
	}
	if row.EncryptionKey != "" {
		d.ArtifactStore.EncryptionKey = &api.EncryptionKey{Id: new(api.EncryptionKeyId(row.EncryptionKey)), Type: new(api.EncryptionKeyType(row.EncryptionType))}
	}
	variables, err := r.q.ListVariableDeclarations(r.ctx, sqlcgen.ListVariableDeclarationsParams{Incarnation: id, Version: int64(version)})
	if err != nil {
		return domain.Definition{}, false, err
	}
	for _, variable := range variables {
		declaration := api.PipelineVariableDeclaration{Name: new(api.PipelineVariableName(variable.Name))}
		if variable.DefaultValue.Valid {
			declaration.DefaultValue = new(api.PipelineVariableValue(variable.DefaultValue.String))
		}
		if variable.Description.Valid {
			declaration.Description = new(api.PipelineVariableDescription(variable.Description.String))
		}
		d.Variables = append(d.Variables, declaration)
	}
	stages, err := r.q.ListStages(r.ctx, sqlcgen.ListStagesParams{Incarnation: id, Version: int64(version)})
	if err != nil {
		return domain.Definition{}, false, err
	}
	for _, s := range stages {
		d.Stages = append(d.Stages, api.StageDeclaration{Name: new(api.StageName(s.Name)), Actions: api.StageActionDeclarationList{}})
	}
	actions, err := r.q.ListActions(r.ctx, sqlcgen.ListActionsParams{Incarnation: id, Version: int64(version)})
	if err != nil {
		return domain.Definition{}, false, err
	}
	for _, a := range actions {
		decl := api.ActionDeclaration{Name: new(api.ActionName(a.Name)), ActionTypeId: &api.ActionTypeId{Category: new(api.ActionCategory(a.Category)), Owner: new(api.ActionOwner(a.Owner)), Provider: new(api.ActionProvider(a.Provider)), Version: new(api.Version(a.ActionVersion))}, RoleArn: optional[api.RoleArn](a.RoleArn), Region: optional[api.AWSRegionName](a.Region), Namespace: optional[api.ActionNamespace](a.Namespace), RunOrder: new(api.ActionRunOrder(a.RunOrder)), Configuration: api.ActionConfigurationMap{}, InputArtifacts: api.InputArtifactList{}, OutputArtifacts: api.OutputArtifactList{}}
		if a.TimeoutMinutes != 0 {
			decl.TimeoutInMinutes = new(api.ActionTimeout(a.TimeoutMinutes))
		}
		d.Stages[a.StageIndex].Actions = append(d.Stages[a.StageIndex].Actions, decl)
	}
	configuration, err := r.q.ListConfiguration(r.ctx, sqlcgen.ListConfigurationParams{Incarnation: id, Version: int64(version)})
	if err != nil {
		return domain.Definition{}, false, err
	}
	for _, c := range configuration {
		d.Stages[c.StageIndex].Actions[c.ActionIndex].Configuration[api.ActionConfigurationKey(c.ConfigKey)] = api.ActionConfigurationValue(c.ConfigValue)
	}
	artifacts, err := r.q.ListDeclarations(r.ctx, sqlcgen.ListDeclarationsParams{Incarnation: id, Version: int64(version)})
	if err != nil {
		return domain.Definition{}, false, err
	}
	for _, a := range artifacts {
		decl := &d.Stages[a.StageIndex].Actions[a.ActionIndex]
		if a.Direction == "input" {
			decl.InputArtifacts = append(decl.InputArtifacts, api.InputArtifact{Name: new(api.ArtifactName(a.Name))})
		} else {
			decl.OutputArtifacts = append(decl.OutputArtifacts, api.OutputArtifact{Name: new(api.ArtifactName(a.Name))})
		}
	}
	return domain.Definition{Scope: sc, Incarnation: id, Declaration: d}, true, nil
}
func (w writer) PutDefinition(v domain.Definition) error {
	d := v.Declaration
	version := int64(value(d.Version))
	row := sqlcgen.PutDefinitionsParams{Incarnation: v.Incarnation, Version: version, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Name: text(d.Name), RoleArn: text(d.RoleArn), ExecutionMode: text(d.ExecutionMode), PipelineType: text(d.PipelineType), ArtifactBucket: text(d.ArtifactStore.Location)}
	row.VariablesPresent = flag(d.Variables != nil)
	if k := d.ArtifactStore.EncryptionKey; k != nil {
		row.EncryptionKey = text(k.Id)
		row.EncryptionType = text(k.Type)
	}
	if err := w.q.PutDefinitions(w.ctx, row); err != nil {
		return err
	}
	if err := w.q.DeleteVariableDeclarations(w.ctx, sqlcgen.DeleteVariableDeclarationsParams{Incarnation: v.Incarnation, Version: version}); err != nil {
		return err
	}
	for i, variable := range d.Variables {
		if err := w.q.PutVariableDeclarations(w.ctx, sqlcgen.PutVariableDeclarationsParams{
			Incarnation: v.Incarnation, Version: version, Position: int64(i), Name: text(variable.Name),
			DefaultValue: sql.NullString{String: text(variable.DefaultValue), Valid: variable.DefaultValue != nil},
			Description:  sql.NullString{String: text(variable.Description), Valid: variable.Description != nil},
		}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteStages(w.ctx, sqlcgen.DeleteStagesParams{Incarnation: v.Incarnation, Version: version}); err != nil {
		return err
	}
	if err := w.q.DeleteActions(w.ctx, sqlcgen.DeleteActionsParams{Incarnation: v.Incarnation, Version: version}); err != nil {
		return err
	}
	if err := w.q.DeleteConfiguration(w.ctx, sqlcgen.DeleteConfigurationParams{Incarnation: v.Incarnation, Version: version}); err != nil {
		return err
	}
	if err := w.q.DeleteDeclarations(w.ctx, sqlcgen.DeleteDeclarationsParams{Incarnation: v.Incarnation, Version: version}); err != nil {
		return err
	}
	for i, stage := range d.Stages {
		if err := w.q.PutStages(w.ctx, sqlcgen.PutStagesParams{Incarnation: v.Incarnation, Version: version, StageIndex: int64(i), Name: text(stage.Name)}); err != nil {
			return err
		}
		for j, a := range stage.Actions {
			if err := w.q.PutActions(w.ctx, sqlcgen.PutActionsParams{Incarnation: v.Incarnation, Version: version, StageIndex: int64(i), ActionIndex: int64(j), Name: text(a.Name), Category: text(a.ActionTypeId.Category), Owner: text(a.ActionTypeId.Owner), Provider: text(a.ActionTypeId.Provider), ActionVersion: text(a.ActionTypeId.Version), RoleArn: text(a.RoleArn), Region: text(a.Region), Namespace: text(a.Namespace), RunOrder: int64(value(a.RunOrder)), TimeoutMinutes: int64(value(a.TimeoutInMinutes))}); err != nil {
				return err
			}
			for k, c := range a.Configuration {
				if err := w.q.PutConfiguration(w.ctx, sqlcgen.PutConfigurationParams{Incarnation: v.Incarnation, Version: version, StageIndex: int64(i), ActionIndex: int64(j), ConfigKey: string(k), ConfigValue: string(c)}); err != nil {
					return err
				}
			}
			for n, input := range a.InputArtifacts {
				if err := w.q.PutDeclarations(w.ctx, sqlcgen.PutDeclarationsParams{Incarnation: v.Incarnation, Version: version, StageIndex: int64(i), ActionIndex: int64(j), Direction: "input", Position: int64(n), Name: text(input.Name)}); err != nil {
					return err
				}
			}
			for n, output := range a.OutputArtifacts {
				if err := w.q.PutDeclarations(w.ctx, sqlcgen.PutDeclarationsParams{Incarnation: v.Incarnation, Version: version, StageIndex: int64(i), ActionIndex: int64(j), Direction: "output", Position: int64(n), Name: text(output.Name)}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
