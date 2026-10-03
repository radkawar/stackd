package codebuild

import (
	domain "stackd/storage/codebuild"
	"stackd/storage/sqlite/codebuild/internal/sqlcgen"
)

func (r reader) pipelineArtifacts(v *domain.BuildRecord) error {
	k := v.Key
	inputs, err := r.q.ListPipelineInputs(r.ctx, sqlcgen.ListPipelineInputsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID})
	if err != nil {
		return err
	}
	if len(inputs) != 0 {
		v.PipelineInputs = make([]domain.PipelineInput, len(inputs))
		for i, input := range inputs {
			v.PipelineInputs[i] = domain.PipelineInput{Name: input.ArtifactName, Location: input.Location, VersionID: input.VersionID, RevisionID: input.RevisionID}
		}
	}
	outputs, err := r.q.ListPipelineOutputs(r.ctx, sqlcgen.ListPipelineOutputsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID})
	if err != nil {
		return err
	}
	if len(outputs) != 0 {
		v.PipelineOutputs = make([]domain.PipelineOutput, len(outputs))
		for i, output := range outputs {
			v.PipelineOutputs[i] = domain.PipelineOutput{Name: output.ArtifactName, Location: output.Location, EncryptionKey: output.EncryptionKey}
		}
	}
	return nil
}

func (w writer) putPipelineArtifacts(v domain.BuildRecord) error {
	k := v.Key
	if err := w.q.DeletePipelineInputs(w.ctx, sqlcgen.DeletePipelineInputsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, input := range v.PipelineInputs {
		if err := w.q.PutPipelineInput(w.ctx, sqlcgen.PutPipelineInputParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID, Position: int64(i), ArtifactName: input.Name, Location: input.Location, VersionID: input.VersionID, RevisionID: input.RevisionID}); err != nil {
			return err
		}
	}
	if err := w.q.DeletePipelineOutputs(w.ctx, sqlcgen.DeletePipelineOutputsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, output := range v.PipelineOutputs {
		if err := w.q.PutPipelineOutput(w.ctx, sqlcgen.PutPipelineOutputParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID, Position: int64(i), ArtifactName: output.Name, Location: output.Location, EncryptionKey: output.EncryptionKey}); err != nil {
			return err
		}
	}
	return nil
}
