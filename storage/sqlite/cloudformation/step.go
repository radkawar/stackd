package cloudformation

import (
	domain "stackd/storage/cloudformation"
	"stackd/storage/sqlite/cloudformation/internal/sqlcgen"
)

func decodeStep(row sqlcgen.CloudformationStep) (domain.StepRecord, error) {
	out := domain.StepRecord{Position: int(row.Position), LogicalID: row.LogicalID, Action: row.Action, State: row.State, Error: row.Error, DeleteFailures: int(row.DeleteFailures), BeforeDeleteStarted: row.BeforeDeleteStarted, BeforeDeleted: row.BeforeDeleted, AdmissionPending: row.AdmissionPending}
	var err error
	out.Before, err = decodeResource(sqlcgen.CloudformationResource{
		StackID:             row.BeforeStackID,
		LogicalID:           row.BeforeLogicalID,
		Type:                row.BeforeType,
		PhysicalID:          row.BeforePhysicalID,
		Ref:                 row.BeforeRef,
		Token:               row.BeforeToken,
		Generation:          row.BeforeGeneration,
		Current:             row.BeforeCurrent,
		Status:              row.BeforeStatus,
		StatusReason:        row.BeforeStatusReason,
		DeletionPolicy:      row.BeforeDeletionPolicy,
		UpdateReplacePolicy: row.BeforeUpdateReplacePolicy,
		Properties:          row.BeforeProperties,
		EventProperties:     row.BeforeEventProperties,
		DynamicReferences:   row.BeforeDynamicReferences,
		Attributes:          row.BeforeAttributes,
		RedactedAttributes:  row.BeforeRedactedAttributes,
		Updated:             row.BeforeUpdated,
	})
	if err != nil {
		return out, err
	}
	out.After, err = decodeResource(sqlcgen.CloudformationResource{
		StackID:             row.AfterStackID,
		LogicalID:           row.AfterLogicalID,
		Type:                row.AfterType,
		PhysicalID:          row.AfterPhysicalID,
		Ref:                 row.AfterRef,
		Token:               row.AfterToken,
		Generation:          row.AfterGeneration,
		Current:             row.AfterCurrent,
		Status:              row.AfterStatus,
		StatusReason:        row.AfterStatusReason,
		DeletionPolicy:      row.AfterDeletionPolicy,
		UpdateReplacePolicy: row.AfterUpdateReplacePolicy,
		Properties:          row.AfterProperties,
		EventProperties:     row.AfterEventProperties,
		DynamicReferences:   row.AfterDynamicReferences,
		Attributes:          row.AfterAttributes,
		RedactedAttributes:  row.AfterRedactedAttributes,
		Updated:             row.AfterUpdated,
	})
	if err != nil {
		return out, err
	}
	out.Restore, err = decodeResource(sqlcgen.CloudformationResource{
		StackID:             row.RestoreStackID,
		LogicalID:           row.RestoreLogicalID,
		Type:                row.RestoreType,
		PhysicalID:          row.RestorePhysicalID,
		Ref:                 row.RestoreRef,
		Token:               row.RestoreToken,
		Generation:          row.RestoreGeneration,
		Current:             row.RestoreCurrent,
		Status:              row.RestoreStatus,
		StatusReason:        row.RestoreStatusReason,
		DeletionPolicy:      row.RestoreDeletionPolicy,
		UpdateReplacePolicy: row.RestoreUpdateReplacePolicy,
		Properties:          row.RestoreProperties,
		EventProperties:     row.RestoreEventProperties,
		DynamicReferences:   row.RestoreDynamicReferences,
		Attributes:          row.RestoreAttributes,
		RedactedAttributes:  row.RestoreRedactedAttributes,
		Updated:             row.RestoreUpdated,
	})
	if err != nil {
		return out, err
	}
	return out, nil
}

func encodeStep(parent string, ordinal int, v domain.StepRecord) (sqlcgen.PutStepParams, error) {
	p := sqlcgen.PutStepParams{ParentID: parent, Ordinal: int64(ordinal), Position: int64(v.Position), LogicalID: v.LogicalID, Action: v.Action, State: v.State, Error: v.Error, DeleteFailures: int64(v.DeleteFailures), BeforeDeleteStarted: v.BeforeDeleteStarted, BeforeDeleted: v.BeforeDeleted, AdmissionPending: v.AdmissionPending}
	before, err := encodeResource(v.Before)
	if err != nil {
		return p, err
	}
	p.BeforeStackID = before.StackID
	p.BeforeLogicalID = before.LogicalID
	p.BeforeType = before.Type
	p.BeforePhysicalID = before.PhysicalID
	p.BeforeRef = before.Ref
	p.BeforeToken = before.Token
	p.BeforeGeneration = before.Generation
	p.BeforeCurrent = before.Current
	p.BeforeStatus = before.Status
	p.BeforeStatusReason = before.StatusReason
	p.BeforeDeletionPolicy = before.DeletionPolicy
	p.BeforeUpdateReplacePolicy = before.UpdateReplacePolicy
	p.BeforeProperties = before.Properties
	p.BeforeEventProperties = before.EventProperties
	p.BeforeDynamicReferences = before.DynamicReferences
	p.BeforeAttributes = before.Attributes
	p.BeforeRedactedAttributes = before.RedactedAttributes
	p.BeforeUpdated = before.Updated
	after, err := encodeResource(v.After)
	if err != nil {
		return p, err
	}
	p.AfterStackID = after.StackID
	p.AfterLogicalID = after.LogicalID
	p.AfterType = after.Type
	p.AfterPhysicalID = after.PhysicalID
	p.AfterRef = after.Ref
	p.AfterToken = after.Token
	p.AfterGeneration = after.Generation
	p.AfterCurrent = after.Current
	p.AfterStatus = after.Status
	p.AfterStatusReason = after.StatusReason
	p.AfterDeletionPolicy = after.DeletionPolicy
	p.AfterUpdateReplacePolicy = after.UpdateReplacePolicy
	p.AfterProperties = after.Properties
	p.AfterEventProperties = after.EventProperties
	p.AfterDynamicReferences = after.DynamicReferences
	p.AfterAttributes = after.Attributes
	p.AfterRedactedAttributes = after.RedactedAttributes
	p.AfterUpdated = after.Updated
	restore, err := encodeResource(v.Restore)
	if err != nil {
		return p, err
	}
	p.RestoreStackID = restore.StackID
	p.RestoreLogicalID = restore.LogicalID
	p.RestoreType = restore.Type
	p.RestorePhysicalID = restore.PhysicalID
	p.RestoreRef = restore.Ref
	p.RestoreToken = restore.Token
	p.RestoreGeneration = restore.Generation
	p.RestoreCurrent = restore.Current
	p.RestoreStatus = restore.Status
	p.RestoreStatusReason = restore.StatusReason
	p.RestoreDeletionPolicy = restore.DeletionPolicy
	p.RestoreUpdateReplacePolicy = restore.UpdateReplacePolicy
	p.RestoreProperties = restore.Properties
	p.RestoreEventProperties = restore.EventProperties
	p.RestoreDynamicReferences = restore.DynamicReferences
	p.RestoreAttributes = restore.Attributes
	p.RestoreRedactedAttributes = restore.RedactedAttributes
	p.RestoreUpdated = restore.Updated
	return p, nil
}
