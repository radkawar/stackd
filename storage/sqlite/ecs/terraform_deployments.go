package ecs

import (
	"database/sql"
	"fmt"

	api "stackd/internal/awsapi/ecs"
	domain "stackd/storage/ecs"
	"stackd/storage/sqlite/ecs/internal/sqlcgen"
)

// These hooks run inside the same caller transaction as native deployment rows.
// History owns only read snapshots; FinishedAt is a native transition scalar.
func (r reader) readTerraformDeployments(out *domain.ServiceRecord) error {
	k := out.Key
	finishes, err := r.q.ListServiceDeploymentFinishTimes(r.ctx, sqlcgen.ListServiceDeploymentFinishTimesParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
	})
	if err != nil {
		return err
	}
	for _, finish := range finishes {
		if finish.Position < 0 || finish.Position >= int64(len(out.Deployments)) {
			return fmt.Errorf("ECS deployment finish position %d outside retained deployments", finish.Position)
		}
		if finish.FinishedAt.Valid {
			out.Deployments[finish.Position].FinishedAt = finish.FinishedAt.Time
		}
	}
	present, err := r.q.GetServiceDeploymentHistoryPresence(r.ctx, sqlcgen.GetServiceDeploymentHistoryPresenceParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
	})
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	rows, err := r.q.ListServiceDeploymentHistory(r.ctx, sqlcgen.ListServiceDeploymentHistoryParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
	})
	if err != nil {
		return err
	}
	out.DeploymentHistory = make(api.ServiceDeployments, len(rows))
	for i, row := range rows {
		deployment := api.ServiceDeployment{
			ServiceDeploymentArn: stringPointer[api.String](row.ServiceDeploymentArn), ServiceArn: stringPointer[api.String](row.ServiceArn), ClusterArn: stringPointer[api.String](row.ClusterArn),
			CreatedAt: timePointer(row.CreatedAt), StartedAt: timePointer(row.StartedAt), UpdatedAt: timePointer(row.UpdatedAt),
			FinishedAt: timePointer(row.FinishedAt), StoppedAt: timePointer(row.StoppedAt),
			Status: stringPointer[api.ServiceDeploymentStatus](row.Status), StatusReason: stringPointer[api.String](row.StatusReason),
		}
		if err := unmarshalFields(jsonReadField{row.TargetServiceRevision, &deployment.TargetServiceRevision}); err != nil {
			return err
		}
		out.DeploymentHistory[i] = deployment
	}
	return nil
}

func (w writer) writeTerraformDeployments(record domain.ServiceRecord) error {
	k := record.Key
	for i, deployment := range record.Deployments {
		var finished sql.NullTime
		if !deployment.FinishedAt.IsZero() {
			finished = sql.NullTime{Time: deployment.FinishedAt, Valid: true}
		}
		if err := w.q.SetServiceDeploymentFinishedAt(w.ctx, sqlcgen.SetServiceDeploymentFinishedAtParams{
			Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
			Position: int64(i), FinishedAt: finished,
		}); err != nil {
			return err
		}
	}
	if err := w.q.SetServiceDeploymentHistoryPresence(w.ctx, sqlcgen.SetServiceDeploymentHistoryPresenceParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
		DeploymentHistoryPresent: record.DeploymentHistory != nil,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteServiceDeploymentHistory(w.ctx, sqlcgen.DeleteServiceDeploymentHistoryParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
	}); err != nil {
		return err
	}
	for i, deployment := range record.DeploymentHistory {
		params := sqlcgen.PutServiceDeploymentHistoryParams{
			Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName, Position: int64(i),
			ServiceDeploymentArn: nullableString(deployment.ServiceDeploymentArn), ServiceArn: nullableString(deployment.ServiceArn), ClusterArn: nullableString(deployment.ClusterArn),
			CreatedAt: nullableTime(deployment.CreatedAt), StartedAt: nullableTime(deployment.StartedAt), UpdatedAt: nullableTime(deployment.UpdatedAt),
			FinishedAt: nullableTime(deployment.FinishedAt), StoppedAt: nullableTime(deployment.StoppedAt),
			Status: nullableString(deployment.Status), StatusReason: nullableString(deployment.StatusReason),
		}
		if err := marshalFields(jsonWriteField{&params.TargetServiceRevision, deployment.TargetServiceRevision}); err != nil {
			return err
		}
		if err := w.q.PutServiceDeploymentHistory(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}
