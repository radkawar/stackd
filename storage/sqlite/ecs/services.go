package ecs

import (
	api "stackd/internal/awsapi/ecs"
	domain "stackd/storage/ecs"
	"stackd/storage/sqlite/ecs/internal/sqlcgen"
)

func (r reader) Service(k domain.ServiceKey) (domain.ServiceRecord, error) {
	row, err := r.q.GetService(r.ctx, sqlcgen.GetServiceParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
	})
	if err != nil {
		return domain.ServiceRecord{}, missing(err)
	}
	return r.service(row)
}

func (r reader) Services(q domain.ServiceQuery) ([]domain.ServiceRecord, error) {
	rows, err := r.q.ListServices(r.ctx, sqlcgen.ListServicesParams{
		Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, ClusterName: q.Name,
		AfterName: q.After, IncludeInactive: flag(q.IncludeInactive), LaunchType: q.LaunchType,
		SchedulingStrategy: q.SchedulingStrategy, RowLimit: rowLimit(q.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ServiceRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.service(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) ActiveServiceKeys() ([]domain.ServiceKey, error) {
	rows, err := r.q.ListActiveServiceKeys(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.ServiceKey, len(rows))
	for i, row := range rows {
		out[i] = domain.ServiceKey{
			ClusterKey:  domain.ClusterKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.ClusterName},
			ServiceName: row.ServiceName,
		}
	}
	return out, nil
}

func (r reader) service(row sqlcgen.EcsService) (domain.ServiceRecord, error) {
	out, err := serviceRecord(row)
	if err != nil {
		return out, err
	}
	if !row.DeploymentsPresent {
		return out, nil
	}
	k := out.Key
	deployments, err := r.q.ListServiceDeployments(r.ctx, sqlcgen.ListServiceDeploymentsParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
	})
	if err != nil {
		return out, err
	}
	out.Deployments = make([]domain.ServiceDeployment, len(deployments))
	out.Data.Deployments = make(api.Deployments, len(deployments))
	for i, row := range deployments {
		deployment, err := serviceDeploymentRecord(row)
		if err != nil {
			return out, err
		}
		if row.ObservedTasksPresent {
			observed, err := r.q.ListServiceObservedTasks(r.ctx, sqlcgen.ListServiceObservedTasksParams{
				Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName, Position: row.Position,
			})
			if err != nil {
				return out, err
			}
			deployment.ObservedTasks = make(map[string]string, len(observed))
			for _, task := range observed {
				deployment.ObservedTasks[task.TaskID] = task.Status
			}
		}
		if row.ResolvedImagesPresent {
			images, err := r.q.ListServiceResolvedImages(r.ctx, sqlcgen.ListServiceResolvedImagesParams{
				Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName, Position: row.Position,
			})
			if err != nil {
				return out, err
			}
			deployment.ResolvedImages = make(map[string]string, len(images))
			for _, image := range images {
				deployment.ResolvedImages[image.ContainerName] = image.ImageReference
			}
		}
		out.Deployments[i] = deployment
		out.Data.Deployments[i] = api.CloneDeployment(deployment.Data)
	}
	return out, nil
}

func (w writer) PutService(v domain.ServiceRecord) error {
	params, err := serviceParams(v)
	if err != nil {
		return err
	}
	if err := w.q.PutService(w.ctx, params); err != nil {
		return err
	}
	k := v.Key
	// Replacing the owned rows also removes their observation and image children. All writes
	// use the caller's transaction, preserving atomic service and event admission.
	if err := w.q.DeleteServiceDeployments(w.ctx, sqlcgen.DeleteServiceDeploymentsParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
	}); err != nil {
		return err
	}
	for i, deployment := range v.Deployments {
		params, err := serviceDeploymentParams(k, i, deployment)
		if err != nil {
			return err
		}
		if err := w.q.PutServiceDeployment(w.ctx, params); err != nil {
			return err
		}
		for taskID, status := range deployment.ObservedTasks {
			if err := w.q.PutServiceObservedTask(w.ctx, sqlcgen.PutServiceObservedTaskParams{
				Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
				Position: int64(i), TaskID: taskID, Status: status,
			}); err != nil {
				return err
			}
		}
		for containerName, imageReference := range deployment.ResolvedImages {
			if err := w.q.PutServiceResolvedImage(w.ctx, sqlcgen.PutServiceResolvedImageParams{
				Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ClusterName: k.Name, ServiceName: k.ServiceName,
				Position: int64(i), ContainerName: containerName, ImageReference: imageReference,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
