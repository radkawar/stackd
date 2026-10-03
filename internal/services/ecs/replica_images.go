package ecs

import (
	"context"
	"strings"

	runtime "stackd/compute/ecs"
)

// Deployment image selection changes executable inputs, not the admitted
// definition or the public container image. A repository digest synthesized from
// a mutable local tag can disappear when that tag is reassigned.
func (s *Service) applyReplicaImages(ctx context.Context, task TaskRecord, spec *runtime.Specification) error {
	if task.ServiceName == "" {
		return nil
	}
	return s.repository.View(ctx, func(r Reader) error {
		service, err := r.Service(ServiceKey{ClusterKey: task.Key.ClusterKey, ServiceName: task.ServiceName})
		if err != nil {
			return err
		}
		for _, deployment := range service.Deployments {
			if value(deployment.Data.Id) != task.ServiceDeploymentID {
				continue
			}
			for i := range spec.Containers {
				container := &spec.Containers[i]
				if image := deployment.ResolvedImages[container.Name]; image != "" {
					container.Image = image
				}
			}
			break
		}
		return nil
	})
}

// Retain the actual immutable engine image ID in the task-observation transaction.
// ImageDigest remains the separate public registry digest reported by the engine.
func retainReplicaImages(tx Transaction, task TaskRecord, status []runtime.ContainerStatus) error {
	if task.ServiceName == "" {
		return nil
	}
	service, err := tx.Service(ServiceKey{ClusterKey: task.Key.ClusterKey, ServiceName: task.ServiceName})
	if err != nil {
		return err
	}
	for i := range service.Deployments {
		deployment := &service.Deployments[i]
		if value(deployment.Data.Id) != task.ServiceDeploymentID {
			continue
		}
		changed := false
		for _, container := range deployment.Definition.ContainerDefinitions {
			name := value(container.Name)
			if value(container.VersionConsistency) == "disabled" || strings.Contains(value(container.Image), "@") || deployment.ResolvedImages[name] != "" {
				continue
			}
			for _, observed := range status {
				if observed.Name != name || observed.ImageID == "" {
					continue
				}
				if deployment.ResolvedImages == nil {
					deployment.ResolvedImages = map[string]string{}
				}
				deployment.ResolvedImages[name] = observed.ImageID
				changed = true
				break
			}
		}
		if changed {
			return tx.PutService(service)
		}
		break
	}
	return nil
}
