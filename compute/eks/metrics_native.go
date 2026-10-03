package eks

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

const nativeMetricsManager = "stackd-native-metrics-server"
const nativeMetricsPath = "/apis/apps/v1/namespaces/kube-system/deployments/metrics-server"

type nativeMetricsDeployment struct {
	Metadata struct {
		componentMetadata
		ManagedFields []componentManagedFields `json:"managedFields"`
	} `json:"metadata"`
	Spec struct {
		Template struct {
			Spec struct {
				Containers []struct {
					Name string   `json:"name"`
					Args []string `json:"args"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

// The bootstrap worker's external address carries VXLAN, not its kubelet API.
// k3s nevertheless uses --flannel-external-ip to choose the packaged metrics
// Deployment's scrape preference. Correct that native-owned default at the
// Deployment authority, leaving customer-managed arguments and other fields alone.
func (c *nativeCluster) ensureNativeMetrics(ctx context.Context) error {
	if c.state.WorkerAdvertiseHost == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	for {
		var deployment nativeMetricsDeployment
		code, err := c.componentRequest(ctx, http.MethodGet, nativeMetricsPath, "", nil, &deployment)
		if code != http.StatusNotFound {
			if err != nil {
				return err
			}
			patch := nativeMetricsAddressPatch(deployment, "k3d-"+c.state.Name+"-server-0")
			if len(patch) == 0 {
				return nil
			}
			_, err = c.componentRequest(ctx, http.MethodPatch, nativeMetricsPath+"?fieldManager="+nativeMetricsManager, "application/json-patch+json", patch, nil)
			return err
		}
		// A ready API can precede the native packaged-add-on controller on a
		// fresh server. Wait for that owner to create its Deployment; never
		// fabricate a replacement Deployment or its serving/RBAC resources.
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("eks: waiting for packaged metrics-server: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func nativeMetricsAddressPatch(deployment nativeMetricsDeployment, server string) []map[string]any {
	metadata := deployment.Metadata
	if metadata.DeletionTimestamp != "" || metadata.ResourceVersion == "" || metadata.Annotations["objectset.rio.cattle.io/owner-gvk"] != "k3s.cattle.io/v1, Kind=Addon" || metadata.Annotations["objectset.rio.cattle.io/owner-name"] != "metrics-server-deployment" || metadata.Annotations["objectset.rio.cattle.io/owner-namespace"] != "kube-system" {
		return nil
	}
	owned := false
	for _, manager := range metadata.ManagedFields {
		if manager.Subresource != "" {
			continue
		}
		fields := manager.FieldsV1
		for _, key := range []string{"f:spec", "f:template", "f:spec", "f:containers", `k:{"name":"metrics-server"}`} {
			fields, _ = fields[key].(map[string]any)
		}
		if _, present := fields["f:args"]; !present {
			continue
		}
		if manager.Manager != "deploy@"+server && manager.Manager != nativeMetricsManager {
			return nil
		}
		owned = true
	}
	if !owned {
		return nil
	}
	for containerIndex, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name != "metrics-server" {
			continue
		}
		for argumentIndex, argument := range container.Args {
			if argument == "--kubelet-preferred-address-types=ExternalIP,InternalIP,Hostname" {
				return []map[string]any{
					{"op": "test", "path": "/metadata/resourceVersion", "value": metadata.ResourceVersion},
					{"op": "replace", "path": fmt.Sprintf("/spec/template/spec/containers/%d/args/%d", containerIndex, argumentIndex), "value": "--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname"},
				}
			}
		}
	}
	return nil
}
