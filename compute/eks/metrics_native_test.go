package eks

import (
	"encoding/json"
	"testing"
)

func TestNativeMetricsPreservesCustomerArgumentOwnership(t *testing.T) {
	const packaged = `{"metadata":{"resourceVersion":"7","annotations":{"objectset.rio.cattle.io/owner-gvk":"k3s.cattle.io/v1, Kind=Addon","objectset.rio.cattle.io/owner-name":"metrics-server-deployment","objectset.rio.cattle.io/owner-namespace":"kube-system"},"managedFields":[{"manager":"deploy@owned-server","fieldsV1":{"f:spec":{"f:template":{"f:spec":{"f:containers":{"k:{\"name\":\"metrics-server\"}":{"f:args":{}}}}}}}}]},"spec":{"template":{"spec":{"containers":[{"name":"metrics-server","args":["--kubelet-preferred-address-types=ExternalIP,InternalIP,Hostname","--metric-resolution=30s"]}]}}}}`
	for _, shared := range []bool{false, true} {
		name := "customer-replaces-native-owner"
		if shared {
			name = "customer-shares-identical-arguments"
		}
		t.Run(name, func(t *testing.T) {
			var deployment nativeMetricsDeployment
			if err := json.Unmarshal([]byte(packaged), &deployment); err != nil {
				t.Fatal(err)
			}
			customer := deployment.Metadata.ManagedFields[0]
			customer.Manager = "customer-controller"
			if shared {
				deployment.Metadata.ManagedFields = append(deployment.Metadata.ManagedFields, customer)
			} else {
				deployment.Metadata.ManagedFields[0] = customer
			}
			if patch := nativeMetricsAddressPatch(deployment, "owned-server"); patch != nil {
				t.Fatalf("customer scrape configuration would be overwritten: %v", patch)
			}
		})
	}
}
