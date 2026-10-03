package ec2

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	api "stackd/internal/awsapi/ec2"
)

func (s *Service) instanceDynamicMetadata(ctx context.Context, r InstanceRecord, version, item string) ([]byte, string, int) {
	if !instanceDynamicCategories[version]["instance-identity"] {
		return nil, "", http.StatusNotFound
	}
	if item == "" {
		return metadataText("instance-identity/")
	}
	category, leaf, _ := strings.Cut(item, "/")
	if category == "instance-identity" && metadataVersionAllows(version, "dynamic/"+item) {
		return s.instanceIdentityMetadata(ctx, r, leaf)
	}
	// fws/instance-monitoring is documented, but native Nitro probes return
	// 404 even though the retained instance has Monitoring.State=disabled.
	return nil, "", http.StatusNotFound
}

// instanceIdentityDocument is the sole byte representation used by the public
// document and its signatures. It reads only the retained instance projection:
// deregistering an AMI or deleting a key pair cannot rewrite this identity.
func instanceIdentityDocument(r InstanceRecord) ([]byte, error) {
	d := r.Data
	document := struct {
		AccountID               string      `json:"accountId"`
		Architecture            string      `json:"architecture"`
		AvailabilityZone        string      `json:"availabilityZone"`
		BillingProducts         []string    `json:"billingProducts"`
		DevpayProductCodes      []string    `json:"devpayProductCodes"`
		MarketplaceProductCodes []string    `json:"marketplaceProductCodes"`
		ImageID                 string      `json:"imageId"`
		InstanceID              string      `json:"instanceId"`
		InstanceType            string      `json:"instanceType"`
		KernelID                *api.String `json:"kernelId"`
		PendingTime             string      `json:"pendingTime"`
		PrivateIP               string      `json:"privateIp"`
		RamdiskID               *api.String `json:"ramdiskId"`
		Region                  string      `json:"region"`
		Version                 string      `json:"version"`
	}{
		AccountID: r.Key.Scope.AccountID, Architecture: str(d.Architecture),
		ImageID: str(d.ImageId), InstanceID: r.Key.ID, InstanceType: str(d.InstanceType),
		KernelID: d.KernelId, PrivateIP: str(d.PrivateIpAddress), RamdiskID: d.RamdiskId,
		Region: r.Key.Scope.Region, Version: "2017-09-30",
	}
	if d.Placement != nil {
		document.AvailabilityZone = str(d.Placement.AvailabilityZone)
	}
	if d.LaunchTime != nil {
		document.PendingTime = time.Time(*d.LaunchTime).UTC().Format(time.RFC3339)
	}
	for _, product := range d.ProductCodes {
		if str(product.ProductCodeType) == "marketplace" {
			document.MarketplaceProductCodes = append(document.MarketplaceProductCodes, str(product.ProductCodeId))
		}
	}
	return json.MarshalIndent(document, "", "  ")
}
