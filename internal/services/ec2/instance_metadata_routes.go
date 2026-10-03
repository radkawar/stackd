package ec2

import (
	"context"
	"net/http"
	"slices"
	"strings"
)

func (s *Service) instanceMetadata(ctx context.Context, record InstanceRecord, path string, imdsv2 bool) ([]byte, string, int) {
	if path == "/" {
		return metadataText(instanceMetadataVersionListing)
	}
	version, route, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	categories, known := instanceMetadataCategories[version]
	if !known {
		return nil, "", http.StatusNotFound
	}
	if route == "" {
		return metadataText("dynamic\nmeta-data\nuser-data")
	}
	root, item, _ := strings.Cut(route, "/")
	switch root {
	case "user-data":
		if route == "user-data" && len(record.UserData) != 0 {
			return record.UserData, "application/octet-stream", http.StatusOK
		}
	case "dynamic":
		return s.instanceDynamicMetadata(ctx, record, version, item)
	case "meta-data":
		if item == "" {
			return s.instanceMetadataMenu(ctx, record, version)
		}
		category, _, _ := strings.Cut(item, "/")
		if !categories[category] || !metadataVersionAllows(version, "meta-data/"+item) {
			return nil, "", http.StatusNotFound
		}
		switch category {
		case "network":
			return s.instanceNetworkMetadata(ctx, record, version, item)
		case "placement":
			return instancePlacementMetadata(record, version, item)
		case "block-device-mapping":
			return instanceBlockDeviceMetadata(record, item)
		case "tags", "tag-sets":
			return instanceTagMetadata(record, item)
		case "public-keys":
			return instancePublicKeyMetadata(record, item)
		case "iam":
			return s.instanceProfileMetadata(ctx, record, item, imdsv2)
		case "identity-credentials":
			return s.instanceIntrinsicCredentialsMetadata(ctx, record, item, imdsv2)
		case "services":
			return instanceServicesMetadata(record, version, item)
		case "system":
			return instanceSystemMetadata(ctx, record, item)
		default:
			// TODO: Comeback add maintenance/Spot/Auto Scaling transitions
			// through their own owners.
			return instanceComputeMetadata(record, item)
		}
	}
	return nil, "", http.StatusNotFound
}

// Leaf introduction dates supplement the native top-level version menus. A
// network MAC or public-key index is normalized by its owner before this lookup.
func metadataVersionAllows(version, path string) bool {
	introduced := instanceMetadataIntroductions[path]
	return introduced == "" || introduced == "1.0" || version == "latest" || (version != "1.0" && version >= introduced)
}

func metadataDirectory(version, prefix string, names []string) ([]byte, string, int) {
	available := names[:0]
	for _, name := range names {
		if metadataVersionAllows(version, prefix+strings.TrimSuffix(name, "/")) {
			available = append(available, name)
		}
	}
	if len(available) == 0 {
		return nil, "", http.StatusNotFound
	}
	slices.Sort(available)
	return metadataText(strings.Join(available, "\n"))
}

func (s *Service) instanceMetadataMenu(ctx context.Context, r InstanceRecord, version string) ([]byte, string, int) {
	names := make([]string, 0, 32)
	for _, name := range []string{"ami-id", "ami-launch-index", "ami-manifest-path", "profile", "instance-action", "instance-id", "instance-life-cycle", "instance-type", "kernel-id", "ramdisk-id", "product-codes", "reservation-id", "hostname", "local-hostname", "local-ipv4", "public-hostname", "public-ipv4", "mac", "security-groups"} {
		if _, present := instanceComputeMetadataValue(r, name); present {
			names = append(names, name)
		}
	}
	if len(r.MetadataBlockDevices) != 0 {
		names = append(names, "block-device-mapping/")
	}
	if r.Data.Placement != nil {
		names = append(names, "placement/")
	}
	if len(r.Data.NetworkInterfaces) != 0 {
		names = append(names, "network/")
	}
	if r.PublicKey != "" {
		names = append(names, "public-keys/")
	}
	if r.Data.IamInstanceProfile != nil {
		names = append(names, "iam/")
	}
	if s.instanceIdentities != nil {
		names = append(names, "identity-credentials/")
	}
	if metadataTagsEnabled(r) {
		names = append(names, "tags/", "tag-sets/")
	}
	if r.Key.Scope.Partition == "aws" {
		names = append(names, "services/")
	}
	if instanceMetadataHypervisor(ctx, r) != "" {
		names = append(names, "system")
	}
	available := names[:0]
	for _, name := range names {
		if instanceMetadataCategories[version][strings.TrimSuffix(name, "/")] {
			available = append(available, name)
		}
	}
	return metadataDirectory(version, "meta-data/", available)
}
