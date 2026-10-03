package ec2

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// AWS refreshes EBS metadata at launch/start, not on hot attach or detach. The
// lifecycle owner retains this ordered device snapshot separately from current
// attachment state; an absent snapshot must not be reconstructed from live EBS.
func instanceBlockDeviceMetadata(r InstanceRecord, item string) ([]byte, string, int) {
	if len(r.MetadataBlockDevices) == 0 {
		return nil, "", http.StatusNotFound
	}
	root := str(r.Data.RootDeviceName)
	if item == "block-device-mapping" {
		names := []string{"ami", "root"}
		index := 1
		for _, device := range r.MetadataBlockDevices {
			if device != root {
				names = append(names, "ebs"+strconv.Itoa(index))
				index++
			}
		}
		slices.Sort(names)
		return metadataText(strings.Join(names, "\n"))
	}
	switch item {
	case "block-device-mapping/ami":
		return metadataText(strings.TrimPrefix(root, "/dev/"))
	case "block-device-mapping/root":
		return metadataText(root)
	}
	index := 1
	for _, device := range r.MetadataBlockDevices {
		if device == root {
			continue
		}
		if item == "block-device-mapping/ebs"+strconv.Itoa(index) {
			return metadataText(strings.TrimPrefix(device, "/dev/"))
		}
		index++
	}
	return nil, "", http.StatusNotFound
}

func instancePublicKeyMetadata(r InstanceRecord, item string) ([]byte, string, int) {
	if r.PublicKey == "" {
		return nil, "", http.StatusNotFound
	}
	switch item {
	case "public-keys":
		return metadataText("0=" + str(r.Data.KeyName))
	case "public-keys/0":
		return metadataText("openssh-key")
	case "public-keys/0/openssh-key":
		// PublicKey is the launch-time owner snapshot. Native EC2 uses the
		// key-pair name as its OpenSSH comment, not the import's comment.
		fields := strings.Fields(r.PublicKey)
		if len(fields) >= 2 {
			return metadataText(fields[0] + " " + fields[1] + " " + str(r.Data.KeyName) + "\n")
		}
	}
	return nil, "", http.StatusNotFound
}

func metadataTagsEnabled(r InstanceRecord) bool {
	return r.Data.MetadataOptions != nil && str(r.Data.MetadataOptions.InstanceMetadataTags) == "enabled"
}

func instanceTagMetadata(r InstanceRecord, item string) ([]byte, string, int) {
	// AWS documents tag updates while running, but no publication deadline or
	// minimum stale interval. Publish the tag owner's committed state directly;
	// a bounded stale observation does not justify a second state or fixed delay.
	if !metadataTagsEnabled(r) {
		return nil, "", http.StatusNotFound
	}
	// Empty tag sets remain available as JSON, but native hierarchical tag
	// reads return 404 when no instance tags exist.
	if len(r.Data.Tags) == 0 && (item == "tags" || strings.HasPrefix(item, "tags/")) {
		return nil, "", http.StatusNotFound
	}
	switch item {
	case "tags":
		return metadataText("instance/")
	case "tag-sets":
		return metadataText("instance")
	case "tag-sets/instance":
		tags := make(map[string]string, len(r.Data.Tags))
		for _, tag := range r.Data.Tags {
			tags[str(tag.Key)] = str(tag.Value)
		}
		body, err := json.Marshal(tags)
		if err != nil {
			return nil, "", http.StatusInternalServerError
		}
		return body, "text/plain", http.StatusOK
	case "tags/instance":
		keys := make([]string, 0, len(r.Data.Tags))
		for _, tag := range r.Data.Tags {
			keys = append(keys, str(tag.Key))
		}
		slices.Sort(keys)
		return metadataText(strings.Join(keys, "\n"))
	}
	for _, tag := range r.Data.Tags {
		if item == "tags/instance/"+str(tag.Key) {
			return metadataText(str(tag.Value))
		}
	}
	return nil, "", http.StatusNotFound
}
