package s3

import (
	"errors"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// The empty domain value is STANDARD; an explicitly empty request is invalid.
func parseStorageClass(requested *api.StorageClass) (string, *awswire.Error) {
	if requested == nil {
		return "", nil
	}
	name := string(*requested)
	switch name {
	case "STANDARD":
		return "", nil
	case "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER", "DEEP_ARCHIVE", "GLACIER_IR":
		return name, nil
	case "FSX_OPENZFS":
		return "", argumentError("x-amz-storage-class", name, "FSX_OPENZFS is not allowed.")
	default:
		wire := failure("InvalidStorageClass", "The storage class you specified is not valid", 400)
		wire.StorageClassRequested = &name
		return "", wire
	}
}

func storageClassName(class string) string {
	if class == "" {
		return "STANDARD"
	}
	return class
}

func isArchivedStorageClass(class string) bool {
	return class == "GLACIER" || class == "DEEP_ARCHIVE"
}

func storageClassRequestError(name string, err error) *awswire.Error {
	if name != "PutObject" && name != "CopyObject" && name != "CreateMultipartUpload" {
		return nil
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) && validation.Path == "StorageClass" && validation.Constraint == "enum" {
		_, wire := parseStorageClass(new(api.StorageClass(validation.EnumValue)))
		return wire
	}
	return nil
}

func requestedStorageClass(c *apiCall, conditions map[string][]string, requested *api.StorageClass) {
	if requested != nil {
		name := string(*requested)
		c.params["x-amz-storage-class"] = name
		conditions["s3:x-amz-storage-class"] = []string{name}
	}
}

func objectRestoreForRead(r Reader, record ObjectRecord) (*ObjectRestore, error) {
	if objectArchiveClass(&record) == "" {
		return nil, nil
	}
	return r.ObjectRestore(record.VersionKey())
}

func objectPayloadError(record ObjectRecord, restore *ObjectRestore, now time.Time, copySource bool) *awswire.Error {
	if objectArchiveClass(&record) == "" || objectRestored(restore, now) {
		return nil
	}
	message := "The operation is not valid for the object's storage class"
	if copySource {
		message = "Operation is not valid for the source object's storage class"
	}
	wire := failure("InvalidObjectState", message, 403)
	wire.StorageClass = record.StorageClass
	if record.Tiering != nil {
		wire.AccessTier = string(record.Tiering.ArchiveTier)
	}
	return wire
}
