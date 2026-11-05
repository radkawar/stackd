package s3tables

import (
	"context"

	"stackd/internal/awschecksum"

	"github.com/google/uuid"
)

// S3 Tables supports these five multipart operations, but not copy or public
// object deletion/listing. Every effect is fenced by current PutTableData IAM
// and the immutable warehouse/table identity at its physical commit boundary.
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/developing-s3-tables-APIs.html
func (s *Service) CreateMultipart(ctx context.Context, location string, attrs ObjectAttributes) (string, error) {
	warehouse, key, err := parseLocation(location)
	if err != nil {
		return "", err
	}
	lock := s.warehouseLock(warehouse)
	lock.Lock()
	defer lock.Unlock()
	table, err := s.dataTable(ctx, warehouse, "PutTableData")
	if err != nil {
		return "", err
	}
	if err = s.objectStorageAvailable(); err != nil {
		return "", err
	}
	if err = validateObjectAttributes(attrs); err != nil {
		return "", err
	}
	if attrs.Checksums != (ObjectChecksums{}) {
		return "", failure("InvalidRequest", "Multipart initiation accepts an algorithm, not a payload checksum", 400)
	}
	if attrs.ContentType == "" {
		attrs.ContentType = "application/octet-stream"
	}
	upload := MultipartUpload{ID: uuid.NewString(), Warehouse: warehouse, Key: key, Created: s.clock.Now().UTC(), Attributes: CloneObjectAttributes(attrs)}
	err = s.objects.CreateMultipart(ctx, upload, func(ctx context.Context) error { return s.recheckDataTable(ctx, table, "PutTableData") })
	if err != nil {
		return "", err
	}
	return upload.ID, nil
}
func (s *Service) UploadMultipartPart(ctx context.Context, location, id string, number int, data []byte, checksums ObjectChecksums) (MultipartPart, error) {
	warehouse, key, err := parseLocation(location)
	if err != nil {
		return MultipartPart{}, err
	}
	lock := s.warehouseLock(warehouse)
	lock.Lock()
	defer lock.Unlock()
	table, err := s.dataTable(ctx, warehouse, "PutTableData")
	if err != nil {
		return MultipartPart{}, err
	}
	if err = s.objectStorageAvailable(); err != nil {
		return MultipartPart{}, err
	}
	if number < 1 || number > MultipartMaximumParts {
		return MultipartPart{}, failure("InvalidArgument", "Part number must be between 1 and 10000", 400)
	}
	if int64(len(data)) > MultipartMaximumPartSize {
		return MultipartPart{}, failure("EntityTooLarge", "A part cannot exceed 5 GiB", 400)
	}
	upload, err := s.objects.GetMultipartUpload(ctx, warehouse, key, id)
	if err != nil {
		return MultipartPart{}, err
	}
	algorithm, err := checksumAlgorithm(checksums)
	if err != nil {
		return MultipartPart{}, err
	}
	if algorithm == "" && upload.Attributes.ChecksumAlgorithm == "CRC64NVME" {
		checksums.CRC64NVME, err = awschecksum.Sum("CRC64NVME", data)
		if err != nil {
			return MultipartPart{}, err
		}
		algorithm = "CRC64NVME"
	}
	if upload.Attributes.ChecksumAlgorithm != "" && algorithm != upload.Attributes.ChecksumAlgorithm {
		return MultipartPart{}, failure("InvalidRequest", "Every part must provide the checksum algorithm selected at initiation", 400)
	}
	info, err := SingleObjectInfo(key, data, ObjectAttributes{ChecksumAlgorithm: algorithm, Checksums: checksums}, s.clock.Now())
	if err != nil {
		return MultipartPart{}, err
	}
	part := MultipartPart{Number: number, ETag: info.ETag, Size: info.Size, Modified: info.Modified, Checksums: checksums}
	err = s.objects.UploadMultipartPart(ctx, warehouse, key, id, part, data, func(ctx context.Context) error { return s.recheckDataTable(ctx, table, "PutTableData") })
	if err != nil {
		return MultipartPart{}, err
	}
	return part, nil
}
func (s *Service) ListMultipartParts(ctx context.Context, location, id string) (MultipartUpload, []MultipartPart, error) {
	warehouse, key, err := parseLocation(location)
	if err != nil {
		return MultipartUpload{}, nil, err
	}
	lock := s.warehouseLock(warehouse)
	lock.Lock()
	defer lock.Unlock()
	table, err := s.dataTable(ctx, warehouse, "GetTableData")
	if err != nil {
		return MultipartUpload{}, nil, err
	}
	if err = s.objectStorageAvailable(); err != nil {
		return MultipartUpload{}, nil, err
	}
	upload, parts, err := s.objects.ListMultipartParts(ctx, warehouse, key, id)
	if err != nil {
		return MultipartUpload{}, nil, err
	}
	if err = s.recheckDataTable(ctx, table, "GetTableData"); err != nil {
		return MultipartUpload{}, nil, err
	}
	return upload, parts, nil
}
func (s *Service) CompleteMultipart(ctx context.Context, location, id string, parts []CompletedPart, conditions ObjectConditions, checksums ObjectChecksums) (ObjectInfo, error) {
	warehouse, key, err := parseLocation(location)
	if err != nil {
		return ObjectInfo{}, err
	}
	lock := s.warehouseLock(warehouse)
	lock.Lock()
	defer lock.Unlock()
	table, err := s.dataTable(ctx, warehouse, "PutTableData")
	if err != nil {
		return ObjectInfo{}, err
	}
	if err = s.objectStorageAvailable(); err != nil {
		return ObjectInfo{}, err
	}
	return s.objects.CompleteMultipart(ctx, warehouse, key, id, parts, s.clock.Now().UTC(), conditions, checksums, s.objectPublicationGuard(table))
}
func (s *Service) AbortMultipart(ctx context.Context, location, id string) error {
	warehouse, key, err := parseLocation(location)
	if err != nil {
		return err
	}
	lock := s.warehouseLock(warehouse)
	lock.Lock()
	defer lock.Unlock()
	table, err := s.dataTable(ctx, warehouse, "PutTableData")
	if err != nil {
		return err
	}
	if err = s.objectStorageAvailable(); err != nil {
		return err
	}
	return s.objects.AbortMultipart(ctx, warehouse, key, id, func(ctx context.Context) error { return s.recheckDataTable(ctx, table, "PutTableData") })
}
