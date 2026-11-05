ALTER TABLE s3tables_objects ADD COLUMN checksum_crc64nvme TEXT NOT NULL DEFAULT '';
ALTER TABLE s3tables_multipart_parts ADD COLUMN checksum_crc64nvme TEXT NOT NULL DEFAULT '';
