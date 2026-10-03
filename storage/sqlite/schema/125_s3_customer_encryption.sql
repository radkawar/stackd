ALTER TABLE s3_buckets ADD COLUMN sse_customer_blocked BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE s3_object_versions ADD COLUMN multipart_checksum_explicit BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE s3_object_version_data ADD COLUMN customer_key_salt BLOB NOT NULL DEFAULT X'';
ALTER TABLE s3_object_version_data ADD COLUMN customer_key_hash BLOB NOT NULL DEFAULT X'';
ALTER TABLE s3_object_version_data ADD COLUMN customer_key_md5 TEXT NOT NULL DEFAULT '';

ALTER TABLE s3_multipart_upload_encryption_keys ADD COLUMN customer_key_salt BLOB NOT NULL DEFAULT X'';
ALTER TABLE s3_multipart_upload_encryption_keys ADD COLUMN customer_key_hash BLOB NOT NULL DEFAULT X'';
ALTER TABLE s3_multipart_upload_encryption_keys ADD COLUMN customer_key_md5 TEXT NOT NULL DEFAULT '';
