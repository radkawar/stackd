-- Signer profile provenance is native private authority, independent of tags.
ALTER TABLE signer_profiles ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
