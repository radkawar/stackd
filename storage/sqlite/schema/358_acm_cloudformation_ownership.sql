-- Public request tokens and mutable tags cannot assert certificate ownership.
ALTER TABLE acm_certificates ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX acm_certificates_cfn_owner ON acm_certificates(partition, account_id, region, cfn_owner) WHERE cfn_owner <> '';
