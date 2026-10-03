-- Account permissions are owner grants, independent of caller IAM authority.
CREATE TABLE ssm_document_shares (
    document_id INTEGER NOT NULL REFERENCES ssm_documents(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    version_selector TEXT NOT NULL CHECK (version_selector IN ('$DEFAULT', '$LATEST', '$ALL')),
    PRIMARY KEY (document_id, account_id)
);
CREATE INDEX ssm_document_shares_recipient ON ssm_document_shares(account_id, document_id);
