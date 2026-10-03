-- Creation outcomes outlive their resources: deleting a route table or network
-- ACL must not permit a client token to allocate another resource.
CREATE TABLE ec2_network_creations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 action TEXT NOT NULL,
 token TEXT NOT NULL,
 vpc_id TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, action, token)
);

CREATE TABLE ec2_network_creation_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 action TEXT NOT NULL,
 token TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, action, token, position),
 FOREIGN KEY (partition, account_id, region, action, token) REFERENCES ec2_network_creations (partition, account_id, region, action, token) ON DELETE CASCADE
);
