# Native ElastiCache fixture

This fixture declares a Valkey primary and an actual read-only replica in an explicit EC2-backed subnet group. Each native node uses its reserved private IPv4 address, actual subnet/AZ and configured port `6379`; no loopback endpoint, invented availability zone or primary-as-reader substitution is used.

## Terraform endpoint fields

With the pinned AWS provider `6.68.0`, the top-level `port` on the `aws_elasticache_cluster` **datasource** is populated only from the AWS `ConfigurationEndpoint`. It is not the node listener port for this Valkey scenario; this distinction does not redefine the separately modeled cache-cluster resource's port. The fixture retains both cluster datasources and reads each node's actual `cache_nodes[0].port`; the primary and reader addresses come from the replication-group datasource and are checked against each corresponding datasource's `cache_nodes[0].address`. Protocol consumers assert fixed `6379`, distinct node addresses and actual read-only replication rather than substituting a constant or adding a nonexistent configuration endpoint.

Provider source: [cluster_data_source.go, v6.68.0](https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/v6.68.0/internal/service/elasticache/cluster_data_source.go).

## Native security boundaries

Managed nodes bind only their reserved address and wait on a fresh private-IPC admission marker before starting their listener. Current EC2 packet policy must be installed first. Named-user ACLs and the disabled passwordless default user remain unchanged. Managed Valkey disables its separate protected-mode guard because that guard rejects non-loopback connections before named authentication when the default user is passwordless; standalone loopback engines retain protected mode. The consumer exercises wrong-password, default-user, anonymous, key/administration ACL and current network-policy rejection.

Primary engine reference: [Valkey security and protected mode](https://valkey.io/topics/security/). Group tag additions/removals propagate to the exact existing members, as described by [AWS AddTagsToResource](https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_AddTagsToResource.html); independent member tag mutations remain an explicit unsupported setting.
