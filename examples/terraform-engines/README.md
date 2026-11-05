# Terraform engines

## Purpose

Run one engine's Terraform lifecycle: create, protocol consumer, independent-state import, refresh, update, unchanged plan, controller reopen with retained bytes, and exact-owned destroy.

| Engine | Consumer and specific guide | Runtime flags |
| --- | --- | --- |
| `cache` | [Valkey primary/read-only replica](cache/README.md), TLS binary SET/GET, ACL and network-policy denial | `-valkey-runtime` with generated TLS certificate/key |
| `memorydb` | Valkey-backed MemoryDB, TLS binary values, ACL checks and physical snapshot restore | `-valkey-runtime` with generated TLS certificate/key |
| `mq` | ActiveMQ 5.18 TLS/OpenWire, persistent binary messages, transactional consumption and JMSXUserID update | `-mq-runtime`, owned state directory, generated TLS and selected Java |
| `search` | OpenSearch 2.19.4 document/index consumers, domain options, tags and policy updates | `-opensearch-runtime` |
| `kafka` | Two-broker Kafka TLS publication/consumption and retained records, IAM/service-linked-role checks | `-msk-runtime` |

## Prerequisites

Complete the [shared example setup](../README.md) and [container deployment](../../docs/runtime-containers.md). This runner enforces Terraform **1.15.9** and uses AWS provider **6.68.0**. Install Python dependencies from the repository root:

```sh
python3 -m pip install -r examples/terraform-engines/requirements.txt
```

Use a supported local Linux Docker host; `--docker-host` defaults to `unix:///var/run/docker.sock`. Cache and Kafka create owned EC2-backed network attachments and packet policy: use the rootful, systemd/cgroup-v2 host recipe without user-namespace remapping, and ensure private engine addresses are reachable from the host. Do not use an unrelated existing engine server.

Preinstall exact digest-qualified images, never just similarly named tags:

- Cache **and MemoryDB:** `VALKEY_IMAGE` in [`common.py`](common.py) and the toolkit digest inspected by [`cache/fixture.py`](cache/fixture.py). Both selections share that preparation function.
- Kafka: `KAFKA_IMAGE` in `common.py` plus `TOOLKIT_IMAGE` in [`kafka/fixture.py`](kafka/fixture.py).
- Search: `IMAGE` in [`search/fixture.py`](search/fixture.py).
- MQ: both `ACTIVE_IMAGE` and `RABBIT_IMAGE` in [`mq/fixture.py`](mq/fixture.py), even though this consumer uses ActiveMQ. Install a Java **11+ JDK** with matching `java` and `javac`, and OpenSSL for generated TLS material. The runner compiles its Java consumer against libraries extracted from the installed image; no libraries or images are downloaded.

Cache/MemoryDB also use OpenSSL to generate TLS material. See the deployment guide for architecture-matched image installation and offline transfer. A provider mirror is optional; without one Terraform may download the provider.

## Run

From the repository root, choose one command after preparing its dependencies:

```sh
python3 examples/terraform-engines/run.py cache --provider-mirror /absolute/path/to/provider-mirror
python3 examples/terraform-engines/run.py memorydb --provider-mirror /absolute/path/to/provider-mirror
python3 examples/terraform-engines/run.py mq --provider-mirror /absolute/path/to/provider-mirror --java /absolute/path/to/jdk/bin/java
python3 examples/terraform-engines/run.py search --provider-mirror /absolute/path/to/provider-mirror
python3 examples/terraform-engines/run.py kafka --provider-mirror /absolute/path/to/provider-mirror
```

Default port: **14706**. Shared options are `--port`, `--stackd`, and `--work-parent` (an existing directory). Each invocation creates a fresh private workspace and random local account, retained in `account-id`. The runner selects the runtime flags shown above; it does not adopt an existing controller.

## Expected results

Expect the printed workspace, Terraform commands, engine-specific verification messages, import/no-op/reopen stages and `Native <engine> lifecycle complete` only after successful cleanup. Any failed consumer or drift assertion fails the invocation. Engine runs retain private artifacts rather than a uniform top-level `report.json`; use the exit status, console and per-engine artifacts together. These are instructions, not a claim that the workflows were executed for this documentation change.

## Cleanup

The runner reopens its exact SQLite database in `finally`, cleans consumer data, runs Terraform destroy and checks empty managed state plus engine-specific absence. Cache/Kafka reserve a private CIDR through `.stackd/native-engine-cidr-reservations.json` and release their lease after verified destroy. Do not remove the shared reservation registry while another run or unresolved resource exists.

State, import state, passwords, TLS keys, logs and native files remain in the printed workspace. Keep it after failures; another invocation creates a different owner and cannot clean the failed one. Do not globally prune Docker or delete by prefix. After successful cleanup and controller shutdown, remove only the exact printed directory if desired. Never publish passwords, keys, tfstate or raw logs. Preserve checked-in [`inventory.json`](inventory.json).

## Limitations

The consumer is selected by one positional engine name; it does not run every operation in the inventory. Search uses OpenSearch, not an Elasticsearch runtime. The MQ consumer uses ActiveMQ, not RabbitMQ user APIs. MemoryDB runs one shard with snapshot isolation checks. Network/runtime preparation is not automated by this runner, and images are inspected rather than pulled.
