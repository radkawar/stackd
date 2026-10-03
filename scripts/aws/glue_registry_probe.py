#!/usr/bin/env python3
"""Bounded native Glue registry/schema evolution probe; metadata only, no compute."""
import json
import time

from glue_native_common import Capture, arguments, require

REFERENCES = ["https://docs.aws.amazon.com/glue/latest/webapi/API_" + name + ".html" for name in (
    "CreateRegistry", "CreateSchema", "RegisterSchemaVersion", "CheckSchemaVersionValidity",
    "GetSchemaByDefinition", "UpdateSchema", "PutSchemaVersionMetadata", "QuerySchemaVersionMetadata",
    "GetSchemaVersionsDiff", "DeleteSchemaVersions", "DeleteSchema", "DeleteRegistry")]


def main():
    cap = Capture(arguments(__doc__), "stackd-schema-", REFERENCES, {
        "max_calls": 100, "wall_seconds": 480, "cli_timeout_seconds": 30,
        "max_registries": 1, "max_schemas": 4, "max_versions_per_schema": 5,
        "cost_usd_upper_estimate": 0.001, "cost_basis": "Glue Schema Registry is offered at no additional charge; no data plane.",
    })
    registry = cap.prefix
    schemas = []
    created = False
    def call(label, operation, parameters):
        response = cap.request(label, "glue", operation, parameters)
        version = response.get("output", {}).get("SchemaVersionId")
        if version and not any(old == version for old, _ in cap.substitutions):
            cap.name(version, "SCHEMA_VERSION_" + str(len([old for old, new in cap.substitutions if new.startswith("SCHEMA_VERSION_")]) + 1))
        return response
    def sid(name):
        return {"RegistryName": registry, "SchemaName": name}
    def wait_version(label, version):
        for attempt in range(12):
            response = call(label + "-" + str(attempt), "get-schema-version", {"SchemaVersionId": version})
            if response["code"] != "Success" or response["output"].get("Status") != "PENDING":
                return response
            time.sleep(2)
        return response
    avro = {"type": "record", "name": "Item", "fields": [{"name": "value", "type": "int"}]}
    avro2 = {"type": "record", "name": "Item", "fields": avro["fields"] + [{"name": "note", "type": ["null", "string"], "default": None}]}
    definitions = {
        "AVRO": json.dumps(avro),
        "JSON": json.dumps({"$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "properties": {"value": {"type": "integer"}}, "additionalProperties": False}),
        "PROTOBUF": 'syntax = "proto3"; message Item { string value = 1; }',
    }
    try:
        cap.identity()
        cap.capture["uncertainty"] = ["Small schemas and one ordinary registry; not exhaustive AVRO/JSON/PROTOBUF compatibility validation.", "No unscoped ListRegistries/ListSchemas scan; version order retained but not a universal ordering claim."]
        created = True
        require(call("create-registry", "create-registry", {"RegistryName": registry, "Description": "owned"}))
        call("duplicate-registry", "create-registry", {"RegistryName": registry})
        call("get-registry", "get-registry", {"RegistryId": {"RegistryName": registry}})
        for fmt, definition in definitions.items():
            call("validate-" + fmt, "check-schema-version-validity", {"DataFormat": fmt, "SchemaDefinition": definition})
            call("validate-invalid-" + fmt, "check-schema-version-validity", {"DataFormat": fmt, "SchemaDefinition": "not a schema"})
            name = fmt.lower()
            schemas.append(name)
            call("create-schema-omitted-compatibility-" + fmt, "create-schema", {"RegistryId": {"RegistryName": registry}, "SchemaName": name, "DataFormat": fmt, "SchemaDefinition": definition})
            output = require(call("create-schema-" + fmt, "create-schema", {"RegistryId": {"RegistryName": registry}, "SchemaName": name, "DataFormat": fmt, "Compatibility": "BACKWARD", "SchemaDefinition": definition}))
            if output.get("SchemaVersionId"):
                wait_version("initial-version-" + fmt, output["SchemaVersionId"])
            call("get-schema-" + fmt, "get-schema", {"SchemaId": sid(name)})
        schemas.append("empty")
        call("create-schema-without-definition", "create-schema", {"RegistryId": {"RegistryName": registry}, "SchemaName": "empty", "DataFormat": "AVRO", "Compatibility": "BACKWARD"})
        call("get-empty-schema", "get-schema", {"SchemaId": sid("empty")})
        call("duplicate-schema", "create-schema", {"RegistryId": {"RegistryName": registry}, "SchemaName": "avro", "DataFormat": "AVRO", "Compatibility": "BACKWARD", "SchemaDefinition": definitions["AVRO"]})
        initial = require(call("get-avro-version-one", "get-schema-version", {"SchemaId": sid("avro"), "SchemaVersionNumber": {"VersionNumber": 1}}))
        first_id = initial["SchemaVersionId"]
        call("register-avro-exact-duplicate", "register-schema-version", {"SchemaId": sid("avro"), "SchemaDefinition": definitions["AVRO"]})
        call("register-avro-whitespace-duplicate", "register-schema-version", {"SchemaId": sid("avro"), "SchemaDefinition": json.dumps(avro, indent=2, sort_keys=True)})
        call("lookup-avro-whitespace", "get-schema-by-definition", {"SchemaId": sid("avro"), "SchemaDefinition": json.dumps(avro, indent=2, sort_keys=True)})
        evolved = require(call("register-avro-compatible", "register-schema-version", {"SchemaId": sid("avro"), "SchemaDefinition": json.dumps(avro2)}))
        wait_version("compatible-version", evolved["SchemaVersionId"])
        incompatible = call("register-avro-incompatible", "register-schema-version", {"SchemaId": sid("avro"), "SchemaDefinition": json.dumps({"type": "record", "name": "Item", "fields": [{"name": "value", "type": "string"}]})})
        if incompatible.get("output", {}).get("SchemaVersionId"):
            wait_version("incompatible-version", incompatible["output"]["SchemaVersionId"])
        call("versions-after-evolution", "list-schema-versions", {"SchemaId": sid("avro"), "MaxResults": 10})
        call("schema-diff", "get-schema-versions-diff", {"SchemaId": sid("avro"), "FirstSchemaVersionNumber": {"VersionNumber": 1}, "SecondSchemaVersionNumber": {"VersionNumber": 2}, "SchemaDiffType": "SYNTAX_DIFF"})
        metadata = {"SchemaVersionId": first_id, "MetadataKeyValue": {"MetadataKey": "owner", "MetadataValue": "one"}}
        call("put-metadata", "put-schema-version-metadata", metadata)
        call("put-metadata-duplicate", "put-schema-version-metadata", metadata)
        call("put-metadata-same-key", "put-schema-version-metadata", dict(metadata, MetadataKeyValue={"MetadataKey": "owner", "MetadataValue": "two"}))
        call("get-metadata", "query-schema-version-metadata", {"SchemaVersionId": first_id})
        call("remove-metadata-missing-value", "remove-schema-version-metadata", dict(metadata, MetadataKeyValue={"MetadataKey": "owner", "MetadataValue": "missing"}))
        call("remove-metadata-value", "remove-schema-version-metadata", metadata)
        call("get-metadata-after-remove", "query-schema-version-metadata", {"SchemaVersionId": first_id})
        call("update-compatibility-without-checkpoint", "update-schema", {"SchemaId": sid("avro"), "Compatibility": "NONE"})
        call("get-schema-after-compatibility-update", "get-schema", {"SchemaId": sid("avro")})
        call("delete-version-one", "delete-schema-versions", {"SchemaId": sid("avro"), "Versions": "1"})
        call("delete-version-missing", "delete-schema-versions", {"SchemaId": sid("avro"), "Versions": "999"})
        call("delete-version-two", "delete-schema-versions", {"SchemaId": sid("avro"), "Versions": "2"})
        call("versions-after-delete", "list-schema-versions", {"SchemaId": sid("avro"), "MaxResults": 10})
        call("schema-other-registry", "get-schema", {"SchemaId": {"RegistryName": registry + "-missing", "SchemaName": "avro"}})
        call("register-json-reordered", "register-schema-version", {"SchemaId": sid("json"), "SchemaDefinition": json.dumps(json.loads(definitions["JSON"]), indent=2, sort_keys=True)})
        cap.capture["completed"] = True
    except Exception as error:
        cap.capture["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        cap.cleaning = True
        remaining = []
        for name in reversed(schemas):
            call("cleanup-schema-" + name, "delete-schema", {"SchemaId": sid(name)})
        if created:
            call("cleanup-registry", "delete-registry", {"RegistryId": {"RegistryName": registry}})
            response = None
            for attempt in range(20):
                response = call("verify-registry-absent-" + str(attempt), "get-registry", {"RegistryId": {"RegistryName": registry}})
                if response["code"] == "EntityNotFoundException":
                    break
                time.sleep(2)
            if not response or response["code"] != "EntityNotFoundException":
                remaining.append(registry)
        cap.finish(remaining)


if __name__ == "__main__":
    main()
