#!/usr/bin/env python3
"""Owned metadata-only supplement for full compatibility and failed-version identity."""
import json
import time

from glue_native_common import Capture, arguments, require


def main():
    cap = Capture(arguments(__doc__), "stackd-schema-boundary-", [
        "https://docs.aws.amazon.com/glue/latest/webapi/API_DeleteSchemaVersions.html",
        "https://docs.aws.amazon.com/glue/latest/webapi/API_RegisterSchemaVersion.html",
        "https://docs.aws.amazon.com/glue/latest/webapi/API_GetSchemaVersion.html",
    ], {"max_calls": 35, "wall_seconds": 180, "max_registries": 1, "max_schemas": 2, "max_versions_per_schema": 4, "cost_usd_upper_estimate": 0.001, "cost_basis": "Schema Registry no additional charge; no compute."})
    registry = cap.prefix
    created = False
    def call(label, op, parameters):
        response = cap.request(label, "glue", op, parameters)
        version = response.get("output", {}).get("SchemaVersionId")
        if version and not any(old == version for old, new in cap.substitutions):
            cap.name(version, label.upper().replace("-", "_") + "_ID")
        return response
    base = {"type": "record", "name": "Item", "fields": [{"name": "value", "type": "int"}]}
    good = dict(base, fields=base["fields"] + [{"name": "note", "type": ["null", "string"], "default": None}])
    bad = dict(base, fields=[{"name": "value", "type": "string"}])
    try:
        cap.identity()
        created = True
        require(call("create-registry", "create-registry", {"RegistryName": registry}))
        for mode in ("BACKWARD_ALL", "FULL_ALL"):
            schema = {"RegistryName": registry, "SchemaName": mode.lower()}
            require(call(mode + "-create", "create-schema", {"RegistryId": {"RegistryName": registry}, "SchemaName": mode.lower(), "DataFormat": "AVRO", "Compatibility": mode, "SchemaDefinition": json.dumps(base)}))
            require(call(mode + "-compatible", "register-schema-version", {"SchemaId": schema, "SchemaDefinition": json.dumps(good)}))
            first = call(mode + "-incompatible", "register-schema-version", {"SchemaId": schema, "SchemaDefinition": json.dumps(bad)})
            if first.get("output", {}).get("Status") == "PENDING":
                time.sleep(3)
                call(mode + "-failure-state", "get-schema-version", {"SchemaVersionId": first["output"]["SchemaVersionId"]})
            call(mode + "-incompatible-duplicate", "register-schema-version", {"SchemaId": schema, "SchemaDefinition": json.dumps(bad)})
            call(mode + "-latest-after-failure", "get-schema-version", {"SchemaId": schema, "SchemaVersionNumber": {"LatestVersion": True}})
            call(mode + "-delete-version-two", "delete-schema-versions", {"SchemaId": schema, "Versions": "2"})
            call(mode + "-versions-after-delete", "list-schema-versions", {"SchemaId": schema, "MaxResults": 10})
        cap.capture["completed"] = True
    except Exception as error:
        cap.capture["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        cap.cleaning = True
        remaining = []
        if created:
            call("cleanup-registry", "delete-registry", {"RegistryId": {"RegistryName": registry}})
            for attempt in range(10):
                response = call("verify-registry-absent-" + str(attempt), "get-registry", {"RegistryId": {"RegistryName": registry}})
                if response["code"] == "EntityNotFoundException":
                    break
                time.sleep(2)
            if response["code"] != "EntityNotFoundException":
                remaining.append(registry)
        cap.finish(remaining)


if __name__ == "__main__":
    main()
