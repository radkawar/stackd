#!/usr/bin/env python3
"""Observe owned IAM user/group response shapes and verify resource cleanup."""

import datetime
import json
import pathlib
import uuid

from aws_cli import run as run_cli, result as cli_result, error_code


def call(operation, **parameters):
    process = run_cli("iam", operation, parameters)
    if process.returncode:
        return {"error": error_code(process)}
    return cli_result(process)["output"]


def checked(operation, **parameters):
    result = call(operation, **parameters)
    if "error" in result:
        raise RuntimeError(f"{operation}: {result['error']}")
    return result


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    name = "stackd-probe-" + uuid.uuid4().hex[:16]
    path = "/" + name + "/"
    owned_user = owned_group = False
    observations = {}
    cleanup = {}
    try:
        user = checked("create-user", UserName=name, Path=path,
                       Tags=[{"Key": "probe", "Value": "stackd"}],
                       PermissionsBoundary="arn:aws:iam::aws:policy/ReadOnlyAccess")
        owned_user = True
        observations["create_user_fields"] = sorted(user["User"])
        checked("create-group", GroupName=name, Path=path)
        owned_group = True
        checked("add-user-to-group", UserName=name, GroupName=name)
        observations["duplicate_membership"] = call(
            "add-user-to-group", UserName=name, GroupName=name)
        observations["get_user_fields"] = sorted(checked("get-user", UserName=name)["User"])
        observations["list_users_fields"] = sorted(checked("list-users", PathPrefix=path)["Users"][0])
        group = checked("get-group", GroupName=name)
        observations["get_group_user_fields"] = sorted(group["Users"][0])
        observations["get_group_fields"] = sorted(group["Group"])
        checked("remove-user-from-group", UserName=name, GroupName=name)
        observations["remove_absent_membership"] = call(
            "remove-user-from-group", UserName=name, GroupName=name)
    finally:
        if owned_group:
            call("remove-user-from-group", UserName=name, GroupName=name)
            cleanup["delete_group"] = call("delete-group", GroupName=name)
            cleanup["get_deleted_group"] = call("get-group", GroupName=name)
        if owned_user:
            call("delete-user-permissions-boundary", UserName=name)
            cleanup["delete_user"] = call("delete-user", UserName=name)
            cleanup["get_deleted_user"] = call("get-user", UserName=name)
        fixture = {
            "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source": "AWS IAM API, commercial partition, uniquely owned temporary user and group",
            "comparison": "Response field presence and exact modeled error codes; generated IDs/timestamps omitted",
            "observations": observations,
            "cleanup": cleanup,
        }
        destination = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/iam/user_group_shapes.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(fixture, indent=2) + "\n")
        print(json.dumps(fixture, indent=2))
        if owned_user and cleanup.get("get_deleted_user") != {"error": "NoSuchEntity"}:
            raise RuntimeError("Owned IAM user cleanup was not verified")
        if owned_group and cleanup.get("get_deleted_group") != {"error": "NoSuchEntity"}:
            raise RuntimeError("Owned IAM group cleanup was not verified")


if __name__ == "__main__":
    main()
