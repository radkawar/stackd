#!/usr/bin/env python3
"""Replay the compatible native free-control fixture against an owned local CLI."""
import argparse
import json
from pathlib import Path

from botocore.exceptions import ClientError

from rds_executable_smoke import Application, require


def replay(app):
    fixture = json.loads((Path(__file__).resolve().parents[2] / "testdata/aws/rds/controls.json").read_text())
    results = []
    excluded = []
    app.report["observations"]["native_control_replay"] = results
    app.report["observations"]["excluded_native_observations"] = excluded
    app.native_parameter_groups = fixture["owned"]
    for observation in fixture["observations"]:
        name = observation["case"]
        # AWS Aurora MySQL's family is 8.0; the actual local upstream engine is
        # 8.4. Do not rewrite that evidence into a claim of Aurora equivalence.
        if "aurora-mysql" in name:
            excluded.append({"case": name, "reason": "native Aurora 8.0 is not the upstream MySQL 8.4 family"})
            continue
        if observation["code"] == "InvalidDBParameterGroupState" and "pending changes" in observation.get("message", ""):
            # A captured transient cloud propagation race is not a deterministic
            # error contract. Local unattached groups publish atomically.
            excluded.append({"case": name, "reason": "unmodeled transient cloud cluster-group propagation"})
            continue
        parameters = json.loads(json.dumps(observation["input"]))
        client = app.data if observation["operation"] == "execute_statement" else app.rds
        try:
            output = getattr(client, observation["operation"])(**parameters)
            code, status = "Success", output["ResponseMetadata"]["HTTPStatusCode"]
        except ClientError as error:
            output = error.response
            code, status = output["Error"]["Code"], output["ResponseMetadata"]["HTTPStatusCode"]
        require(code == observation["code"], f"{name}: {code} != native {observation['code']}")
        require(status == observation["http_status"], f"{name}: HTTP {status} != native {observation['http_status']}")
        expected = observation.get("output", {})
        if "Parameters" in expected:
            selected = lambda rows: {row["ParameterName"]: (row.get("ParameterValue"), row.get("Source"), row.get("ApplyMethod")) for row in rows}
            require(selected(output["Parameters"]) == selected(expected["Parameters"]), f"{name}: retained parameter state differs")
        for field in ("DBParameterGroup", "DBClusterParameterGroup"):
            if field in expected:
                for key in ("DBParameterGroupName", "DBClusterParameterGroupName", "DBParameterGroupFamily", "Description"):
                    if key in expected[field]:
                        require(output[field][key] == expected[field][key], f"{name}: {key} differs")
        results.append({"case": name, "code": code, "http_status": status})
    app.report["observations"]["excluded_native_family"] = "aurora-mysql8.0: local real upstream engine/family is 8.4, not native Aurora"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    app = Application(parser.parse_args())
    try:
        app.start()
        replay(app)
    finally:
        try:
            for group in reversed(getattr(app, "native_parameter_groups", [])):
                try:
                    if group["cluster"]:
                        app.rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=group["name"])
                    else:
                        app.rds.delete_db_parameter_group(DBParameterGroupName=group["name"])
                except ClientError as error:
                    if error.response["Error"]["Code"] != "DBParameterGroupNotFound":
                        raise
            app.cleanup()
        finally:
            (app.state / "report.json").write_text(json.dumps(app.report, indent=2, default=str) + "\n")
    print(json.dumps(app.report, default=str))


if __name__ == "__main__":
    main()
