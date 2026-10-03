"""Replay native feature-flag admission and serving through a running stackd."""

import copy
import json
from pathlib import Path
import urllib.request
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def run(endpoint):
    """Return observations after exercising and deleting exact-owned resources."""
    session = boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )
    config = Config(retries={"max_attempts": 0}, read_timeout=30)
    app = session.client("appconfig", endpoint_url=endpoint, config=config)
    data = session.client("appconfigdata", endpoint_url=endpoint, config=config)
    fixture_path = Path(__file__).resolve().parents[2] / "testdata/aws/appconfig/feature_flags_native.json"
    capture = json.loads(fixture_path.read_text())
    inputs = {
        row["label"]: row["input"]["Content"].encode()
        for row in capture["calls"]
        if row["operation"] == "create_hosted_configuration_version"
    }
    expected = {row["name"]: row["served"].encode() for row in capture["served_fixtures"]}
    name = "stackd-feature-flags-" + uuid.uuid4().hex[:12]
    application = environment = profile = strategy = None
    versions = []
    observations = {"served": {}, "rejections": {}, "cleanup": []}

    def require(condition, message):
        if not condition:
            raise AssertionError(message)

    def drain():
        request = urllib.request.Request(
            endpoint.rstrip("/") + "/_stackd/jobs/drain?limit=4096",
            data=b"{}",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            json.load(response)

    def strip_entry_timestamps(document):
        document = copy.deepcopy(document)
        for section in ("flags", "values"):
            for entry in document.get(section, {}).values():
                entry.pop("_createdAt", None)
                entry.pop("_updatedAt", None)
        return document

    try:
        application = app.create_application(Name=name, Tags={"owner": name})["Id"]
        environment = app.create_environment(ApplicationId=application, Name="consumer")["Id"]
        profile = app.create_configuration_profile(
            ApplicationId=application,
            Name="flags",
            LocationUri="hosted",
            Type="AWS.AppConfig.FeatureFlags",
        )["Id"]
        strategy = app.create_deployment_strategy(
            Name=name,
            DeploymentDurationInMinutes=0,
            FinalBakeTimeInMinutes=0,
            GrowthFactor=100,
            GrowthType="LINEAR",
            ReplicateTo="NONE",
        )["Id"]
        for source, served_name in (
            ("boolean-enabled-disabled", "booleans"),
            ("variant-document", "variants"),
            ("variant-default-enabled-only", "default-enabled"),
        ):
            created = app.create_hosted_configuration_version(
                ApplicationId=application,
                ConfigurationProfileId=profile,
                ContentType="application/json",
                Content=inputs[source],
                VersionLabel=served_name,
            )
            version = created["VersionNumber"]
            versions.append(version)
            normalized = created["Content"].read()
            hosted = app.get_hosted_configuration_version(
                ApplicationId=application,
                ConfigurationProfileId=profile,
                VersionNumber=version,
            )["Content"].read()
            require(hosted == normalized, "hosted create/read must preserve the same normalized bytes")
            hosted_document = json.loads(hosted)
            require(
                strip_entry_timestamps(hosted_document) == json.loads(inputs[source]),
                "hosted content must retain flag definitions, constraints, variant rules and disabled attributes",
            )
            for section in ("flags", "values"):
                for entry in hosted_document[section].values():
                    require(
                        "_createdAt" in entry and "_updatedAt" in entry,
                        "hosted helper must retain per-entry timestamps",
                    )
            app.start_deployment(
                ApplicationId=application,
                EnvironmentId=environment,
                ConfigurationProfileId=profile,
                ConfigurationVersion=str(version),
                DeploymentStrategyId=strategy,
            )
            drain()
            token = data.start_configuration_session(
                ApplicationIdentifier=application,
                EnvironmentIdentifier=environment,
                ConfigurationProfileIdentifier=profile,
            )["InitialConfigurationToken"]
            response = data.get_latest_configuration(ConfigurationToken=token)
            served = response["Configuration"].read()
            require(served == expected[served_name], f"{served_name}: served bytes differ from the native capture: {served!r}")
            require(hosted != served, "the data API must not expose the hosted definition document")
            observations["served"][served_name] = {
                "content": served.decode(),
                "version": version,
                "request_id": response["ResponseMetadata"]["RequestId"],
            }

        for source in ("enum-invalid", "required-missing"):
            try:
                app.create_hosted_configuration_version(
                    ApplicationId=application,
                    ConfigurationProfileId=profile,
                    ContentType="application/json",
                    Content=inputs[source],
                )
            except ClientError as error:
                response = error.response
                require(response["Error"]["Code"] == "BadRequestException", str(error))
                require(response.get("Reason") == "InvalidConfiguration", str(error))
                observations["rejections"][source] = {
                    "code": response["Error"]["Code"],
                    "reason": response["Reason"],
                    "request_id": response["ResponseMetadata"]["RequestId"],
                }
            else:
                raise AssertionError(f"{source}: invalid flag attributes were accepted")
        retained = app.list_hosted_configuration_versions(
            ApplicationId=application, ConfigurationProfileId=profile
        )
        require(
            sorted(row["VersionNumber"] for row in retained["Items"]) == versions,
            "rejected feature-flag content must not publish a hosted version",
        )
        observations["hosted_definition_roundtrip"] = True
    finally:
        failures = []

        def cleanup(label, operation, **arguments):
            try:
                operation(**arguments)
                observations["cleanup"].append(label)
            except Exception as error:
                failures.append(f"{label}: {error}")

        if environment is not None:
            cleanup("environment", app.delete_environment, ApplicationId=application, EnvironmentId=environment, DeletionProtectionCheck="BYPASS")
        if profile is not None:
            # Enumerate within our exact-owned profile so even an unexpectedly
            # accepted negative case is deleted before reporting its assertion.
            try:
                owned_versions = app.list_hosted_configuration_versions(ApplicationId=application, ConfigurationProfileId=profile)["Items"]
                for version in owned_versions:
                    cleanup("version:" + str(version["VersionNumber"]), app.delete_hosted_configuration_version, ApplicationId=application, ConfigurationProfileId=profile, VersionNumber=version["VersionNumber"])
            except Exception as error:
                failures.append(f"list-owned-versions: {error}")
            cleanup("profile", app.delete_configuration_profile, ApplicationId=application, ConfigurationProfileId=profile, DeletionProtectionCheck="BYPASS")
        if application is not None:
            cleanup("application", app.delete_application, ApplicationId=application)
        if strategy is not None:
            cleanup("strategy", app.delete_deployment_strategy, DeploymentStrategyId=strategy)
        if failures:
            raise AssertionError("Feature flag cleanup failed: " + "; ".join(failures))
    return observations
