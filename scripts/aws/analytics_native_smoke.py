#!/usr/bin/env python3
"""Run the real analytics clients against one fresh, owned SQLite controller.

Requires the pinned Trino/Spark images and the Python dependencies used by the
individual smoke scripts. Private controller state/logs remain in
--state-directory; client assertion receipts are written to --output and client
failure diagnostics go to stderr. No AWS profile or ambient credentials are
used. The controller must shut down cleanly.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

from stackd_process import StackdProcess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--state-directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    directory = args.state_directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}"
    account = "123456789012"  # Explicit fixture identity, never a production default.
    database = directory / "state.sqlite"
    environment = dict(os.environ)
    for key in list(environment):
        if key.startswith("AWS_") or key.lower().endswith("_proxy"):
            del environment[key]
    environment.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test",
                       AWS_DEFAULT_REGION="us-east-1", AWS_EC2_METADATA_DISABLED="true",
                       AWS_CONFIG_FILE=str(directory / "empty-config"),
                       AWS_SHARED_CREDENTIALS_FILE=str(directory / "empty-credentials"),
                       NO_PROXY="127.0.0.1,localhost")
    command = [str(binary), "-listen", f"127.0.0.1:{port}",
               "-public-endpoint", endpoint,
               "-compute-endpoint", f"http://host.docker.internal:{port}",
               "-account-id", account, "-database", str(database),
               "-athena-runtime", "-docker-host", args.docker_host]
    scripts = Path(__file__).resolve().parent
    cases = [
        ("hive", "athena_hive_semantics_smoke.py",
         ["--endpoint-url", endpoint, "--account", account]),
        ("ordinary-iceberg", "glue_iceberg_rest_smoke.py",
         ["--endpoint", endpoint, "--state-directory", str(database) + ".athena",
          "--docker-host", args.docker_host]),
        ("replacement", "glue_iceberg_commit_smoke.py", ["--endpoint", endpoint]),
        ("managed-catalogs", "athena_catalogs_smoke.py",
         ["--endpoint-url", endpoint, "--account", account]),
    ]
    receipts = {}
    controller = StackdProcess(directory)
    try:
        controller.start(command, endpoint, environment=environment)
        for name, script, arguments in cases:
            result = subprocess.run([sys.executable, str(scripts / script), *arguments],
                                    env=environment, text=True, capture_output=True,
                                    timeout=900, check=False)
            (directory / f"{name}.stdout").write_text(result.stdout)
            (directory / f"{name}.stderr").write_text(result.stderr)
            if result.returncode:
                print(result.stderr, file=sys.stderr, end="")
                raise RuntimeError(f"{name} exited {result.returncode}; inspect private logs in {directory}")
            receipts[name] = json.loads(result.stdout)
            print(f"Passed native analytics scenario: {name}", flush=True)
    finally:
        controller.stop(kill_on_timeout=True)
    args.output.write_text(json.dumps({"completed": True, "clean_shutdown": True,
                                       "checks": receipts}, indent=2) + "\n")
    print("Native analytics controller shut down cleanly", flush=True)


if __name__ == "__main__":
    main()
