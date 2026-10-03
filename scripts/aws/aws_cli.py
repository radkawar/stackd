"""AWS CLI transport shared by native behavior probes.

Callers own endpoint/retry choices, observations and resource cleanup. JSON shapes
remain open because probes deliberately exercise invalid and newly added inputs.
"""
import ast
import json
import re
import subprocess
from collections.abc import Mapping, Sequence
from typing import Any, NotRequired, TypedDict


class ProbeResult(TypedDict):
    code: str
    output: NotRequired[dict[str, Any]]
    error: NotRequired[dict[str, Any]]
    message: NotRequired[str]
    http_status: NotRequired[int]
    request_id: NotRequired[str | None]


class CLITimeout(RuntimeError):
    """A bounded CLI call expired; command arguments may contain secrets."""


class AWSCLIError(RuntimeError):
    """A failed strict call, retaining native JSON error fields for its caller."""

    def __init__(self, service: str, operation: str, stderr: str, details: dict[str, Any]):
        super().__init__(f"{service}:{operation}: {stderr.strip()}")
        self.details = details


def run(service: str, operation: str, parameters: Mapping[str, Any] | None = None,
        env: Mapping[str, str] | None = None, *, options: Sequence[str] = (),
        timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    """Execute one CLI command without interpreting service or client failures."""
    command = ["aws", service, operation, "--output", "json", "--no-cli-pager"]
    if parameters is not None:
        command += ["--cli-input-json", json.dumps(parameters)]
    try:
        return subprocess.run(command + list(options), env=env, capture_output=True,
                              text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise CLITimeout("AWS CLI timed out during " + operation) from None


def call(service: str, operation: str, parameters: Mapping[str, Any] | None = None,
         env: Mapping[str, str] | None = None, *, paginate: bool = True,
         error_format: str | None = None) -> dict[str, Any]:
    """Return JSON output; service and CLI-validation errors retain typed details.

    Configuration and transport failures abort capture instead of becoming
    observations of AWS behavior. AWS CLI uses 252 for input errors and 254
    for service errors.
    """
    options = ["--cli-connect-timeout", "10", "--cli-read-timeout", "30"]
    if error_format is not None:
        options += ["--cli-error-format", error_format]
    if not paginate:
        options.append("--no-paginate")
    process = run(service, operation, parameters or None, env, options=options)
    if process.returncode:
        diagnosis = f"{service}:{operation}: {process.stderr.strip()}"
        if error_format == "json" and process.returncode in (252, 254):
            try:
                details = json.loads(process.stderr)
            except json.JSONDecodeError:
                raise RuntimeError(diagnosis) from None
            if isinstance(details, dict) and isinstance(details.get("Code"), str):
                raise AWSCLIError(service, operation, process.stderr, details)
        raise RuntimeError(diagnosis)
    return result(process)["output"]


def require_account(account: str, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Verify the explicitly selected native account before resource operations."""
    identity = call("sts", "get-caller-identity", env=env)
    if identity["Account"] != account:
        raise RuntimeError("Unexpected native AWS account")
    return identity


def observe(service: str, operation: str, parameters: Mapping[str, Any] | None = None,
            env: Mapping[str, str] | None = None, *, paginate: bool = True) -> ProbeResult:
    """Capture native JSON success/error fields; callers own output redaction."""
    try:
        output = call(service, operation, parameters, env, paginate=paginate, error_format="json")
    except AWSCLIError as error:
        return {"code": error.details["Code"], "error": error.details}
    return {"code": "Success", "output": output}


def _text_error(stderr: str) -> tuple[str, str | None]:
    match = re.search(r"An error occurred \(([^)]+)\)(?:.*?operation(?: \([^)]*\))?: (.*))?", stderr)
    return (match[1], match[2]) if match else ("CLIError", None)


def result(process: subprocess.CompletedProcess[str], *, cli_error: str = "CLIError",
           cli_message: str | None = "AWS CLI failed; raw diagnostics discarded",
           debug: bool = False) -> ProbeResult:
    """Decode an observation, separating modeled errors from CLI rejection.

    A None client message retains the final three diagnostic lines for probes
    whose captured CLI-validation observations include those lines.
    """
    if process.returncode:
        code, message = _text_error(process.stderr)
        decoded: ProbeResult = {
            "code": code if message is not None else cli_error,
            "message": message if message is not None else cli_message if cli_message is not None
            else " ".join(process.stderr.splitlines()[-3:]),
        }
    else:
        decoded = {"code": "Success", "output": json.loads(process.stdout) if process.stdout.strip() else {}}
    if debug:
        statuses = re.findall(r'"[A-Z]+ [^"\r\n]* HTTP/1\.[01]" (\d{3})', process.stderr)
        if statuses:
            decoded["http_status"] = int(statuses[-1])
    return decoded


def error_code(process: subprocess.CompletedProcess[str]) -> str:
    """Decode code-only observations, including CLI ParamValidation errors."""
    return _text_error(process.stderr)[0]


def raw_xml(process: subprocess.CompletedProcess[str]) -> bytes | None:
    """Extract the last XML response from CLI debug output; discard other logs."""
    raw = None
    for line in process.stderr.splitlines():
        if line.startswith(("b'<", 'b"<')):
            try:
                candidate = ast.literal_eval(line)
                if candidate.startswith(b"<"):
                    raw = candidate
            except (ValueError, SyntaxError):
                pass
    return raw
