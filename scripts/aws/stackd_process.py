"""Process lifecycle shared by local executable probes.

Callers own command flags, isolated environments, service observations and resource
cleanup. Keep stop() in their finally block, including when readiness fails.
Forced cleanup is opt-in and always reports a failed shutdown.
"""
from collections.abc import Mapping, Sequence
from pathlib import Path
import ssl
import subprocess
import time
from typing import NotRequired, TypedDict
import urllib.request


class ControllerRun(TypedDict):
    start: int
    command: list[str]
    log: str
    pid: NotRequired[int]
    exit: NotRequired[int]
    forced: NotRequired[bool]


class StackdProcess:
    def __init__(self, directory: Path):
        self.directory = directory
        self.process: subprocess.Popen[bytes] | None = None
        self.runs: list[ControllerRun] = []

    def start(self, command: Sequence[str], endpoint: str, *,
              environment: Mapping[str, str], timeout: float = 60,
              tls: ssl.SSLContext | None = None) -> None:
        if self.process is not None:
            raise RuntimeError("Stop the current controller before starting another")
        log_path = self.directory / f"controller-{len(self.runs) + 1}.log"
        run: ControllerRun = {"start": len(self.runs) + 1, "command": list(command), "log": str(log_path)}
        self.runs.append(run)
        with log_path.open("wb") as log:
            self.process = subprocess.Popen(command, stdout=log, stderr=log, env=environment)
        run["pid"] = self.process.pid
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.process.poll()
            if status is not None:
                raise RuntimeError(f"Controller exited {status} before readiness; inspect {log_path}")
            try:
                with urllib.request.urlopen(endpoint + "/_stackd/health", context=tls, timeout=1) as response:
                    if response.status == 200:
                        return
            except OSError:
                pass
            time.sleep(0.1)
        raise TimeoutError(f"Controller readiness; PID {self.process.pid}, log {log_path}")

    def stop(self, timeout: float = 30, *, kill_on_timeout: bool = False) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            status = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if not kill_on_timeout:
                raise
            self.process.kill()
            self.runs[-1]["forced"] = True
            status = self.process.wait(timeout=10)
        self.runs[-1]["exit"] = status
        self.process = None
        if status != 0 or self.runs[-1].get("forced", False):
            raise RuntimeError(f"Controller exited {status}; inspect {self.runs[-1]['log']}")
