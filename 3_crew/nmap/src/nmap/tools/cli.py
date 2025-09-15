import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, Optional, Set


@dataclass
class CommandResult:
    stdin: str
    stdout: str
    stderr: str
    returncode: int
    success: bool
    duration: float

    def to_dict(self) -> Dict[str, object]:
        return {
            "stdin": self.stdin,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "returncode": self.returncode,
            "success": self.success,
            "duration": self.duration,
        }


class CommandRunner:
    """Simple, extensible CLI command runner with allowlist and structured output."""

    def __init__(self, allowed_commands: Optional[Set[str]] = None):
        self.allowed_commands = allowed_commands or set()

    def _is_allowed(self, command: str) -> bool:
        if not self.allowed_commands:
            return True
        try:
            first = shlex.split(command)[0]
        except Exception:
            first = command.split(" ")[0]
        base = first.rsplit("/", 1)[-1]
        return base in self.allowed_commands

    def run(self, command: str, timeout: int = 600) -> Dict[str, object]:
        start = time.monotonic()
        if not self._is_allowed(command):
            return CommandResult(
                stdin=command,
                stdout="",
                stderr=f"Command not allowed: {command}",
                returncode=127,
                success=False,
                duration=0.0,
            ).to_dict()

        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            duration = time.monotonic() - start
            return CommandResult(
                stdin=command,
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
                success=(proc.returncode == 0),
                duration=duration,
            ).to_dict()
        except subprocess.TimeoutExpired as e:
            duration = time.monotonic() - start
            return CommandResult(
                stdin=command,
                stdout=e.stdout.decode("utf-8", errors="ignore") if e.stdout else "",
                stderr=(e.stderr.decode("utf-8", errors="ignore") if e.stderr else "")
                + "\nTimeoutExpired",
                returncode=124,
                success=False,
                duration=duration,
            ).to_dict()
        except Exception as e:
            duration = time.monotonic() - start
            return CommandResult(
                stdin=command,
                stdout="",
                stderr=str(e),
                returncode=1,
                success=False,
                duration=duration,
            ).to_dict()

