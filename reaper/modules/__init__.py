import os
import time
import signal
import platform
import subprocess
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Callable
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity = Severity.INFO
    evidence: str = ""
    module: str = ""
    target: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "module": self.module,
            "target": self.target,
        }


@dataclass
class ModuleResult:
    success: bool
    findings: list[Finding] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    command: str = ""

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "findings": [f.to_dict() for f in self.findings],
            "raw_output": self.raw_output,
            "error": self.error,
            "command": self.command,
        }


class BaseModule(ABC):
    name: str = ""
    description: str = ""
    default_timeout: int = 300  # seconds

    def __init__(self, db=None):
        self.db = db
        self._process: Optional[subprocess.Popen] = None
        self._interrupted = False
        self._on_output: Optional[Callable[[str], None]] = None

    def set_output_callback(self, callback: Callable[[str], None]):
        self._on_output = callback

    def _emit(self, line: str):
        if self._on_output:
            try:
                self._on_output(line)
            except Exception:
                pass

    def run_command(
        self,
        cmd: list[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> tuple[int, str, str]:
        """
        Run a subprocess with:
          - streaming output line-by-line to the registered callback
          - SIGINT forwarded to the child process group
          - configurable timeout with SIGKILL escalation
        Returns (returncode, stdout, stderr).
        """
        if timeout is None:
            timeout = self.default_timeout

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        returncode = -1
        self._interrupted = False

        def _stream(pipe, bucket):
            try:
                for raw in iter(pipe.readline, b""):
                    line = raw.decode("utf-8", errors="replace").rstrip()
                    bucket.append(line)
                    self._emit(line)
            except Exception:
                pass
            finally:
                try:
                    pipe.close()
                except Exception:
                    pass

        proc_kwargs: dict = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
        }
        # Use a new session on Linux so we can killpg the whole tree
        if platform.system() != "Windows":
            proc_kwargs["start_new_session"] = True
        if cwd:
            proc_kwargs["cwd"] = cwd
        if env:
            proc_kwargs["env"] = env

        def _kill(sig=signal.SIGTERM):
            p = self._process
            if p is None:
                return
            try:
                if platform.system() != "Windows":
                    try:
                        os.killpg(os.getpgid(p.pid), sig)
                    except (ProcessLookupError, PermissionError, OSError):
                        p.send_signal(sig)
                else:
                    p.terminate()
            except (ProcessLookupError, PermissionError, OSError):
                pass

        def _terminate():
            _kill(signal.SIGTERM)
            time.sleep(0.4)
            _kill(signal.SIGKILL if platform.system() != "Windows" else signal.SIGTERM)

        original_sigint = signal.getsignal(signal.SIGINT)
        in_main = threading.current_thread() is threading.main_thread()

        def _sigint_handler(sig, frame):
            self._interrupted = True
            self._emit("[!] Interrupted — terminating child process…")
            _terminate()
            if in_main:
                signal.signal(signal.SIGINT, original_sigint)

        try:
            self._process = subprocess.Popen(cmd, **proc_kwargs)

            if in_main:
                try:
                    signal.signal(signal.SIGINT, _sigint_handler)
                except (ValueError, OSError):
                    pass

            t_out = threading.Thread(
                target=_stream, args=(self._process.stdout, stdout_lines), daemon=True
            )
            t_err = threading.Thread(
                target=_stream, args=(self._process.stderr, stderr_lines), daemon=True
            )
            t_out.start()
            t_err.start()

            try:
                self._process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._emit(f"[!] Timeout ({timeout}s) — killing process")
                _terminate()
                self._process.wait()

            t_out.join(timeout=5)
            t_err.join(timeout=5)
            returncode = self._process.returncode

        except FileNotFoundError:
            msg = f"[!] Tool not found: '{cmd[0]}' — is it installed and in PATH?"
            stderr_lines.append(msg)
            self._emit(msg)
        except PermissionError:
            msg = f"[!] Permission denied: {cmd[0]}"
            stderr_lines.append(msg)
            self._emit(msg)
        except Exception as exc:
            msg = f"[!] Unexpected error running command: {exc}"
            stderr_lines.append(msg)
            self._emit(msg)
        finally:
            if in_main:
                try:
                    signal.signal(signal.SIGINT, original_sigint)
                except (ValueError, OSError):
                    pass
            self._process = None

        return returncode, "\n".join(stdout_lines), "\n".join(stderr_lines)

    def tool_available(self, tool: str) -> bool:
        import shutil
        return shutil.which(tool) is not None

    def tool_check_emit(self, tool: str) -> bool:
        if not self.tool_available(tool):
            self._emit(f"[!] '{tool}' not found in PATH — install it first")
            return False
        return True

    @abstractmethod
    def run(self, target: str, options: dict) -> ModuleResult:
        pass

    def parse_output(self, output: str) -> list[Finding]:
        return []
