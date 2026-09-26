"""Base adapter: validate input -> build command -> execute -> capture -> parse -> normalize."""
import hashlib
import shutil
import subprocess

DEFAULT_TIMEOUT = 300


class AdapterResult:
    def __init__(self, tool, status="COMPLETED", data=None, raw="", error="", duration_ms=0):
        self.tool = tool
        self.status = status  # COMPLETED/FAILED/PARTIAL/SKIPPED
        self.data = data or []
        self.raw = raw
        self.error = error
        self.duration_ms = duration_ms


class BaseAdapter:
    tool_name = "base"
    binary = ""

    def is_available(self):
        return bool(self.binary) and shutil.which(self.binary) is not None

    def version(self):
        if not self.is_available():
            return "missing"
        try:
            p = subprocess.run([self.binary, "-version"], capture_output=True, text=True, timeout=15)
            out = (p.stdout + p.stderr).strip().splitlines()
            return out[0][:80] if out else "unknown"
        except Exception:
            return "unknown"

    def build_command(self, *args, **kwargs):
        raise NotImplementedError

    def parse(self, stdout: str, stderr: str = ""):
        raise NotImplementedError

    def run(self, *args, timeout=DEFAULT_TIMEOUT, **kwargs):
        if not self.is_available():
            return AdapterResult(self.tool_name, status="SKIPPED", error=f"{self.binary} not installed")
        cmd = self.build_command(*args, **kwargs)
        import time

        start = time.time()
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            dur = int((time.time() - start) * 1000)
            if p.returncode != 0 and not p.stdout.strip():
                return AdapterResult(self.tool_name, status="FAILED", raw=p.stdout, error=p.stderr[:2000], duration_ms=dur)
            data = self.parse(p.stdout, p.stderr)
            status = "COMPLETED" if p.returncode == 0 else "PARTIAL"
            return AdapterResult(self.tool_name, status=status, data=data, raw=p.stdout[:100000], error=p.stderr[:2000] if p.returncode else "", duration_ms=dur)
        except subprocess.TimeoutExpired:
            return AdapterResult(self.tool_name, status="FAILED", error="timeout")
        except Exception as e:
            return AdapterResult(self.tool_name, status="FAILED", error=str(e)[:1000])


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def redact_command(cmd: list[str]) -> str:
    out = []
    for part in cmd:
        low = part.lower()
        if any(k in low for k in ("webhook", "token", "secret", "key=", "password")):
            out.append("***REDACTED***")
        else:
            out.append(part)
    return " ".join(out)
