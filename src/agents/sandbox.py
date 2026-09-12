"""VulnHound's Daytona lifecycle and target-constrained tool runner.

Call deploy_target() before starting agents: its returned host is the authority
for run_tool(), and each agent captures that host for its lifetime. Importing
this module reads .env but performs no network calls.
"""

from __future__ import annotations

import atexit
import logging
import os
import re
import shlex
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Iterator, TypedDict
from urllib.parse import unquote, urlsplit

from daytona import CreateSandboxFromSnapshotParams, Daytona
from dotenv import load_dotenv


# Daytona() reads DAYTONA_API_KEY from the environment. Existing values win.
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

_log = logging.getLogger(__name__)
_state_lock = RLock()
_target_host: str | None = None
_target_sandboxes: list[Any] = []
_agent_targets: dict[int, str | None] = {}
_toolkit_snapshot: str | None = None

ALLOWED_BINARIES = frozenset({
    "nmap", "whatweb", "gobuster", "sqlmap", "nikto", "curl", "dirb", "ffuf",
})

# Deliberately finite option grammars: an unknown option may change the target,
# load executable code/configuration, or enable another network destination.
_FLAGS = {
    "curl": {"-I", "--head", "-i", "--include", "-s", "--silent", "-S",
             "--show-error", "-k", "--insecure", "-v", "--verbose", "-f", "--fail",
             "--compressed", "--http1.1", "--http2", "--path-as-is", "-G", "--get",
             "-g", "--globoff", "-q", "--disable"},
    "nmap": {"-sV", "-sT", "-sS", "-sU", "-Pn", "-n", "--open", "-v", "-vv",
             "--reason", "-F", "--version-light", "--version-all"},
    "whatweb": {"-v", "--verbose", "-q", "--quiet", "--no-errors", "--no-cookies"},
    "gobuster": {"-q", "--quiet", "-k", "--no-tls-validation", "-e", "--expanded",
                 "-n", "--no-status", "--no-progress", "--no-error"},
    "sqlmap": {"--batch", "--banner", "--dbs", "--tables", "--columns", "--dump",
               "--current-db", "--current-user", "--is-dba", "--flush-session",
               "--fresh-queries", "--ignore-proxy", "--ignore-redirects"},
    "nikto": {"-ssl", "-nossl", "-nointeractive", "-nocheck", "-nolookup",
              "-nocookies", "-no404"},
    "dirb": {"-r", "-S", "-w", "-f"},
    "ffuf": {"-s", "-v", "-k", "-noninteractive", "-ignore-body", "-http2"},
}
_OPTIONS = {
    "curl": {"--url": "target", "-X": "method", "--request": "method",
             "-H": "header", "--header": "header", "-d": "data", "--data": "data",
             "--data-raw": "data", "--data-urlencode": "data", "-A": "data",
             "--user-agent": "data", "-b": "data", "--cookie": "data",
             "-m": "number", "--max-time": "number", "--connect-timeout": "number"},
    "nmap": {"-p": "ports", "--top-ports": "number", "--max-retries": "number",
             "--host-timeout": "duration", "--scan-delay": "duration",
             "--min-rate": "number", "--max-rate": "number", "-T": "timing"},
    "whatweb": {"-a": "aggression", "--aggression": "aggression",
                "-H": "header", "--header": "header", "--open-timeout": "number",
                "--read-timeout": "number", "--follow-redirect": "never"},
    "gobuster": {"-u": "target", "--url": "target", "-w": "wordlist",
                 "--wordlist": "wordlist", "-t": "number", "--threads": "number",
                 "-x": "extensions", "--extensions": "extensions",
                 "-s": "numbers", "--status-codes": "numbers",
                 "-b": "numbers", "--status-codes-blacklist": "numbers",
                 "--timeout": "duration", "-H": "header", "--headers": "header"},
    "sqlmap": {"-u": "target", "--url": "target", "--data": "data",
               "--cookie": "data", "--headers": "header", "-p": "identifier",
               "--level": "level", "--risk": "risk", "--threads": "number",
               "--timeout": "number", "--retries": "number", "--delay": "number",
               "--technique": "technique", "-D": "identifier", "-T": "identifier",
               "-C": "identifier", "--dbms": "identifier"},
    "nikto": {"-h": "target", "-host": "target", "-url": "target",
              "-p": "ports", "-port": "ports", "-timeout": "number",
              "-maxtime": "duration", "-Tuning": "tuning", "-Pause": "number"},
    "dirb": {"-X": "extensions", "-x": "wordlist", "-z": "number",
             "-H": "header", "-a": "data", "-c": "data"},
    "ffuf": {"-u": "target", "-w": "wordlist", "-t": "number", "-rate": "number",
             "-timeout": "number", "-maxtime": "number", "-mc": "status",
             "-fc": "numbers", "-fs": "numbers", "-fw": "numbers", "-fl": "numbers",
             "-H": "header", "-X": "method", "-d": "data", "-b": "data"},
}
_PATTERNS = {
    "number": r"\d+(?:\.\d+)?", "numbers": r"\d+(?:[-,]\d+)*",
    "ports": r"(?:\d+(?:[-,]\d+)*|-)", "duration": r"\d+(?:\.\d+)?(?:ms|s|m|h)?",
    "timing": r"[0-5]", "aggression": r"[134]", "level": r"[1-5]", "risk": r"[1-3]",
    "never": r"never", "technique": r"[BEUSTQ]+", "tuning": r"[0-9abcx]+",
    "identifier": r"[A-Za-z0-9_, -]+", "extensions": r"\.?[A-Za-z0-9]+(?:,\.?[A-Za-z0-9]+)*",
    "method": r"(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)",
    "status": r"(?:all|\d+(?:[-,]\d+)*)",
}


def _endpoint(value: str) -> tuple[str, int | None]:
    """Parse a literal HTTP authority; reject URL-parser ambiguities."""
    if not value or re.search(r"[\s\\\x00-\x1f\x7f]", value):
        raise ValueError("Invalid target")
    parsed = urlsplit(value if "://" in value else "//" + value)
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP(S) URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are not allowed")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
        raise ValueError("A literal hostname is required")
    if any(not label or label.startswith("-") or label.endswith("-") for label in host.split(".")):
        raise ValueError("Invalid hostname")
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    return host, port


def _is_target(value: str, target_host: str | None) -> bool:
    try:
        host, port = _endpoint(value)
        if host in {"localhost", "127.0.0.1"}:
            return port in {None, 3000}
        return bool(target_host) and host == _endpoint(target_host)[0]
    except (TypeError, ValueError):
        return False


def _safe_references(value: str, target_host: str | None) -> bool:
    """Reject embedded off-target URLs/hostnames, including encoded payloads."""
    for _ in range(4):
        if re.search(r"[\x00-\x1f\x7f\\]", value):
            return False
        for reference in re.findall(r"(?:[a-zA-Z][\w+.-]*:)?//[^\s'\"<>]+", value):
            if not _is_target(reference.lstrip("/") if reference.startswith("//") else reference,
                              target_host):
                return False
        for host in re.findall(r"(?<![\w.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+", value):
            if not _is_target(host, target_host):
                return False
        decoded = unquote(value)
        if decoded == value:
            return True
        value = decoded
    return False  # Do not accept more deeply nested encodings.


def _valid_value(kind: str, value: str, target_host: str | None) -> bool:
    if not value or value.startswith("-"):
        return kind == "ports" and value == "-"
    if kind == "target":
        return _is_target(value, target_host)
    if kind == "wordlist":
        # Files supply path suffixes only; no target lists or custom FUZZ keys.
        return bool(re.fullmatch(r"/(?:usr/share/(?:wordlists|dirb/wordlists)|tmp)/[\w./-]+", value)) \
            and ".." not in value.split("/")
    if kind in _PATTERNS:
        return bool(re.fullmatch(_PATTERNS[kind], value))
    if kind == "header":
        name, sep, body = value.partition(":")
        if not sep or not re.fullmatch(r"[A-Za-z0-9-]+", name):
            return False
        if name.lower() in {"host", "origin", "referer", "x-forwarded-host"}:
            return _is_target(body.strip(), target_host) and _safe_references(body, target_host)
        if name.lower() in {"forwarded", "connection", "upgrade", "proxy-authorization"}:
            return False
    if kind in {"header", "data"}:
        # '@' can load files with curl; FUZZ in headers could alter HTTP routing.
        return "@" not in value and "FUZZ" not in value and _safe_references(value, target_host)
    return False


def _command_args(command: str, target_host: str | None) -> list[str]:
    if not isinstance(command, str) or re.search(r"[\x00-\x1f\x7f`$]", command):
        raise ValueError("Shell expansion and control characters are forbidden")
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    args = list(lexer)
    if not args or args[0] not in ALLOWED_BINARIES:
        raise ValueError("Command binary is not allowed")
    tool = args[0]
    index = 1
    if tool == "gobuster":
        if len(args) < 2 or args[1] != "dir":
            raise ValueError("Only gobuster dir is allowed")
        index = 2
    targets: list[str] = []
    ports: list[str] = []
    wordlists = 0
    while index < len(args):
        token = args[index]
        index += 1
        if token in _FLAGS[tool]:
            continue
        # curl's common -sSI form and nmap's -T4 / -p3000 forms.
        if tool == "curl" and re.fullmatch(r"-[sSIikvfg]+", token):
            continue
        if tool == "nmap" and re.fullmatch(r"-T[0-5]", token):
            continue
        option, equals, value = token.partition("=")
        if tool == "nmap" and token.startswith("-p") and len(token) > 2:
            option, equals, value = "-p", "=", token[2:]
        if option in _OPTIONS[tool]:
            kind = _OPTIONS[tool][option]
            if not equals:
                if index >= len(args):
                    raise ValueError("Missing option value")
                value = args[index]
                index += 1
            if not _valid_value(kind, value, target_host):
                raise ValueError("Option value is not allowed")
            if kind == "target":
                targets.append(value)
            elif kind == "ports":
                ports.append(value)
            elif kind == "wordlist":
                wordlists += 1
            continue
        if not token.startswith("-") and tool in {"curl", "nmap", "whatweb", "dirb"}:
            if tool == "dirb" and targets:
                if not _valid_value("wordlist", token, target_host):
                    raise ValueError("Invalid wordlist")
                wordlists += 1
            else:
                if not _is_target(token, target_host):
                    raise ValueError("Off-target argument")
                targets.append(token)
            continue
        raise ValueError("Unknown or unsafe option")
    if len(targets) != 1:
        raise ValueError("Exactly one explicit target is required")
    target = targets[0]
    parsed = urlsplit(target if "://" in target else "//" + target)
    if not _safe_references(parsed.query, target_host):
        raise ValueError("Off-target reference in query")
    if tool == "nmap" and (parsed.scheme or parsed.path or parsed.port):
        raise ValueError("nmap requires a bare hostname; use -p for the port")
    if _endpoint(target)[0] in {"localhost", "127.0.0.1"} and any(p != "3000" for p in ports):
        raise ValueError("Only the target's loopback port 3000 is allowed")
    if tool in {"gobuster", "ffuf"} and wordlists != 1:
        raise ValueError("Exactly one local wordlist is required")
    return args


def allowed_command(command: str, target_host: str) -> bool:
    """Allow one known tool with one exact target and a finite safe option set.

    Localhost/127.0.0.1 (port 3000 when explicit) are also permitted. Subdomains,
    host suffix matches, CIDRs, shell syntax, proxies, config/target files,
    arbitrary scripts and redirect-following switches are rejected. This is
    command validation, not an OS-level network firewall.
    """
    try:
        _command_args(command, target_host)
        return True
    except (TypeError, ValueError):
        return False


def run_tool(sandbox: Any, command: str, timeout: int = 120) -> dict:
    """Run a guarded command against the deployed target; reject before exec.

    The target is registered by deploy_target(), not inferred from the command
    or an agent-controlled sandbox attribute. SDK execution failures become
    {stdout, exit_code: -1, ok: False}; policy violations raise ValueError.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise ValueError("timeout must be a positive integer")
    with _state_lock:
        host = _agent_targets.get(id(sandbox), _target_host)
        if any(sandbox is target for target in _target_sandboxes):
            raise ValueError("Tools must run in an agent sandbox, not the target")
    if not allowed_command(command, host or ""):
        raise ValueError("Command rejected: use an allowed tool against the deployed target")
    args = _command_args(command, host)
    tool = args[0]
    # Disable implicit routing and non-target network activity where applicable.
    fixed = {
        "curl": ["-q", "--globoff", "--proxy", "", "--noproxy", "*",
                 "--proto", "=http,https", "--max-redirs", "0"],
        "nmap": ["-n"],
        "whatweb": ["--follow-redirect=never"],
        "sqlmap": ["--ignore-redirects", "--ignore-proxy", "--batch"],
        "nikto": ["-nocheck", "-nointeractive", "-ask", "no"],
        "ffuf": ["-noninteractive"],
    }.get(tool, [])
    args = [tool, *fixed, *args[1:]]
    # Remove inherited proxies and user config locations. shlex.join ensures
    # quoted payloads cannot become a second shell command during execution.
    wrapped = shlex.join([
        "env", "-i", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/tmp/vulnhound-tool-home", "XDG_CONFIG_HOME=/tmp/vulnhound-tool-home",
        *args,
    ])
    try:
        response = sandbox.process.exec(wrapped, timeout=timeout)
        return {"stdout": response.result or "", "exit_code": response.exit_code,
                "ok": response.exit_code == 0}
    except Exception as exc:
        return {"stdout": f"{type(exc).__name__}: {exc}", "exit_code": -1, "ok": False}


class TaskResult(TypedDict):
    """One task's output, exit status, and any execution or cleanup failure."""

    success: bool
    output: str
    exit_code: int | None
    error: str | None


@contextmanager
def sandbox_session(snapshot: str | None = None, *, public: bool = False) -> Iterator[Any]:
    """Create a sandbox and always attempt to stop it when the context exits."""
    client = Daytona()
    # These parameters are verified in the installed SDK, not guessed kwargs.
    if snapshot or public:
        sandbox = client.create(CreateSandboxFromSnapshotParams(snapshot=snapshot, public=public))
    else:
        sandbox = client.create()
    try:
        yield sandbox
    finally:
        sandbox.stop()


def _exec_checked(sandbox: Any, command: str, timeout: int = 120) -> str:
    """Trusted provisioning only; LLM-generated commands must use run_tool()."""
    response = sandbox.process.exec(command, timeout=timeout)
    if response.exit_code != 0:
        raise RuntimeError(f"Sandbox setup exited with {response.exit_code}: {response.result}")
    return response.result or ""


def install_tools(sandbox: Any) -> None:
    """Install the toolkit on a Debian/Ubuntu sandbox, requiring root or sudo.

    This is the fallback when snapshot creation/restoration is unavailable.
    Installation is idempotent and skips apt when the required tools exist.
    """
    # REQUIRED tools the agents actually drive; the toolkit must provide these.
    # OPTIONAL tools may be absent on some distros (e.g. nikto is not packaged on
    # Debian trixie); a missing optional package must not fail the whole install,
    # so packages are installed individually rather than in one atomic apt call.
    script = """
set -eu
REQUIRED="nmap whatweb gobuster sqlmap curl"
OPTIONAL="nikto dirb ffuf"
missing=0
for tool in $REQUIRED; do
    command -v "$tool" >/dev/null 2>&1 || missing=1
done
if [ "$missing" -eq 0 ]; then exit 0; fi
command -v apt-get >/dev/null 2>&1 || { echo 'Toolkit requires apt-get' >&2; exit 1; }
if [ "$(id -u)" -eq 0 ]; then SUDO=""; APT="apt-get";
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then SUDO="sudo -n"; APT="sudo -n apt-get";
else echo 'Toolkit installation requires root or passwordless sudo' >&2; exit 1; fi
$APT update
# Install each package independently so one unavailable package (or one that is
# not in this distro's repositories) does not abort the rest of the toolkit.
for pkg in $REQUIRED $OPTIONAL; do
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$pkg" \
        || echo "WARN: optional/unavailable package skipped: $pkg" >&2
done
# Only the REQUIRED tools must be present for the agents to function.
for tool in $REQUIRED; do command -v "$tool" >/dev/null || { echo "Required tool missing after install: $tool" >&2; exit 1; }; done
"""
    _exec_checked(sandbox, "sh -c " + shlex.quote(script), timeout=900)


def pentest_toolkit_snapshot() -> str:
    """Install the toolkit, snapshot it, and return the created snapshot name.

    If the listed sb.snapshot.create(name) API is absent, raise
    NotImplementedError; callers can use install_tools() instead. Never return
    a made-up snapshot name after failure.
    """
    global _toolkit_snapshot
    name = f"vulnhound-toolkit-{uuid.uuid4().hex[:12]}"
    with sandbox_session() as sandbox:
        snapshot_api = getattr(sandbox, "snapshot", None)
        if not callable(getattr(snapshot_api, "create", None)):
            raise NotImplementedError(
                "Installed Daytona SDK lacks sandbox.snapshot.create(name); "
                "agent_sandbox() will use install_tools() instead"
            )
        install_tools(sandbox)
        snapshot_api.create(name)
    with _state_lock:
        _toolkit_snapshot = name
    return name


@contextmanager
def agent_sandbox(snapshot: str | None = None) -> Iterator[Any]:
    """Yield a pre-tooled agent sandbox and always stop it, even on setup failure.

    Restore an existing snapshot through the installed SDK's verified creation
    parameters. Without a snapshot, install_tools() provisions a fresh sandbox.
    The installer also checks restored images and skips apt if tools exist.
    """
    with sandbox_session(snapshot) as sandbox:
        with _state_lock:
            _agent_targets[id(sandbox)] = _target_host
        try:
            install_tools(sandbox)
            yield sandbox
        finally:
            with _state_lock:
                _agent_targets.pop(id(sandbox), None)


def run_agents_parallel(agent_fns: list[Callable[[Any], Any]], max_workers: int = 6) -> list:
    """Give each callable its own pre-tooled sandbox; preserve input order.

    Successful entries are the callable's unmodified return value. An agent's
    creation, installation, execution, or cleanup failure is returned as
    {ok: False, error: 'ExceptionType: message'} at that agent's input index.
    """
    with _state_lock:
        snapshot = _toolkit_snapshot or os.environ.get("VULNHOUND_TOOLKIT_SNAPSHOT")

    def run_agent(agent_fn: Callable[[Any], Any]) -> Any:
        try:
            with agent_sandbox(snapshot) as sandbox:
                result = agent_fn(sandbox)
            return result
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(run_agent, agent_fns))


def make_run_tool(host: str) -> Callable[..., dict]:
    """Bind an agent-facing tool(command, timeout=120) to a trusted target host.

    Application code supplies deploy_target()['host']; never pass an
    LLM-selected host here. Each invocation gets its own pre-tooled sandbox and
    stops it afterward. Creating the callable itself performs no network calls.
    This also supports a target deployed by the application's owning process.
    """
    target, _ = _endpoint(host)

    def tool(command: str, timeout: int = 120) -> dict:
        if not allowed_command(command, target):
            raise ValueError("Command rejected: target or options are not allowed")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            raise ValueError("timeout must be a positive integer")
        with _state_lock:
            snapshot = _toolkit_snapshot or os.environ.get("VULNHOUND_TOOLKIT_SNAPSHOT")
        with agent_sandbox(snapshot) as sandbox:
            with _state_lock:
                _agent_targets[id(sandbox)] = target
            return run_tool(sandbox, command, timeout)

    return tool


def _run_task(code: str) -> TaskResult:
    result: TaskResult = {
        "success": False,
        "output": "",
        "exit_code": None,
        "error": None,
    }
    try:
        with sandbox_session() as sandbox:
            response = sandbox.process.code_run(code)
            result["output"] = response.result
            result["exit_code"] = response.exit_code
            result["success"] = response.exit_code == 0
            if not result["success"]:
                result["error"] = f"Code execution exited with status {response.exit_code}"
    except Exception as exc:
        result["success"] = False
        error = f"{type(exc).__name__}: {exc}"
        result["error"] = f"{result['error']}; {error}" if result["error"] else error
    return result


def run_parallel(tasks: list[str], max_workers: int = 10) -> list[TaskResult]:
    """Run each code string in its own sandbox, returning results in input order.

    Creation, execution, and stop failures are captured in the corresponding
    result instead of aborting the batch. At most max_workers sandboxes run at
    once; every sandbox that was created is stopped in a finally block.
    """
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(_run_task, tasks))


# Preview servers outlive serve(); close their sessions on normal Python exit.
_server_sessions = ExitStack()
atexit.register(_server_sessions.close)


def _preview_url(sandbox: Any, port: int) -> str:
    preview_api = getattr(sandbox, "preview", None)
    if callable(getattr(preview_api, "get_url", None)):
        preview = preview_api.get_url(port)
    elif callable(getattr(sandbox, "get_preview_link", None)):
        # Verified directly in the installed SDK; its preview API uses this name.
        preview = sandbox.get_preview_link(port)
    else:
        raise NotImplementedError(
            "Daytona SDK has no supported sandbox preview API"
        )
    url = preview if isinstance(preview, str) else preview.url
    if not isinstance(url, str) or urlsplit(url).scheme not in {"http", "https"}:
        raise ValueError("Daytona returned an invalid preview URL")
    _endpoint(url)
    return url


def _wait_ready(sandbox: Any, port: int = 3000, timeout: float = 300) -> None:
    """Poll HTTP locally without following redirects or requiring curl."""
    probe = (
        "import http.client; "
        f"c = http.client.HTTPConnection('127.0.0.1', {port}, timeout=2); "
        "c.request('GET', '/'); r = c.getresponse(); "
        "raise SystemExit(0 if 200 <= r.status < 400 else 1)"
    )
    deadline = time.monotonic() + timeout
    last_error = "No HTTP response"
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        try:
            response = sandbox.process.exec(
                shlex.join(["python3", "-c", probe]), timeout=max(1, min(5, int(remaining)))
            )
            if response.exit_code == 0:
                return
            last_error = response.result or f"probe exited with {response.exit_code}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(2, remaining))
    raise TimeoutError(f"Juice Shop did not become ready within {timeout:g}s: {last_error[-2000:]}")


_JUICE_SHOP_RUNTIME = r"""
set -eu
# 1) Prefer a working Docker daemon if one is actually present (portability).
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    docker rm -f vulnhound-juice-shop >/dev/null 2>&1 || true
    docker run -d -p 3000:3000 --name vulnhound-juice-shop "$IMAGE"
    exit 0
fi
# 2) Otherwise use Podman. Determine how to gain root: the Daytona sandbox runs
#    as an unprivileged user, and ROOTLESS Podman cannot work here (the nested
#    user namespace forbids newuidmap uid_map writes), so run as root.
if [ "$(id -u)" -eq 0 ]; then S="";
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then S="sudo -n";
else echo 'No container runtime: need Docker, root, or passwordless sudo' >&2; exit 1; fi
if ! command -v podman >/dev/null 2>&1; then
    $S apt-get update
    $S env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends podman
fi
# Force the vfs storage driver via config BEFORE the first podman call: 'overlay'
# is unsupported over the sandbox's overlayfs backing store (needs a mount_program
# that is unavailable), and once overlay initialises the config cannot be switched.
$S mkdir -p /etc/containers /var/lib/containers/storage /run/containers/storage
printf '[storage]\ndriver="vfs"\ngraphroot="/var/lib/containers/storage"\nrunroot="/run/containers/storage"\n' | $S tee /etc/containers/storage.conf >/dev/null
$S podman rm -f vulnhound-juice-shop >/dev/null 2>&1 || true
# --network=host avoids CNI/netavark netns setup (also restricted in the sandbox);
# Juice Shop binds 0.0.0.0:3000 in the host netns, i.e. the sandbox's real port 3000.
$S podman run -d --network=host --name vulnhound-juice-shop "$IMAGE"
"""


def _start_juice_shop(sandbox: Any) -> None:
    image = os.environ.get("JUICE_SHOP_IMAGE", "bkimminich/juice-shop")
    # Fully qualify a bare Docker Hub reference so Podman does not try to resolve
    # it interactively (a registry host has a '.' or ':' in its first segment).
    first = image.split("/", 1)[0]
    if "/" not in image or not ("." in first or ":" in first or first == "localhost"):
        image = "docker.io/" + image
    # A cold Juice Shop image pull under vfs can take a few minutes on a fresh
    # sandbox; give the whole provisioning step a generous timeout.
    script = "IMAGE=" + shlex.quote(image) + "\n" + _JUICE_SHOP_RUNTIME
    try:
        _exec_checked(sandbox, "sh -c " + shlex.quote(script), timeout=900)
        return
    except Exception as exc:
        _log.warning("Container runtime launch failed; trying npm fallback: %s", exc)

    # Juice Shop is a private source package without an npx executable. Fetch
    # the source via npm's degit CLI, then use its documented npm install/start.
    # A repository shorthand avoids embedding an infrastructure URL in code.
    source = os.environ.get("JUICE_SHOP_SOURCE", "juice-shop/juice-shop")
    script = f"""
set -eu
command -v npm >/dev/null 2>&1 || {{ echo 'npm is required for the Juice Shop fallback' >&2; exit 1; }}
npx --yes degit {shlex.quote(source)} /tmp/vulnhound-juice-shop
cd /tmp/vulnhound-juice-shop
CYPRESS_INSTALL_BINARY=0 npm install --include=dev --no-audit --no-fund
HOST=0.0.0.0 PORT=3000 NODE_ENV=production nohup npm start > /tmp/vulnhound-juice-shop.log 2>&1 < /dev/null &
"""
    _exec_checked(sandbox, "sh -c " + shlex.quote(script), timeout=600)


def deploy_target() -> dict:
    """Deploy our Juice Shop, wait up to 300s for HTTP, and register its host.

    Returns {sandbox_id, preview_url, host}. The target stays alive until normal
    Python shutdown. Failed setup always stops its sandbox. Docker is preferred;
    the npm source fallback requires a compatible Node.js runtime and npm.
    Optional JUICE_SHOP_IMAGE / JUICE_SHOP_SOURCE select image/source versions.
    No target URL or API key is hardcoded, and no remote host is adopted from an
    agent's command.
    """
    global _target_host
    with ExitStack() as pending:
        sandbox = pending.enter_context(sandbox_session(public=True))
        # Fail immediately if the configured SDK cannot supply a public preview.
        url = _preview_url(sandbox, 3000)
        _start_juice_shop(sandbox)
        _wait_ready(sandbox)
        host, _ = _endpoint(url)
        result = {"sandbox_id": sandbox.id, "preview_url": url, "host": host}
        with _state_lock:
            _server_sessions.enter_context(pending.pop_all())
            _target_sandboxes.append(sandbox)
            _target_host = host
        return result


def serve(port: int, start_cmd: str) -> str:
    """Launch a background server and return its public preview URL.

    The command must bind to 0.0.0.0 on the supplied port. Logs are written to
    /tmp/daytona-server.log inside the sandbox. The sandbox remains running
    until normal Python shutdown; failed setup stops it immediately. Returning
    a URL does not guarantee that the application has finished starting.

    Supports both the specified and installed SDK preview interfaces.
    """
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    if not isinstance(start_cmd, str) or not start_cmd.strip():
        raise ValueError("start_cmd must be a non-empty string")

    with ExitStack() as pending:
        sandbox = pending.enter_context(sandbox_session(public=True))
        url = _preview_url(sandbox, port)

        background_cmd = (
            f"nohup sh -c {shlex.quote(start_cmd)} "
            "> /tmp/daytona-server.log 2>&1 < /dev/null &"
        )
        response = sandbox.process.exec(f"sh -c {shlex.quote(background_cmd)}")
        if response.exit_code != 0:
            raise RuntimeError(f"Server launch failed: {response.result}")

        with _state_lock:
            _server_sessions.enter_context(pending.pop_all())
        return url


def deploy_app(python_code: str, port: int = 3000) -> dict:
    """Deploy a single-file (stdlib) Python web app into a public sandbox.

    Uploads the code, runs it on `port`, waits for HTTP readiness, and registers
    the target host for the allowlist. Returns {sandbox_id, preview_url, host}.
    Used to scan the bundled demo targets the same way Juice Shop is scanned.
    """
    global _target_host
    import base64
    b64 = base64.b64encode(python_code.encode()).decode()
    with ExitStack() as pending:
        sandbox = pending.enter_context(sandbox_session(public=True))
        url = _preview_url(sandbox, port)
        write = f"echo {shlex.quote(b64)} | base64 -d > /tmp/vulnhound_app.py"
        _exec_checked(sandbox, "sh -c " + shlex.quote(write), timeout=30)
        run = (f"nohup python3 /tmp/vulnhound_app.py {int(port)} "
               "> /tmp/vulnhound_app.log 2>&1 < /dev/null &")
        resp = sandbox.process.exec("sh -c " + shlex.quote(run))
        if resp.exit_code != 0:
            raise RuntimeError(f"App launch failed: {resp.result}")
        _wait_ready(sandbox, port)
        host, _ = _endpoint(url)
        result = {"sandbox_id": sandbox.id, "preview_url": url, "host": host}
        with _state_lock:
            _server_sessions.enter_context(pending.pop_all())
            _target_sandboxes.append(sandbox)
            _target_host = host
        return result


if __name__ == "__main__":
    # Pure local policy checks: running this module creates no sandboxes.
    demo_host = "owned-target.example"
    demo_cases = [
        (f"nmap -sV -p 3000 {demo_host}", True),
        (f"curl -sSI https://{demo_host}/", True),
        ("curl http://127.0.0.1:3000/", True),
        (f"sqlmap -u 'https://{demo_host}/api?id=1' --batch", True),
        (f"gobuster dir -u https://{demo_host}/ -w /usr/share/dirb/wordlists/common.txt", True),
        ("nmap external.example", False),
        (f"curl https://{demo_host}.external.example/", False),
        (f"curl https://{demo_host}/; whoami", False),
        (f"curl -L https://{demo_host}/", False),
        (f"curl --proxy http://external.example https://{demo_host}/", False),
        (f"curl -H 'Host: external.example' https://{demo_host}/", False),
        (f"nmap --script unsafe.nse {demo_host}", False),
        ("curl http://127.0.0.1:8000/", False),
    ]
    failures = 0
    for demo_command, expected in demo_cases:
        passed = allowed_command(demo_command, demo_host) == expected
        failures += not passed
        print(f"{'PASS' if passed else 'FAIL'}: {demo_command}")
    raise SystemExit(1 if failures else 0)
