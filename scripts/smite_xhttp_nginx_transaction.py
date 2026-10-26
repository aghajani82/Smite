#!/usr/bin/env python3
"""Local root-only XHTTP route transaction; NOT a remote Agent endpoint.

An administrator must explicitly provision a *dedicated* Nginx include inside
the intended TLS/443 server BEFORE this helper can apply any route.
The helper never changes that include, existing U-OPTI routes, or FRPS.

This is an independently testable host helper foundation. No Panel/Node
wiring, signed inventory import, installer or production rollout is implied.
"""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from smite_xhttp_nginx_plan import plan_xhttp_nginx_route, RouteAdmissionDenied

ROUTE_DIR = Path("/etc/nginx/smite-xhttp-routes")
BRIDGE = Path("/etc/nginx/smite-xhttp-bridge.conf")
LOCK_FILE = "/run/lock/smite-xhttp-nginx-route.lock"
BIN = "/usr/sbin/nginx"

# Only generated locations for numeric-port XHTTP paths are considered. All
# other names in nginx -T can coexist, but an exact or prefix clash is denied.
LOCATION = re.compile(r"^\s*location\s+(?:=\s*|\^~\s*)(/[0-9]+(?:/[A-Za-z0-9_-]+)*/?)\s*\{", re.M)
BIND = re.compile(r'"frps",pid=(\d+)(?:,|[)])')


class RouteTransactionHold(RuntimeError):
    pass


def _safe_file(path: Path) -> None:
    info = path.lstat()  # Never follow a symlink.
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022):
        raise RouteTransactionHold("UNTRUSTED_FILE")


def _safe_directory(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022):
        raise RouteTransactionHold("UNTRUSTED_ROUTE_DIRECTORY")


def _run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=25)
    if result.returncode:
        # Do not echo process stderr; it may reveal unrelated config.
        raise RouteTransactionHold("COMMAND_FAILED")
    return result.stdout


def _frps_socket_inventory() -> tuple[int, frozenset[int]]:
    """Strictly require :7000 and all owned proxy sockets on loopback.

    No user-supplied PID, process name, or listen list is considered proof.
    """
    sockets = _run(["/usr/bin/ss", "-Hlntp"])
    observed: dict[int, int] = {}
    all_frps: list[tuple[str, int]] = []
    for line in sockets.splitlines():
        columns = line.split(maxsplit=5)
        if len(columns) < 6:
            continue
        local = columns[3]
        pid = BIND.search(columns[5])
        if not pid:
            continue
        process_pid = int(pid.group(1))
        all_frps.append((local, process_pid))
        match = re.fullmatch(r"127\.0\.0\.1:(\d+)", local)
        if not match:
            continue
        port = int(match.group(1))
        if port in observed:
            raise RouteTransactionHold("DUPLICATE_FRPS_LISTENER")
        observed[port] = process_pid
    if 7000 not in observed:
        raise RouteTransactionHold("FRPS_OWNER_7000_MISSING")
    owner_pid = observed[7000]
    # Every socket owned by this FRPS must be loopback. Reject wildcard and
    # IPv6/public listeners even if the control port itself is loopback.
    if any(
        pid == owner_pid and re.fullmatch(r"127\.0\.0\.1:\d+", local) is None
        for local, pid in all_frps
    ):
        raise RouteTransactionHold("FRPS_PUBLIC_BIND_FORBIDDEN")
    owned = frozenset(port for port, pid in observed.items() if pid == owner_pid)
    if len(owned) < 2:
        raise RouteTransactionHold("FRPS_PROXY_NOT_PRESENT")
    return owner_pid, owned


class LocalNginxRouteTransaction:
    """Runs only under explicit local root access, guarded and lock serialized."""

    def __init__(self, *, route_dir: Path = ROUTE_DIR, bridge: Path = BRIDGE,
                 nginx_binary: str = BIN):
        self.route_dir = route_dir
        self.bridge = bridge
        self.nginx_binary = nginx_binary

    def _preflight(self, port: int, path: str) -> tuple[str, str, int, frozenset[int], Path]:
        if os.geteuid() != 0:
            raise RouteTransactionHold("ROOT_REQUIRED")
        _safe_directory(self.route_dir)
        _safe_file(self.bridge)
        directive = f"include {self.route_dir}/*.conf;"
        if self.bridge.read_text().strip() != directive:
            raise RouteTransactionHold("BRIDGE_CONTENT_UNAPPROVED")

        # Nginx must actually load the pre-approved bridge, not merely have a
        # file with the expected name. The bridge must have been independently
        # installed in the intended TLS/443 server (installer's responsibility).
        _run([self.nginx_binary, "-t"])
        active = _run([self.nginx_binary, "-T"])
        if f"# configuration file {self.bridge}:" not in active or directive not in active:
            raise RouteTransactionHold("BRIDGE_NOT_INCLUDED")
        old_pid, old_ports = _frps_socket_inventory()
        if port not in old_ports:
            raise RouteTransactionHold("SIGNED_FRPS_PORT_NOT_LISTENING")

        planned = plan_xhttp_nginx_route(
            {"port": port, "path": path, "network": "xhttp",
             "protocol": "vless", "listen": "127.0.0.1", "enabled": True},
            registered_routes={}, frps_listener_ports=set(old_ports),
        )
        target = self.route_dir / f"{port}.conf"
        # Reject active routes in any server/file; also reject other routes
        # to the same port (even if path is different). Existing unmanaged
        # /49328/sso on IR intentionally HOLDs rather than overwriting it.
        active_locations = {p.rstrip("/") for p in LOCATION.findall(active)}
        for existing in active_locations:
            if (existing == path or existing.startswith(path + "/")
                    or path.startswith(existing + "/")):
                raise RouteTransactionHold("EXISTING_NGINX_PATH_COLLISION")
        if re.search(r"127\.0\.0\.1:" + str(port) + r"\b", active):
            raise RouteTransactionHold("EXISTING_NGINX_UPSTREAM_COLLISION")
        if target.is_symlink() or target.exists():
            raise RouteTransactionHold("ROUTE_FILE_ALREADY_EXISTS")

        return planned.snippet, active, old_pid, old_ports, target

    def check(self, port: int, path: str) -> None:
        self._preflight(port, path)

    def apply(self, port: int, path: str) -> None:
        # Lockfile directory is provisioned by the OS; never accept a
        # caller-controlled lock path. No silent fallback on lock failures.
        fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_uid != 0 or stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
                raise RouteTransactionHold("UNTRUSTED_LOCK_FILE")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            snippet, _, before_pid, before_ports, target = self._preflight(port, path)
            # The target is a new file only. Existing files, incl. 45121, are
            # never rewritten. Atomic replacement into a fixed root-only dir.
            staged_fd, staged_path = tempfile.mkstemp(prefix=".smite-stage-", dir=self.route_dir)
            committed = False
            try:
                with os.fdopen(staged_fd, "w") as out:
                    os.fchmod(out.fileno(), 0o600)
                    out.write(snippet)
                    out.flush()
                    os.fsync(out.fileno())
                # Re-check the target before committing; concurrent writers
                # must still be excluded by the trusted installer ownership.
                if target.exists() or target.is_symlink():
                    raise RouteTransactionHold("ROUTE_FILE_RACE")
                os.replace(staged_path, target)
                committed = True
                try:
                    _run([self.nginx_binary, "-t"])
                    _run([self.nginx_binary, "-s", "reload"])
                    # Verify that the owner socket and every prior proxy socket
                    # remain owned by the same FRPS PID.
                    after_pid, after_ports = _frps_socket_inventory()
                    if after_pid != before_pid or not before_ports.issubset(after_ports):
                        raise RouteTransactionHold("FRPS_RUNTIME_CHANGED")
                except Exception:
                    # Remove only our just-created file. Never restore/overwrite
                    # unrelated Nginx configs; attempt to reload last valid config.
                    target.unlink(missing_ok=True)
                    try:
                        _run([self.nginx_binary, "-t"])
                        _run([self.nginx_binary, "-s", "reload"])
                    except Exception:
                        raise RouteTransactionHold("ROLLBACK_NEEDS_OPERATOR")
                    raise
            finally:
                if not committed:
                    Path(staged_path).unlink(missing_ok=True)
        finally:
            os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description="Privileged local XHTTP route gate")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--path", required=True)
    parser.add_argument("--apply", action="store_true", help="Explicit local administrator transaction")
    parser.add_argument("--confirm-local-root", action="store_true")
    args = parser.parse_args()
    try:
        manager = LocalNginxRouteTransaction()
        if args.apply:
            if not args.confirm_local_root:
                raise RouteTransactionHold("EXPLICIT_APPROVAL_REQUIRED")
            manager.apply(args.port, args.path)
            print("RESULT=PASS_LOCAL_NGINX_ROUTE_CREATED")
        else:
            manager.check(args.port, args.path)
            print("RESULT=PASS_LOCAL_READ_ONLY")
        print("FRPS_RESTART=NO")
        return 0
    except (RouteTransactionHold, RouteAdmissionDenied, OSError, subprocess.TimeoutExpired, BlockingIOError):
        print("RESULT=HOLD_FAIL_CLOSED")
        return 2


if __name__ == "__main__":
    sys.exit(main())
