"""Stage 10: verify source modules in unpublished Smite images.

Run offline through GitHub Actions: docker cp this helper into a disposable
container, followed by docker exec (without starting application services).
No network calls, pairing, Docker activation or writes to user servers.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys


REQUIRED = {
    "panel": (
        "main.py",
        "app/node_auth.py",
        "app/node_pairing_store.py",
        "app/agent_request_signer.py",
        "app/signed_agent_transport.py",
        "app/signed_node_registration.py",
        "app/routers/node_pairing.py",
        "app/routers/signed_nodes.py",
        "app/routers/nodes.py",
        "app/node_client.py",
    ),
    "node": (
        "main.py",
        "app/node_auth.py",
        "app/agent_auth.py",
        "app/signed_panel_client.py",
        "app/panel_client.py",
        "app/routers/agent.py",
    ),
}


def smoke(*, role: str, root: Path = Path("/app")) -> list[str]:
    if role not in REQUIRED:
        raise ValueError("Unknown image role")
    lines = []
    for filename in REQUIRED[role]:
        source = root / filename
        if source.is_symlink() or not source.is_file():
            raise RuntimeError(f"Missing application module: {filename}")
        # Compile in memory: do not create .pyc in production image.
        compile(source.read_bytes(), str(source), "exec")
        lines.append("SOURCE_PRESENT=" + filename)
    if role == "panel":
        if not (root / "static/index.html").is_file():
            raise RuntimeError("Panel frontend assets absent")
        lines.append("PANEL_FRONTEND=BUILT")
    else:
        code = (root / "app/routers/agent.py").read_text()
        if "dependencies=[Depends(require_agent_auth)]" not in code:
            raise RuntimeError("Signed Agent dependency missing")
        code = (root / "main.py").read_text()
        if '@app.get("/")' not in code:
            raise RuntimeError("Strict-safe unauthenticated liveness route missing")
        lines.append("STRICT_AGENT_ROUTER=AVAILABLE")
    lines.append("IMAGE_SOURCE_SMOKE=PASSED")
    lines.append("IMAGE_RUNTIME_SECURITY=NOT_ACTIVATED")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("panel", "node"), required=True)
    parser.add_argument("--root", type=Path, default=Path("/app"))
    args = parser.parse_args()
    try:
        for line in smoke(role=args.role, root=args.root):
            print(line)
        return 0
    except (RuntimeError, OSError, UnicodeError, SyntaxError, ValueError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
