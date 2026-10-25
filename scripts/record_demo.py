"""Record the zero-config demo as an asciicast, from a real run.

    python scripts/record_demo.py --out docs/demo.cast
    npx svg-term-cli --in docs/demo.cast --out docs/demo.svg --window --width 96 --height 36

Everything shown is produced by the actual binaries: this script builds cmd/rinwall and
cmd/mockupstream, starts the mock MCP server, starts the proxy in zero-config mode in
front of it, and makes the HTTP calls a person would make with curl. The typed commands
are rendered keystroke by keystroke for the recording; the output under each one is the
byte-for-byte response the equivalent curl would have printed. Nothing is scripted
text pretending to be output.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import random
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

PROXY = "http://127.0.0.1:8080"
UPSTREAM = "http://127.0.0.1:8000/mcp"


class Cast:
    def __init__(self, width: int, height: int):
        self.t = 0.0
        self.events: list[tuple[float, str]] = []
        self.header = {
            "version": 2, "width": width, "height": height, "timestamp": int(time.time()),
            "title": "RinWall: zero-config in front of an MCP server",
            "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
        }
        self.rng = random.Random(7)

    def out(self, s: str, dt: float = 0.0) -> None:
        self.t += dt
        self.events.append((round(self.t, 3), s))

    def prompt(self) -> None:
        self.out("\x1b[1;32m$\x1b[0m ", 0.4)

    def type(self, cmd: str) -> None:
        for ch in cmd:
            self.out(ch, self.rng.uniform(0.02, 0.06) if ch != " " else 0.08)
        self.out("\r\n", 0.35)

    def lines(self, text: str, per_line: float = 0.03) -> None:
        for line in text.rstrip("\n").split("\n"):
            self.out(line + "\r\n", per_line)

    def comment(self, s: str) -> None:
        self.out(f"\x1b[2m# {s}\x1b[0m\r\n", 0.6)

    def write(self, path: str) -> None:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(self.header) + "\n")
            for t, s in self.events:
                f.write(json.dumps([t, "o", s]) + "\n")


def http(method: str, url: str, body: dict | None = None, token: str | None = None) -> tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def pretty(raw: str) -> str:
    try:
        return json.dumps(json.loads(raw), indent=2)
    except json.JSONDecodeError:
        return raw


def wait_for(url: str, seconds: float = 30) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)
            return
        except urllib.error.HTTPError:
            return
        except Exception:
            time.sleep(0.3)
    raise SystemExit(f"timed out waiting for {url}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="docs/demo.cast")
    ap.add_argument("--width", type=int, default=96)
    ap.add_argument("--height", type=int, default=36)
    args = ap.parse_args()

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    work = tempfile.mkdtemp(prefix="jitdemo-")
    ext = ".exe" if os.name == "nt" else ""
    proxy_bin = os.path.join(work, "rinwall" + ext)
    mock_bin = os.path.join(work, "mockupstream" + ext)
    subprocess.check_call(["go", "build", "-o", proxy_bin, "./cmd/rinwall"], cwd=repo)
    subprocess.check_call(["go", "build", "-o", mock_bin, "./cmd/mockupstream"], cwd=repo)

    procs = []
    try:
        mock = subprocess.Popen([mock_bin], cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(mock)
        wait_for("http://127.0.0.1:8000/users/42")

        cast = Cast(args.width, args.height)
        cast.comment("an MCP server is already running on :8000 - the one you want to put an agent in front of")
        cast.prompt()
        cast.type(f"rinwall --mcp {UPSTREAM}")

        # Zero-config mode keeps its state under the OS temp dir and prints
        # the paths in its banner; point it at a neutral directory so the
        # recording does not carry a username from whichever machine made it.
        tmp = os.path.join(os.path.splitdrive(work)[0] + os.sep if os.name == "nt" else "/", "tmp")
        os.makedirs(tmp, exist_ok=True)
        env = {**os.environ, "TMP": tmp, "TEMP": tmp, "TMPDIR": tmp}
        proxy = subprocess.Popen([proxy_bin, "--mcp", UPSTREAM], cwd=work, env=env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        procs.append(proxy)
        # Read stderr on a thread and stop once the banner has been quiet for
        # a moment: the process keeps running (and the pipe open), so a
        # blocking readline would never return after the banner.
        q: queue.Queue[str] = queue.Queue()
        threading.Thread(target=lambda: [q.put(l) for l in proxy.stderr], daemon=True).start()
        banner = []
        token = None
        t0 = time.time()
        while time.time() - t0 < 40:
            try:
                line = q.get(timeout=1.5)
            except queue.Empty:
                if token:
                    break
                continue
            banner.append(line.rstrip("\n"))
            m = re.match(r"\s+(eyJ[A-Za-z0-9_.-]+)\s*$", line)
            if m:
                token = m.group(1)
        if not token:
            raise SystemExit("no reviewer token in banner:\n" + "\n".join(banner))
        # The banner, exactly as printed, with two presentation changes: the
        # proxy's timestamped log lines before it (local paths, nothing a
        # viewer needs) are omitted, and the long reviewer token is
        # shortened on screen.
        for line in banner:
            if re.match(r"\d{4}/\d\d/\d\d \d\d:\d\d:\d\d ", line):
                continue
            shown = line if not line.strip().startswith("eyJ") else "    " + token[:28] + "..." + token[-6:]
            cast.out(shown + "\r\n", 0.045)
        cast.out("\r\n", 1.6)

        wait_for(PROXY + "/biscuit-keys")
        time.sleep(1.5)  # let the mock upstream pick up the proxy's keys

        def call(tool: str, args_: dict, note: str) -> dict:
            body = {"agent_id": "demo", "tool": tool, "args": args_}
            cast.comment(note)
            cast.prompt()
            cast.type(f"curl -s {PROXY}/tool-call -d '{json.dumps(body, separators=(',', ':'))}' | python -m json.tool")
            _, raw = http("POST", PROXY + "/tool-call", body)
            cast.lines(pretty(raw))
            cast.out("\r\n", 1.4)
            return json.loads(raw)

        call("mcp_get_user", {"user_id": "42"}, "a read: executes freely")
        pending = call("mcp_close_account", {"user_id": "42"},
                       "irreversible: nothing reaches the upstream until a human approves it")
        rid = pending.get("request_id")
        if not rid:
            raise SystemExit("expected pending_approval, got: " + json.dumps(pending))

        rhash = pending["request_hash"]
        cast.comment("the reviewer token from the banner approves it, bound to that exact request hash")
        cast.prompt()
        cast.type(f'curl -s -X POST {PROXY}/approvals/{rid}/approve -H "Authorization: Bearer $REVIEWER" '
                  f"-d '{{\"hash\":\"{rhash}\"}}' | python -m json.tool")
        _, raw = http("POST", f"{PROXY}/approvals/{rid}/approve", {"hash": rhash}, token)
        cast.lines(pretty(raw))
        cast.out("\r\n", 1.4)

        call("mcp_get_user", {"user_id": "42"}, "the same read now shows the approved change")
        cast.out("", 3.0)

        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        cast.write(args.out)
        print("wrote", args.out, f"({len(cast.events)} events, {cast.t:.1f}s)")
    finally:
        for p in procs:
            p.kill()


if __name__ == "__main__":
    main()
