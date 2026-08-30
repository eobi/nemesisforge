"""A Model Context Protocol server over stdio.

JSON-RPC 2.0, line-delimited, standard library only. The engine core makes that promise and
a tool surface that needs a package index breaks it exactly when the engine is most useful:
offline, in a container, on a machine nobody wants to give an index to.

STDOUT IS THE PROTOCOL. One stray print corrupts the stream and the client sees a parse
error instead of the thing you were trying to say. Diagnostics go to stderr.
"""
from __future__ import annotations

import json
import sys
import traceback
from typing import Optional

from . import rings, safety

PROTOCOL_VERSION = "2024-11-05"
SERVER = {"name": "nemesis-forge", "version": "1.0.0"}


class Server:
    def __init__(self, target_root: Optional[str] = None, ring2: bool = False,
                 max_ring: int = 1) -> None:
        self.session = rings.Session(
            target_root=safety.Root.of(target_root) if target_root else None,
            ring2_enabled=ring2)
        self.max_ring = rings.RING2 if ring2 else max_ring

    # ── plumbing ──────────────────────────────────────────────────────────────
    def _log(self, msg: str) -> None:
        print(f"[nemesis-forge-mcp] {msg}", file=sys.stderr, flush=True)

    def _send(self, obj: dict) -> None:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    def _reply(self, rid, result: dict) -> None:
        self._send({"jsonrpc": "2.0", "id": rid, "result": result})

    def _error(self, rid, code: int, message: str) -> None:
        self._send({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})

    # ── methods ───────────────────────────────────────────────────────────────
    def _initialize(self, rid, _params: dict) -> None:
        self._reply(rid, {"protocolVersion": PROTOCOL_VERSION,
                          "capabilities": {"tools": {}},
                          "serverInfo": SERVER})

    def _tools_list(self, rid, _params: dict) -> None:
        self._reply(rid, {"tools": [
            {"name": t.name, "description": t.description, "inputSchema": t.schema}
            for t in rings.tools_for(self.max_ring)]})

    def _tools_call(self, rid, params: dict) -> None:
        name = params.get("name", "")
        args = params.get("arguments") or {}
        tool = rings.by_name(name)
        if tool is None:
            self._error(rid, -32601, f"no such tool: {name}")
            return
        if tool.ring > self.max_ring:
            # Refused by RING, not by argument. Saying which ring and how to enable it is
            # the difference between a wall and a door with a lock on it.
            self.session.record(name, False, "ring refused")
            self._reply(rid, {"content": [{"type": "text", "text": json.dumps({
                "error": f"{name} is ring {tool.ring}; this server runs at ring "
                         f"{self.max_ring}",
                "enable": "--ring2" if tool.ring == rings.RING2 else "--max-ring 1",
            })}], "isError": True})
            return
        try:
            out = tool.fn(self.session, **args)
            ok = "error" not in out
        except safety.RootError as e:
            out, ok = {"error": str(e)}, False
        except Exception as e:                                   # noqa: BLE001
            self._log(traceback.format_exc().strip().splitlines()[-1])
            out, ok = {"error": f"{type(e).__name__}: {e}"}, False
        self.session.record(name, ok)
        self._reply(rid, {"content": [{"type": "text",
                                       "text": json.dumps(out, indent=2, default=str)}],
                          "isError": not ok})

    # ── loop ──────────────────────────────────────────────────────────────────
    def serve(self) -> int:
        self._log(f"ready; ring<= {self.max_ring}; root="
                  f"{self.session.target_root.path if self.session.target_root else 'unset'}")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            rid, method = msg.get("id"), msg.get("method", "")
            params = msg.get("params") or {}
            if method == "initialize":
                self._initialize(rid, params)
            elif method in ("notifications/initialized", "initialized"):
                continue
            elif method == "tools/list":
                self._tools_list(rid, params)
            elif method == "tools/call":
                self._tools_call(rid, params)
            elif method == "ping":
                self._reply(rid, {})
            elif rid is not None:
                self._error(rid, -32601, f"unsupported method: {method}")
        return 0
