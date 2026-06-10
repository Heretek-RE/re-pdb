"""MCP server entry point for re-pdb.

Exposes debug-PDB download primitives to Claude Code via the
Model Context Protocol stdio transport.

Two download paths:

* ``download_msdl`` — the Microsoft Symbol Server
  (``msdl.microsoft.com``). Always permitted.
* ``download_custom`` — a non-msdl URL. **Refused by default.**
  Set ``RE_PDB_ALLOW_PUBLIC=1`` in the env to permit non-msdl
  hosts; the override is recorded in the response so the analyst
  can audit the download after the fact.

The server never writes outside the user-specified output path
and never republishes the PDB.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from re_pdb import msdl

mcp = FastMCP("re-pdb")

logger = logging.getLogger("re_pdb")
logger.setLevel(logging.INFO)


# ── Health ──────────────────────────────────────────────────────────────


@mcp.tool()
def check_pdb() -> dict:
    """Return msdl reachability + httpx availability.

    Probes the Microsoft Symbol Server's index (a tiny HEAD
    request) to confirm the analyst's network can reach it. A
    404 on the URL is fine — that just means the probe path
    doesn't exist; what we're testing is the TCP / TLS
    handshake.
    """
    import importlib.util

    httpx_spec = importlib.util.find_spec("httpx")
    if httpx_spec is None:
        return {
            "server": "re-pdb",
            "version": "0.1.0",
            "status": "WARN",
            "httpx_available": False,
            "msdl_reachable": False,
            "allow_public_opt_in": os.environ.get("RE_PDB_ALLOW_PUBLIC") == "1",
            "install_hint": "pip install httpx",
        }
    import httpx

    reachable = False
    http_status: int | None = None
    reason = "not probed"
    try:
        resp = httpx.head(
            "https://msdl.microsoft.com/download/symbols/",
            timeout=5,
            follow_redirects=True,
        )
        http_status = resp.status_code
        reachable = resp.status_code < 500
        reason = f"HTTP {resp.status_code}"
    except Exception as exc:  # noqa: BLE001
        reason = f"connection failed: {exc}"

    return {
        "server": "re-pdb",
        "version": "0.1.0",
        "status": "OK" if reachable else "WARN",
        "httpx_available": True,
        "msdl_reachable": reachable,
        "msdl_probe": reason,
        "msdl_http_status": http_status,
        "allow_public_opt_in": os.environ.get("RE_PDB_ALLOW_PUBLIC") == "1",
    }


# ── Download primitives ─────────────────────────────────────────────────


def _validate_path_out(path: str) -> tuple[Path | None, dict | None]:
    """Resolve the user-specified output path and ensure it is
    writable. Returns ``(Path, None)`` on success, ``(None, err)``
    on failure. The ``err`` dict is suitable for direct return to
    the MCP caller.
    """
    if not path:
        return None, {
            "status": "ERROR",
            "error": "out path is empty; provide the path where the PDB should be written",
        }
    out = Path(path).expanduser()
    # Reject paths that try to walk up the filesystem into
    # already-shipped directories. The user is the only writer;
    # the server does not protect against the user shooting
    # themselves, but it does reject obvious DMZ escapes
    # (writing to /etc, /sys, /proc).
    resolved = out.resolve()
    if str(resolved).startswith(("/proc", "/sys", "/dev")):
        return None, {
            "status": "ERROR",
            "error": f"refusing to write to a system path: {resolved}",
        }
    parent = out.parent
    if not parent.exists():
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return None, {
                "status": "ERROR",
                "error": f"cannot create output directory: {exc}",
            }
    return out, None


def _download(url: str) -> dict:
    """Issue the actual HTTP GET and return a result dict.

    The dict has the shape::

        {
          "url": "...",
          "status": "OK" | "ERROR",
          "http_status": int | None,
          "bytes_written": int | None,
          "content_type": str | None,
          "sha256": str | None,
          "reason": "..."
        }

    On a 404 the dict has ``status: "ERROR"`` and
    ``http_status: 404``; the caller (MCP tool) surfaces that to
    the analyst.
    """
    import httpx

    try:
        resp = httpx.get(url, timeout=60, follow_redirects=True)
    except Exception as exc:  # noqa: BLE001
        return {
            "url": url,
            "status": "ERROR",
            "http_status": None,
            "bytes_written": None,
            "content_type": None,
            "sha256": None,
            "reason": f"connection failed: {exc}",
        }
    # A16 fix (v2.8.0): reclassify HTTP 404 from "ERROR" to a clearer
    # "not_found" status. Per stress testing, some publishers
    # do not publish their internal
    # PDBs to the Microsoft Symbol Server — 404 is the EXPECTED
    # response for any shipped commercial game binary, not a tool
    # error. The "ERROR" label was misleading the agent into thinking
    # the tool itself had failed.
    if resp.status_code == 200:
        status = "OK"
        reason = "ok"
    elif resp.status_code == 404:
        status = "not_found"
        reason = (
            "HTTP 404 — publisher does not publish this PDB to MSDL "
            "(expected for shipped commercial game binaries; not a tool error)"
        )
    else:
        status = "ERROR"
        reason = f"HTTP {resp.status_code}"
    return {
        "url": url,
        "status": status,
        "http_status": resp.status_code,
        "bytes_written": len(resp.content) if resp.content else 0,
        "content_type": resp.headers.get("content-type"),
        "sha256": None,  # populated by the caller after writing to disk
        "reason": reason,
        # The raw bytes are attached under a non-serialisable key;
        # the MCP wrapper pops this off before returning JSON.
        "_content": resp.content,
    }


@mcp.tool()
def download_msdl(guid: str, age: str | int, basename: str, out: str) -> dict:
    """Download a PDB from the Microsoft Symbol Server.

    Args:
        guid: PDB GUID (any standard form — with or without dashes,
            lower- or upper-case). 32 hex digits total.
        age: PDB age (1-3 hex digits; pass as int or hex string).
            The age is what differentiates two builds of the same
            source tree — the GUID identifies the source, the
            age identifies the build.
        basename: PDB file name, e.g. ``foo.pdb``. Must match the
            file's RSDS debug-record reference.
        out: filesystem path where the PDB will be written. The
            parent directory is created if it does not already
            exist.

    Returns::

        {
          "status": "OK" | "ERROR",
          "out": "...",
          "url": "https://msdl.microsoft.com/...",
          "http_status": 200,
          "bytes_written": N,
          "sha256": "...",
          "reason": "ok"
        }
    """
    try:
        norm_guid = msdl.normalise_guid(guid)
        norm_age = msdl.normalise_age(age)
    except ValueError as exc:
        return {
            "status": "ERROR",
            "out": out,
            "error": str(exc),
        }
    if not basename or "/" in basename or "\\" in basename or ".." in basename:
        return {
            "status": "ERROR",
            "out": out,
            "error": f"basename must be a plain filename, not a path: {basename!r}",
        }
    target, err = _validate_path_out(out)
    if err is not None:
        return {**err, "out": out}

    url = msdl.build_msdl_url(basename, norm_guid, norm_age)
    result = _download(url)
    if result["status"] != "OK":
        return {
            "status": "ERROR",
            "out": out,
            "url": url,
            "http_status": result["http_status"],
            "reason": result["reason"],
        }
    # Write the bytes; compute sha256 at the same time.
    import hashlib
    content = result.pop("_content") or b""
    h = hashlib.sha256()
    h.update(content)
    try:
        target.write_bytes(content)
    except OSError as exc:
        return {
            "status": "ERROR",
            "out": out,
            "url": url,
            "error": f"failed to write PDB: {exc}",
        }
    return {
        "status": "OK",
        "out": str(target),
        "url": url,
        "http_status": result["http_status"],
        "bytes_written": len(content),
        "sha256": h.hexdigest(),
        "content_type": result["content_type"],
        "reason": "ok",
    }


@mcp.tool()
def download_custom(url: str, out: str) -> dict:
    """Download a PDB from a non-msdl URL. **Disabled by default.**

    The Microsoft Symbol Server is the only public symbol host in
    common use. To prevent accidental downloads from a typo'd
    publisher-internal URL, this tool refuses any URL whose host
    is not in the default allowlist. The analyst can opt in by
    setting ``RE_PDB_ALLOW_PUBLIC=1`` in the env; the override
    is recorded in the response so the download is auditable.

    Args:
        url: full URL to the PDB (http or https)
        out: filesystem path where the PDB will be written

    Returns::

        {
          "status": "OK" | "ERROR",
          "out": "...",
          "url": "...",
          "public_opt_in_used": bool,
          ...
        }
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {
            "status": "ERROR",
            "out": out,
            "url": url,
            "error": f"unsupported scheme: {parsed.scheme!r} (need http or https)",
        }
    host = parsed.hostname or ""
    allowlist = list(msdl.DEFAULT_ALLOWLIST)
    public_opt_in = os.environ.get("RE_PDB_ALLOW_PUBLIC") == "1"
    if not public_opt_in and not msdl.is_allowed_host(host, allowlist):
        return {
            "status": "ERROR",
            "out": out,
            "url": url,
            "host": host,
            "allowlist": allowlist,
            "public_opt_in_used": False,
            "error": (
                "non-msdl host refused. To permit, set RE_PDB_ALLOW_PUBLIC=1 "
                "in the MCP server's env. The override is recorded in the "
                "response when used."
            ),
        }
    target, err = _validate_path_out(out)
    if err is not None:
        return {**err, "out": out, "url": url, "public_opt_in_used": public_opt_in}

    result = _download(url)
    if result["status"] != "OK":
        return {
            "status": "ERROR",
            "out": out,
            "url": url,
            "public_opt_in_used": public_opt_in,
            "http_status": result["http_status"],
            "reason": result["reason"],
        }
    import hashlib
    content = result.pop("_content") or b""
    h = hashlib.sha256()
    h.update(content)
    try:
        target.write_bytes(content)
    except OSError as exc:
        return {
            "status": "ERROR",
            "out": out,
            "url": url,
            "public_opt_in_used": public_opt_in,
            "error": f"failed to write PDB: {exc}",
        }
    return {
        "status": "OK",
        "out": str(target),
        "url": url,
        "public_opt_in_used": public_opt_in,
        "http_status": result["http_status"],
        "bytes_written": len(content),
        "sha256": h.hexdigest(),
        "content_type": result["content_type"],
        "reason": "ok",
    }


# ── Local PDB parse ────────────────────────────────────────────────────


@mcp.tool()
def parse_pdb(path: str, max_symbols: int = 5000, max_types: int = 2000) -> dict:
    """Parse a local PDB file and return a structured summary.

    This is the read-side companion to :func:`download_msdl` /
    :func:`download_custom` — the latter fetch a PDB; this one
    reads one. The parser uses the ``pefile``-style CodeView
    stream + the PDB stream reader in :mod:`re_pdb.parser`.

    Args:
        path: path to a local ``.pdb`` file
        max_symbols: cap on the returned symbol list (default 5000)
        max_types: cap on the returned type list (default 2000)

    Returns::

        {
          "status": "OK" | "ERROR",
          "path": "...",
          "size": N,
          "signature": "...",
          "age": N,
          "guid": "...",
          "machine": "...",
          "symbols": [{"name": "...", "address": 0x..., "section": N, "kind": "..."}, ...],
          "types": [{"id": N, "kind": "...", "name": "..."}, ...],
          "truncated": bool
        }

    On a missing / unreadable / non-PDB file, returns
    ``{"status": "ERROR", "error": "..."}`` without raising.

    The parser is pure-stdlib (no third-party PDB reader
    required); it handles the canonical CodeView 4.0 + 7.0
    streams and a subset of the type stream. For deeper
    parsing (full UDT expansion, source-line mapping) use
    a third-party tool.
    """
    from pathlib import Path
    p = Path(path)
    if not p.is_file():
        return {"status": "ERROR", "path": path, "error": "file not found"}
    try:
        size = p.stat().st_size
    except OSError as exc:
        return {"status": "ERROR", "path": path, "error": f"stat failed: {exc}"}
    try:
        data = p.read_bytes()
    except OSError as exc:
        return {"status": "ERROR", "path": path, "error": f"read failed: {exc}"}
    # PDB signature: "Microsoft C/C++ MSF 7.00" at offset 0
    if size < 64 or not data.startswith(b"Microsoft C/C++ MSF"):
        return {
            "status": "ERROR",
            "path": path,
            "size": size,
            "error": "not a recognized PDB file (missing MSF signature)",
        }
    try:
        from re_pdb import parser as pdb_parser
        parsed = pdb_parser.parse_pdb_bytes(data, max_symbols=max_symbols, max_types=max_types)
    except ImportError:
        return {
            "status": "ERROR",
            "path": path,
            "size": size,
            "error": "re_pdb.parser module not available; reinstall the re-pdb package",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "ERROR",
            "path": path,
            "size": size,
            "error": f"parse failed: {exc}",
        }
    return {
        "status": "OK",
        "path": path,
        "size": size,
        "signature": parsed.get("signature"),
        "age": parsed.get("age"),
        "guid": parsed.get("guid"),
        "machine": parsed.get("machine"),
        "symbols": parsed.get("symbols", []),
        "types": parsed.get("types", []),
        "symbol_count": len(parsed.get("symbols", [])),
        "type_count": len(parsed.get("types", [])),
        "truncated": parsed.get("truncated", False),
    }


# ── Entrypoint ─────────────────────────────────────────────────────────


def main() -> None:
    """Run the MCP server over stdio (the standard Claude Code transport)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
