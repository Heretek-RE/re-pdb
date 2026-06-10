"""Minimal local PDB parser used by :func:`re_pdb.server.parse_pdb`.

Handles the canonical CodeView 4.0 + 7.0 streams + the PDB
stream header. A full PDB reader (the public ``pdbparse``
package, or the Microsoft ``dia2`` SDK) is out of scope for
the bundled reader — the goal is to expose a structured
summary that the analyst can use to confirm the PDB belongs
to the binary they downloaded, not to do full UDT expansion.

The parser is pure-stdlib (no third-party PDB reader). It
returns a dict shaped like::

    {
      "signature": "...",
      "age": N,
      "guid": "...",
      "machine": "X86_64" | "X86" | ...,
      "symbols": [{"name": "...", "address": 0x..., "section": N,
                  "kind": "proc" | "public" | "data" | "..."}, ...],
      "types": [{"id": N, "kind": "...", "name": "..."}, ...],
      "truncated": bool
    }

The on-disk PDB format reference is
``https://llvm.org/docs/PDB/index.html`` (the Microsoft
PDB format is publicly documented).
"""

from __future__ import annotations

import struct
from typing import Any

# PDB stream constants
_PDB_SIGNATURE = b"Microsoft C/C++ MSF 7.00"
_PDB7_SIGNATURE = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53"
_STREAM_DIRECTORY_INDEX = 3

# Stream types we recognize
_PDB_STREAM_PDB = "PDB"
_PDB_STREAM_TPI = "TPI"
_PDB_STREAM_DBI = "DBI"
_PDB_STREAM_SYMBOLS = "Symbols"

# CodeView symbol kind codes (subset, the most common ones)
_SYM_PROC = 0x1101
_SYM_PUBLIC = 0x1103
_SYM_DATA = 0x110C
_SYM_LDATA = 0x110D
_SYM_GDATA = 0x110E
_SYM_LPROC = 0x110F
_SYM_THUNK = 0x1107


def _read_pdb_header(data: bytes) -> tuple[int, int, int, int, int, int] | None:
    """Parse the PDB 7.0 file header. Returns (page_size, alloc_table_pages,
    num_streams, stream_dir_size, stream_dir_pages, root_pages) or None on
    malformed input."""
    if len(data) < 56:
        return None
    sig = data[:32]
    if sig not in (_PDB7_SIGNATURE, _PDB_SIGNATURE, _PDB_SIGNATURE + b"\r\n\x1a\x44\x53"):
        # Some tooling omits the trailer; be lenient.
        if not sig.startswith(b"Microsoft C/C++ MSF"):
            return None
    page_size = struct.unpack_from("<I", data, 32)[0]
    alloc_table_pages = struct.unpack_from("<I", data, 36)[0]
    file_pages = struct.unpack_from("<I", data, 40)[0]
    root_pages_count = struct.unpack_from("<I", data, 44)[0]
    # Skip reserved 4 bytes
    num_streams = struct.unpack_from("<I", data, 52)[0]
    return (page_size, alloc_table_pages, file_pages, num_streams, root_pages_count, 56)


def _page_offset(page_size: int, page_index: int) -> int:
    return page_size * page_index


def parse_pdb_bytes(data: bytes, max_symbols: int = 5000, max_types: int = 2000) -> dict[str, Any]:
    """Parse a PDB file from raw bytes and return a structured summary.

    Args:
        data: PDB file bytes
        max_symbols: cap on the symbol list
        max_types: cap on the type list

    Returns a dict with the shape documented at module level.
    """
    header = _read_pdb_header(data)
    if header is None:
        return {"error": "not a recognized PDB file", "symbols": [], "types": []}
    page_size, _alloc_pages, _file_pages, num_streams, _root_pages_count, hdr_off = header
    if num_streams > 1000:
        # Sanity: the stream directory can have at most a few
        # dozen entries in any real PDB; a larger count means
        # the file is corrupt.
        return {"error": f"unreasonable stream count: {num_streams}",
                "symbols": [], "types": []}
    # Read stream-directory-size and stream-directory-pages from
    # header extension (after the 56-byte base).
    if hdr_off + 4 + 4 * num_streams > len(data):
        return {"error": "header truncated", "symbols": [], "types": []}
    # Stream sizes: a list of N+1 u4 values (the +1 is the
    # 0-length "directory itself" entry).
    sizes_off = hdr_off
    sizes = struct.unpack_from(f"<{num_streams + 1}I", data, sizes_off)
    pages_off = sizes_off + 4 * (num_streams + 1)
    # We only need the symbol stream + the PDB stream (for
    # signature/age) + the type stream.
    # The stream offsets in the directory are not strictly
    # ordered; the directory itself is the meta-stream.
    # We treat the streams by index, where the conventional
    # layout is [PDB, TPI, DBI, ..., Symbols, ...].
    # The actual page list for stream N follows the size list.
    streams: dict[str, bytes] = {}
    cur_off = pages_off
    for i, size in enumerate(sizes[:num_streams]):
        if size == 0:
            continue
        page_count = (size + page_size - 1) // page_size
        if cur_off + 4 * page_count > len(data):
            break
        try:
            page_list = struct.unpack_from(f"<{page_count}I", data, cur_off)
        except struct.error:
            break
        # Concatenate the pages into a single byte string
        buf = bytearray()
        for p in page_list:
            off = _page_offset(page_size, p)
            if off + page_size > len(data):
                break
            buf.extend(data[off:off + page_size])
        streams[_stream_name_hint(i)] = bytes(buf[:size])
        cur_off += 4 * page_count
    out: dict[str, Any] = {
        "signature": None,
        "age": None,
        "guid": None,
        "machine": None,
        "symbols": [],
        "types": [],
        "truncated": False,
    }
    if "PDB" in streams:
        s = streams["PDB"]
        if len(s) >= 28:
            try:
                guid_bytes = s[:16]
                age = struct.unpack_from("<I", s, 16)[0]
                # Name index + 4-byte padding
                # Format the GUID as the canonical 8-4-4-4-12 form
                g1, g2, g3 = struct.unpack_from("<HHH", guid_bytes, 0)
                g4, g5, g6, g7, g8, g9, g10, g11 = struct.unpack_from("<HHHHHHHH", guid_bytes, 6)
                out["guid"] = f"{g1:08X}-{g2:04X}-{g3:04X}-{g4:04X}-{g5:04X}{g6:04X}{g7:04X}{g8:04X}{g9:04X}{g10:04X}"
                out["age"] = age
            except (struct.error, ValueError):
                pass
    if "Symbols" in streams:
        out["symbols"] = _parse_symbol_stream(streams["Symbols"], max_symbols)
        out["truncated"] = len(out["symbols"]) >= max_symbols
    if "TPI" in streams:
        out["types"] = _parse_type_stream(streams["TPI"], max_types)
    out["machine"] = _guess_machine(out.get("symbols", []))
    return out


def _stream_name_hint(idx: int) -> str:
    """Return the conventional name for stream index *idx*.

    Real PDB files have a stream-name table that's the
    last stream in the directory; we don't parse that here.
    The conventional layout (per the LLVM docs) is::

        0: PDB stream (signature, age, GUID)
        1: TPI stream (type info)
        2: DBI stream (debug info)
        3: IPI stream (id info)
        ...
        N: Symbols stream

    Without parsing the name table we use a simple index-
    based hint. The reader doesn't need exact names — it
    just needs the bytes to parse.
    """
    return {
        0: "PDB",
        1: "TPI",
        2: "DBI",
        3: "IPI",
    }.get(idx, f"idx-{idx}")


def _parse_symbol_stream(buf: bytes, max_symbols: int) -> list[dict[str, Any]]:
    """Best-effort parse of the CodeView symbol substream.

    The CodeView format is variable-length records; we
    recognize the most common record kinds and skip the
    rest. The format reference is the LLVM PDB code, in
    particular ``llvm/DebugInfo/CodeView/``.
    """
    out: list[dict[str, Any]] = []
    i = 0
    while i + 2 <= len(buf) and len(out) < max_symbols:
        # CodeView record: u16 length (in bytes, not including
        # the 2 length bytes), u16 kind.
        try:
            length = struct.unpack_from("<H", buf, i)[0]
            kind = struct.unpack_from("<H", buf, i + 2)[0]
        except struct.error:
            break
        i += 4
        body = buf[i:i + length]
        i += length
        if kind in (_SYM_PROC, _SYM_LPROC):
            # PROC: u32 parent, u32 end, u32 next, u16 length,
            # u32 offset, u16 segment, u8[4] name (pascal-style)
            if len(body) < 19:
                continue
            try:
                offset = struct.unpack_from("<I", body, 11)[0]
                seg = struct.unpack_from("<H", body, 15)[0]
                name_len = body[17]
                name = body[18:18 + name_len].decode("utf-8", errors="replace")
            except (struct.error, IndexError):
                continue
            out.append({
                "name": name,
                "address": offset,
                "section": seg,
                "kind": "proc" if kind == _SYM_PROC else "local-proc",
            })
        elif kind == _SYM_PUBLIC:
            # PUBLIC: u32 offset, u16 segment, u8[4] name
            if len(body) < 7:
                continue
            try:
                offset = struct.unpack_from("<I", body, 0)[0]
                seg = struct.unpack_from("<H", body, 4)[0]
                name_len = body[6]
                name = body[7:7 + name_len].decode("utf-8", errors="replace")
            except (struct.error, IndexError):
                continue
            out.append({
                "name": name,
                "address": offset,
                "section": seg,
                "kind": "public",
            })
        elif kind in (_SYM_DATA, _SYM_LDATA, _SYM_GDATA):
            # DATA: u32 offset, u16 segment, u8[4] name (pascal)
            if len(body) < 7:
                continue
            try:
                offset = struct.unpack_from("<I", body, 0)[0]
                seg = struct.unpack_from("<H", body, 4)[0]
                name_len = body[6]
                name = body[7:7 + name_len].decode("utf-8", errors="replace")
            except (struct.error, IndexError):
                continue
            out.append({
                "name": name,
                "address": offset,
                "section": seg,
                "kind": "data",
            })
    return out


def _parse_type_stream(buf: bytes, max_types: int) -> list[dict[str, Any]]:
    """Best-effort parse of the TPI stream (type info).

    The TPI stream is a sequence of fixed-prefix type records;
    the first 4 bytes are the type stream header (version,
    header size, type-index size, type-index count). After
    that, each record is ``u16 kind, u16 length, [body]`` —
    the same shape as the symbol substream. We return the
    count + a sample of type names; full UDT expansion is
    out of scope.
    """
    out: list[dict[str, Any]] = []
    if len(buf) < 28:
        return out
    try:
        # Header: u32 sig, u32 version, u32 header_size,
        # u32 type_index_size (always 0x100000000 for the
        # canonical TPI stream; for compatibility with 7.0
        # we read just the first 28 bytes)
        type_count = struct.unpack_from("<I", buf, 24)[0]
    except struct.error:
        return out
    out.append({"id": 0, "kind": "header", "name": f"tpi_count={type_count}"})
    # Walk from offset 28
    i = 28
    while i + 4 <= len(buf) and len(out) < max_types:
        try:
            length = struct.unpack_from("<H", buf, i)[0]
            kind = struct.unpack_from("<H", buf, i + 2)[0]
        except struct.error:
            break
        i += 4
        body = buf[i:i + length]
        i += length
        if length == 0:
            break
        out.append({
            "id": len(out),
            "kind": f"cv-{kind:04X}",
            "name": body[:32].hex(),
        })
    return out


def _guess_machine(symbols: list[dict[str, Any]]) -> str:
    """Heuristic machine guess from the section number in the symbol records.

    A real PDB carries the machine type in the DBI stream header
    (u16 Machine field at offset 0). We don't parse DBI here —
    the section numbers in the symbol records are a usable
    proxy: section 1 is the default for x86/x64 images.
    """
    sections = {s.get("section") for s in symbols if s.get("section") is not None}
    if not sections:
        return None
    if max(sections) > 10:
        return "X86_64"
    return "X86"
