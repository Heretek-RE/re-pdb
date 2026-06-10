"""Microsoft Symbol Server download helper.

The msdl URL pattern is::

    https://msdl.microsoft.com/download/symbols/<basename>/<GUID><AGE><basename>

with the GUID uppercase + zero-padded, and the age as a 1-3 digit
hex number. The server returns the file directly (or a 404 if no
matching PDB is on file).

This module is intentionally **purely-functional**: it builds the
URL, hands it to ``httpx``, and returns the response object to
the caller. The MCP server layer (above) handles output-path
policy and the public-URL opt-in.
"""

from __future__ import annotations

import re
from typing import Iterable


# Default allowlist of hosts the public downloader trusts. The
# Microsoft Symbol Server is the only public symbol host in
# common use; the opt-in env var (``RE_PDB_ALLOW_PUBLIC=1``) lets
# the analyst widen the allowlist at runtime.
DEFAULT_ALLOWLIST: tuple[str, ...] = (
    "msdl.microsoft.com",
)


def is_allowed_host(host: str, allowlist: Iterable[str]) -> bool:
    """Return True if *host* (case-insensitive) matches an entry
    in *allowlist*. The match is suffix-based: ``"msdl.microsoft.com"``
    in the allowlist matches a request to ``"msdl.microsoft.com"``
    exactly and a request to ``"sub.msdl.microsoft.com"`` would
    not — subdomains need their own entry. This is the safe
    default for symbol-server lookups; broaden the allowlist if
    the analyst uses an internal mirror.
    """
    h = host.lower().strip()
    for entry in allowlist:
        e = entry.lower().strip()
        if h == e:
            return True
    return False


# GUID: standard 8-4-4-4-12 hex, 32 hex digits total when stripped.
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$"
)
# Age: 1-3 hex digits, often 1.
_AGE_RE = re.compile(r"^[0-9a-fA-F]{1,3}$")


def normalise_guid(guid: str) -> str:
    """Validate a GUID and return it in the msdl-canonical form
    (uppercase, no dashes, 32 hex digits). Raises ``ValueError``
    on a malformed input — callers map the exception to a user
    error.
    """
    if not _GUID_RE.match(guid):
        raise ValueError(f"malformed GUID: {guid!r}")
    return guid.replace("-", "").upper()


def normalise_age(age: str | int) -> str:
    """Validate an age and return it as a 1-3 character uppercase
    hex string. Accepts int for convenience. Raises ``ValueError``
    on out-of-range input (msdl ages are 0..0xFFF, 12 bits).
    """
    s = f"{age:x}" if isinstance(age, int) else str(age).strip()
    if not _AGE_RE.match(s):
        raise ValueError(f"malformed age: {age!r}")
    if int(s, 16) > 0xFFF:
        raise ValueError(f"age out of range: {age!r}")
    return s.upper()


def build_msdl_url(basename: str, guid: str, age: str | int) -> str:
    """Build the canonical msdl URL for *basename* / *guid* / *age*.

    Example::

        >>> build_msdl_url("foo.pdb",
        ...                 "12345678-9ABC-DEF0-1234-56789ABCDEF0", 1)
        'https://msdl.microsoft.com/download/symbols/foo.pdb/123456789ABCDEF0123456789ABCDEF01foo.pdb'
    """
    return (
        "https://msdl.microsoft.com/download/symbols/"
        f"{basename}/{normalise_guid(guid)}{normalise_age(age)}{basename}"
    )
