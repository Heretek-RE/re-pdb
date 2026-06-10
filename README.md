# re-pdb

MCP server for downloading **debug PDBs** from the **Microsoft
Symbol Server** (msdl) and, on an opt-in basis, from custom
mirrors.

PDBs accompany binary triage: the analyst pulls the matching PDB
to recover struct layouts, function names, and source line
information for a stripped binary. The standard workflow:

1. Run `re-lief.parse_binary` (or `re-rizin.list_imports_exports`)
   on a target. The PE/COFF debug directory names the PDB and its
   GUID + age.
2. Call `download_msdl(guid=<g>, age=<a>, basename=<b>)`. The
   server fetches
   `https://msdl.microsoft.com/download/symbols/<b>/<GUID><AGE><b>`,
   follows the standard `msdl-fingerprints.txt` indirection, and
   writes the PDB to a user-specified output path.
3. The PDB is then fed back into a decompiler / Rizin.

## Tools

| Tool | What it does |
|---|---|
| `check_pdb` | Health check — return msdl reachability + httpx availability |
| `download_msdl` | Download a single PDB from the Microsoft Symbol Server |
| `download_custom` | Download a PDB from a non-msdl URL. **Disabled by default.** Set `RE_PDB_ALLOW_PUBLIC=1` to permit non-msdl hosts. |

## Safety

PDBs are usually the publisher's debug artefacts, distributed via
public symbol servers. They are not copyrighted assets of the
target binary, but they can leak internal naming. `re-pdb`:

- Never writes outside the output path the caller specifies.
- Defaults to msdl only; refuses non-msdl URLs unless the
  analyst explicitly opts in via `RE_PDB_ALLOW_PUBLIC=1`.
- Never republishes the downloaded PDB — the MCP caller is
  responsible for storage and access.

## Install

Part of the RE-AI plugin; `./install.sh` installs the package. To
install standalone:

```bash
pip install -e ./servers/re-pdb
```

## Run

```bash
re-pdb                              # stdio transport (default for MCP)
python -m re_pdb                    # equivalent
```

## URL allowlist

The default allowlist contains one host: `msdl.microsoft.com`.
The opt-in `RE_PDB_ALLOW_PUBLIC=1` env var permits any URL but
records the override in the MCP response so the analyst can audit
non-msdl downloads after the fact.
