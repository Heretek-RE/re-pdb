# re-pdb

MCP server for downloading debug PDBs from the Microsoft Symbol Server (msdl) and (opt-in) custom mirrors. Never writes outside the user-specified output path; never republishes.

Version: 0.1.0 | License: MIT

## Structure

```
re-pdb/
  pyproject.toml                    # build config (setuptools, mcp[cli] + deps)
  src/re_pdb/
    __init__.py
    __main__.py                     # entry: from server import main; main()
    server.py                       # FastMCP app with @mcp.tool() functions
  README.md
  LICENSE
  SECURITY.md


```

## Build

```bash
pip install -e .                    # install with deps
re-pdb                         # start MCP server on stdio
```



## Tools

This server exposes these MCP tools: `check_pdb,download_msdl,download_custom,parse_pdb`

## Usage (standalone)

Register this server in your `.mcp.json`:

```json
{
  "mcpServers": {
    "re-pdb": {
      "command": "uv",
      "args": ["--directory", "/path/to/re-pdb", "run", "re-pdb"]
    }
  }
}
```

Or use via the [RE-AI agent-space](https://github.com/Heretek-RE/RE-AI): `./install.sh` clones all servers at pinned versions.
