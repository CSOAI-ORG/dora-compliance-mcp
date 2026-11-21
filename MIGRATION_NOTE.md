# MIGRATION_NOTE - MCP 2026-07-28 wire - class `header-add`

**Date:** 2026-10-07 - **Lane:** M4 MCP-migration (header-add wave) - **Branch:** `mcp-2026-wire-header-add`  
**Runbook:** `MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md` section 3 (header-add) + section 4 (the shim as bridge)  
**Deprecation deadline:** the legacy wire dies **2027-07-28** - 12 months after the 2026-07-28 revision.

## 1. Transport reality

Server runs on stdio (`server:main`) **and** streamable-HTTP (`mcp-wrapper.py`).

## 2. What changed in this branch

1. `pyproject.toml`: `mcp>=1.0.0` -> `mcp>=2.0.0`; hatch `only-include` extended with `mcp2026_shim.py`.
2. `server.py`: FastMCP -> `MCPServer as FastMCP` import (2.x rename) + migration note.
3. `mcp-wrapper.py`: the ASGI ingress is now **wired** - `ShimASGI(mcp_server.streamable_http_app(json_response=True))` fronts every request with `translate_request` (validates `Mcp-Method` / `Mcp-Name`, injects `params._meta.protocolVersion = "2026-07-28"`, strips `Mcp-Session-Id`, answers legacy `initialize` / `server/discover` locally). `json_response=True` because the shim buffers bodies.
4. `mcp-wrapper.py`: `mcp_server.settings.host = ...` + `run(transport=...)` replaced - in mcp 2.x `Settings` has no `host`/`port`, so the old lines would raise; host/port now come from `MCP_HOST` / `MCP_PORT`.
5. `mcp-wrapper.py`: the served well-known cards now declare `2026-07-28` (they said `2025-11-25`, which would have contradicted the wire the shim actually serves).
6. `mcp2026_shim.py` vendored at the repo root.

The shim does the four runbook duties at the transport: read/validate `Mcp-Method` and `Mcp-Name` on ingress, reject a missing `Mcp-Name` on `tools/call` / `resources/read` / `prompts/get` with `-32602`, emit `params._meta.protocolVersion = "2026-07-28"` on every outbound request, and never emit `Mcp-Session-Id` (it strips one if a proxy adds it).

## 3. Verify

```bash
PYTHONPATH= /opt/homebrew/bin/python3.11 ~/clawd/mcp_wire_audit.py audit --local dora-compliance-mcp
```

| state | era | migration |
|---|---|---|
| before (default branch) | 2026-07 | header-add |
| **after (this branch)** | **2026-07** | **handshake-removal** |
| control (note block removed) | 2026-07 | header-add |

Files changed in this branch: `pyproject.toml`, `server.py`, `mcp-wrapper.py`, `mcp2026_shim.py`, `MIGRATION_NOTE.md`. The scanner reads the source/manifest files only: it skips `mcp2026_shim.py` by design (`SELF_FILES`) and does not scan `.md`, so neither `MIGRATION_NOTE.md` nor the shim contributes signals above.

**How to read the `after` row honestly.** The audit is a static scan and this tool excludes its own shim from the scan by design (`SELF_FILES`), so `protocol-2026-07-28`, `mcp-method-header`, `mcp-name-header`, `server-discover` and `session-id` in the `after` record are read from the migration note text, not from executable handshake code. The `session-id` signal in particular is prose (the note documents that the shim *strips* the header) - the control run, which deletes only that note block, drops back to `2026-07 / header-add` and shows no `session-id` at all. Runtime evidence for the wire is the `mcp>=2.0.0` pin (2.3.0 speaks 2026-07-28) plus the vendored shim at the ingress; `mcp>=2.0.0` alone is not a wire signal for this scanner.

## 4. Follow-ups (not in this branch)

* Other static surfaces still declare the old wire: `.well-known/mcp/server-card.json` (`protocol_version`), `server.json` (`$schema` revision). Not touched here - each is an Article-21 declaration change and belongs in its own commit.
* `README.md` was not edited (out of runbook scope).

Verify command of record: `PYTHONPATH= /opt/homebrew/bin/python3.11 ~/clawd/mcp_wire_audit.py audit --local <repo>` -> `era: 2026-07`, `migration: none` is the acceptance target for class `header-add`; re-run it after merge, not on this branch's note text.

Plan: `MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md` - deadline 2027-07-28 - measurement, not certification.
