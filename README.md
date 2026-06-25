# shieldmendai-core
The self-healing shield for your server.
## Roadmap

### Phase 1 — Core Guardian
- Monitor server services
- Detect failed processes
- Restart broken services
- Send Telegram alerts
- Keep repair logs

### Phase 2 — Self-Healing
- Diagnose common failures
- Apply safe repair steps
- Create backups before changes
- Verify services after repair
- Learn from past incidents

### Phase 3 — Installer
- One-command install
- Telegram setup prompts
- User config file
- Systemd service setup
- Safe update process

### Phase 4 — Public Release
- Documentation
- Example configs
- Security checklist
- First stable release

## Vision

ShieldMendAI is a reusable AI-powered server guardian that monitors systems, detects failures, attempts safe repairs, alerts owners through Telegram, and learns from previous incidents.

Users install ShieldMendAI on their own servers, provide their own configuration and credentials, and maintain full control of their infrastructure.

Goal: Reduce downtime through safe automation and self-healing workflows.

## Development Status

ShieldMendAi is in Phase 1: read-only inventory and architecture. This phase
documents reusable monitoring and recovery concepts from a stopped private
system without copying private code, credentials, trading logic, state, or
operational data.

No standalone recovery engine is implemented yet. The next phase will create
the minimal `shieldmendai` package and configuration schema in dry-run mode.

Development records:

- [Codex handoff](docs/CODEX_HANDOFF.md)
- [Extraction plan](docs/EXTRACTION_PLAN.md)
- [Sanitized source inventory](docs/SOURCE_INVENTORY.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security boundaries](docs/SECURITY_BOUNDARIES.md)
- [Dedicated server plan](docs/DEDICATED_SERVER_PLAN.md)
- [Extraction manifest](extraction_manifest.json)

Run the read-only continuation check from the repository root:

```bash
scripts/resume_check.sh
```
