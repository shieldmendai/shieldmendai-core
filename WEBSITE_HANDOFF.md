# ShieldMendAi Website Handoff

## Checkpoint

- Current UTC timestamp: `2026-06-25T19:21:14Z`
- Current git branch at handoff update time: `codex/extraction-phase-6`
- Requested continuation branch: `website/redesign-v1`
- Remaining unfinished item at this checkpoint: move the completed website redesign onto the requested branch, stage the intended files, commit, and push that branch only

## Redesign status

The public website under `docs/` was redesigned around the verified Builder
Roadmap and current repository capability boundary.

Source-of-truth records reviewed before writing public claims:

- `docs/CODEX_HANDOFF.md`
- `PROJECT_STATUS.md`
- `README.md`
- `extraction_manifest.json`
- completed `codex/extraction-phase-1` through
  `codex/extraction-phase-6` branches
- `docs/ARCHITECTURE.md`
- `docs/SECURITY_BOUNDARIES.md`
- `docs/DEDICATED_SERVER_PLAN.md`
- repository test suite

## New information architecture

- `docs/index.html`: canonical product overview, mission summary, development
  proof, lifecycle explanation, Builder Roadmap preview, capability boundary,
  and simulator call to action.
- `docs/roadmap.html`: canonical Builder Roadmap and long-term goal.
- `docs/simulator.html`: interactive browser-only deterministic recovery
  demonstration.
- `docs/about.html`: canonical founder story, mission context, design
  principles, and public-development explanation.
- `docs/funding.html`: canonical funding priorities, support context,
  historical proof video, and funding risk statement.
- `docs/community.html`: canonical community destinations, SMEND information,
  Base network identification, Bankr link, contract address, and token/legal
  disclosures.
- `docs/testimonials.html`: preserved legacy URL that redirects to the canonical
  founder-story section on `about.html`.
- `docs/TOKEN_PLAN.md`: revised factual token reference aligned with the current
  product capability boundary.
- `docs/styles.css`: shared responsive visual system.
- `docs/site.js`: mobile navigation and browser-only simulator behavior.

## Content relocation and consolidation record

| Previous content | New authoritative location | Treatment |
|---|---|---|
| General mission and product tagline repeated across pages | `index.html` | Consolidated and rewritten against current repository status |
| Old promotional roadmap | `roadmap.html` | Replaced with verified five-stage Builder Roadmap |
| Founder story in `testimonials.html` | `about.html#founder` | Relocated; legacy URL preserved with redirect |
| Founder video | `about.html#founder` | Preserved |
| Proof/funding video | `funding.html` | Preserved and labeled as a historical project update |
| Funding ask and use of support | `funding.html` | Consolidated and updated |
| Telegram community block | `community.html` | Relocated |
| X, GitHub, Telegram, and Bankr links | `community.html` and global footer | Preserved |
| SMEND token explanation | `community.html#token` | Consolidated and separated from primary product hierarchy |
| Base network identification | `community.html#token` | Preserved |
| Contract address | `community.html#token` | Preserved exactly |
| DEX Screener chart | `community.html#token` | Replaced embedded chart with a direct official destination link to reduce promotional dominance and third-party page weight |
| Token risk disclaimer | `community.html` | Consolidated and expanded |
| Token plan markdown | `docs/TOKEN_PLAN.md` | Updated to remove stale product claims and preserve official details |
| Repeated product/funding/token promotional copy | Canonical pages above | Removed where duplicated |
| Duplicate “Protect” paragraph on old homepage | None | Intentional duplicate removal |
| “Audit planned” trust badge | None | Removed because no committed audit record was verified |
| Claims of real private-infrastructure testing and live recovery | None | Removed from current site copy because public repository records do not establish those as current ShieldMendAi capabilities |
| Claims that service monitoring, auto-restart, Telegram delivery, or production recovery are available | Capability boundary and roadmap | Corrected to simulation-only, planned, or production unavailable |

## Roadmap evidence used

- Six completed development phases.
- 141 passing automated tests.
- Standalone installable Python package and CLI.
- Eleven deterministic observer simulations.
- Deny-by-default repair authorization.
- Exact target/action allowlists.
- Bounded retries, cooldowns, backoff, circuit breakers, duplicate suppression,
  and recovery-loop protection.
- Versioned incident records, timelines, correlation, integrity validation,
  retention preview/simulation, and notification simulations.
- Completed public phase branches.
- Exact next task: controlled dedicated-server sandbox installation and
  local-only, read-only Linux observation pilot.

## Capability-labeling rules used

- Completed package, models, policies, records, and tests are labeled
  implemented/tested.
- Observation, repair, recovery, retention removal, and notification execution
  are labeled deterministic simulation only.
- Website and simulator redesign are labeled building now.
- Dedicated-server sandbox and read-only Linux observation are labeled the next
  controlled milestone.
- Live observers, low-risk repair adapters, verification, rollback, provider
  delivery, dashboards, beta, Docker, Kubernetes, deployment, and code-repair
  workflows are labeled planned.
- Universal compatibility and autonomous production repair are labeled
  long-term objectives.
- Live monitoring, repair, notification delivery, customer deployment, and
  production persistence remain explicitly unavailable.

## Validation checklist

- [x] Homepage prominently explains verified accomplishments.
- [x] Website and simulator work are identified as currently building.
- [x] Dedicated-server sandbox milestone is clearly explained.
- [x] Future capabilities are labeled planned.
- [x] Long-term goal is a major roadmap statement.
- [x] Simulated capability is not presented as live.
- [x] Planned capability is not marked complete.
- [x] Test count is tied to repository records and rechecked during validation.
- [x] Roadmap preview is on the homepage.
- [x] Complete dedicated roadmap page exists.
- [x] Responsive desktop/mobile layouts are defined.
- [x] Roadmap uses infrastructure-development language, not token-roadmap language.
- [x] Official links, contract, videos, founder, funding, community, token,
  Base, Bankr, and legal/risk information are preserved.
- [x] Duplicate and overly promotional content is consolidated.
- [x] Product, architecture, roadmap, and simulator dominate the hierarchy.

## Unfinished items

- Branch migration to `website/redesign-v1` had not yet been completed when this handoff was updated.
- The checkpoint commit and push were still pending at the time of this handoff update.

## Exact continuation task

Switch the repository work onto `website/redesign-v1`, stage the intended website redesign files, create the checkpoint commit `feat: redesign ShieldMendAi website and builder roadmap`, push only that branch to `origin`, and verify the local branch matches the remote branch tip.
