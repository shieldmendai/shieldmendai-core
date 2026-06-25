# Sanitized Source Inventory

## Scope and Method

The inventory records concepts only. Reviewed files were read using metadata,
hashing, syntax-structure summaries, and targeted capability classification.
No source code, secret value, private configuration, report, log, state,
backup, database, wallet material, or strategy content was copied.

Confidence reflects confidence in the high-level classification, not approval
to reuse code.

## Source Files

| Path | General purpose | Reusable behavior | Private/trading dependencies | Security concerns | Disposition | Priority | Confidence |
|---|---|---|---|---|---|---|---|
| `/root/newbasebot/newbase_guardian_watchdog.py` | State-oriented watchdog | JSON validation, atomic writes, backup-before-change, incident summary | Positions, transaction and trading configuration semantics | Mutates private state and permissions | Adapt conceptually | High | High |
| `/root/newbasebot/newbase_autopilot_watchdog.py` | Service watchdog and coordinator | Unit health checks, stale-report detection, restart decisions, retry delay | Hardcoded private units, reports, account state | Direct systemd actions and private report inspection | Rewrite | High | High |
| `/root/newbasebot/newbase_state_healer.py` | State consistency repair | Detect stale/inconsistent records and atomically persist correction | Position accounting and trading state | Private financial state mutation | Adapt conceptually | Medium | High |
| `/root/newbasebot/newbase_state_self_healer.py` | Wallet-aware state reconciliation | Validation, quarantine-style isolation, atomic updates | Wallet, RPC, balances, transaction state | Credential-bearing RPC and wallet access | Exclude implementation | Low | High |
| `/root/newbasebot/newbase_auto_bad_route_doctor.py` | Route failure classifier | Failure counters, cooldown/throttle state, bounded marking | Sell routes, open positions, deny/quarantine behavior | Proprietary trading and private state | Exclude implementation | Low | High |
| `/root/newbasebot/route_health_watch.py` | Route and position health monitor | Scheduled probes, risk intervals, failure budgets, event recording | Wallet, RPC, sell execution, positions, route logic | Can trigger financial actions and uses credentials | Exclude implementation | Low | High |
| `/root/newbasebot/newbase_scalper_pipeline_health.py` | Multi-signal pipeline health report | systemd status, file age, compilation check, HTTP/RPC probe, redaction concept | Trading pipeline, credential locations, private logs | May inspect credentials and operational logs | Adapt conceptually | High | High |
| `/root/newbasebot/newbase_telegram_alert_bridge.py` | Telegram incident bridge | Deduplication, throttling, message formatting, optional delivery | Private state schema and destinations | Token and chat identifier handling | Rewrite | Medium | High |
| `/root/newbasebot/doctor/doctor_common.py` | Shared doctor utilities | atomic JSON writes, backups, file age, unit status helpers, history model | Private config, candidates, positions, hardcoded units | Enables service/state mutation | Adapt conceptually | High | High |
| `/root/newbasebot/doctor/newbase_doctor.py` | Rule orchestrator | Rule loading, guarded execution, structured reports | Private rule set and emergency trading policy | Dynamic code loading and private policy | Rewrite framework only | Medium | Medium |
| `/root/newbasebot/scripts/newbase_local_mechanic_guardian.py` | Routine host mechanic | Process identity checks, duplicate detection, notification throttle | Private processes, core config, hardcoded units | Process signaling, service changes, config mutation | Rewrite | High | High |
| `/root/newbasebot/scripts/newbase_ai_guardian_reactor.py` | Health reaction coordinator | compile/config probes, service checks, notify-once behavior | Private units, RPC, wallet/position state | Starts/stops services and handles secrets | Rewrite | High | High |
| `/root/newbasebot/test_route_health_watch.py` | Route health unit tests | Temporary-directory isolation and boundary-focused test style | Encodes proprietary route and trading behavior | Test names and fixtures reveal private logic | Exclude; retain only generic testing concepts | Low | High |

## systemd Units

Each legacy unit is inventory evidence only. None will be copied or used as a
default. Future units use `shieldmendai-*` names and independent paths.

| Unit name | General purpose | Reusable behavior | Private/trading dependencies | Security concerns | Disposition | Priority | Confidence |
|---|---|---|---|---|---|---|---|
| `newbase-guardian-watchdog.service` | Run watchdog once | oneshot separation | Private path/script | Legacy target and privileged context | Rewrite | High | High |
| `newbase-guardian-watchdog.timer` | Schedule watchdog | boot delay, recurring cadence, accuracy window | Legacy service | Could create frequent repair loop | Adapt conceptually | High | High |
| `newbase-autopilot-watchdog.service` | Run coordinator once | oneshot execution | Private path/script and units | Direct production control | Rewrite | High | High |
| `newbase-autopilot-watchdog.timer` | Schedule coordinator | persistent recurring timer | Legacy service | Catch-up may trigger unsafe action | Adapt conceptually | High | High |
| `newbase-state-healer.service` | Run state healer once | isolated oneshot task | Private trading state | Mutates financial records | Exclude implementation | Low | High |
| `newbase-state-healer.timer` | Schedule state healer | recurring cadence | Legacy service | Repeated state mutation | Exclude | Low | High |
| `newbase-state-self-healer.service` | Run reconciliation once | isolated oneshot task | Wallet/RPC and private state | Credential and wallet access | Exclude implementation | Low | High |
| `newbase-state-self-healer.timer` | Schedule reconciliation | recurring cadence | Legacy service | Automated wallet-aware mutation | Exclude | Low | High |
| `newbase-route-health.service` | Run locked health check | overlap prevention with a process lock | Wallet/RPC and route execution | Credential file and financial action coupling | Adapt locking concept only | Medium | High |
| `newbase-route-health.timer` | Schedule frequent route checks | short cadence and accuracy window | Legacy service | High-frequency production activity | Exclude | Low | High |
| `newbase-scalper-pipeline-health.service` | Produce pipeline health report | oneshot health aggregation | Trading pipeline and private logs | Runs as root and inspects private operations | Rewrite | High | High |
| `newbase-scalper-pipeline-health.timer` | Schedule health aggregation | persistent periodic timer | Legacy service | Root task recurrence | Adapt conceptually | Medium | High |
| `newbase-local-mechanic-guardian.service` | Run routine repairs | isolated mechanic task | Private processes/config/units | Process signaling and host mutation | Rewrite | High | High |
| `newbase-local-mechanic-guardian.timer` | Schedule mechanic | persistent recurring timer | Legacy service | Restart-loop risk | Adapt conceptually | High | High |
| `newbase-ai-guardian-reactor.service` | Run health reaction logic | probe/decision task boundary | Private services, RPC, state, alerts | Starts/stops services and handles credentials | Rewrite | High | High |
| `newbase-ai-guardian-reactor.timer` | Schedule reaction logic | persistent recurring timer | Legacy service | Repeated actions without generic circuit breaker | Adapt conceptually | High | High |

## Reusable Concepts Selected for Clean-room Design

- normalized health observations;
- configurable systemd, file, process, command, and HTTP probes;
- missing, stale, malformed JSON, mode, and ownership checks;
- atomic writes and bounded backup concepts for future controlled actions;
- explicit policy decisions and allowlisted repairs;
- post-repair verification;
- cooldowns, retry budgets, backoff, locking, and circuit breakers;
- structured redacted incidents;
- optional deduplicated and throttled Telegram notifications;
- oneshot service plus timer deployment pattern;
- synthetic temporary-directory and fake-adapter tests.
