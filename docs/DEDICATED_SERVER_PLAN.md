# Dedicated ShieldMendAi Server Plan

This plan applies only after the implementation and tests are complete and the
user explicitly authorizes deployment.

1. Save sanitized work through reviewed local Git commits.
2. Run tests and repository-only security scans.
3. Push only to
   `https://github.com/shieldmendai/shieldmendai-core.git`.
4. On the separate dedicated server, verify the official remote and clone or
   pull the reviewed commit.
5. Install ShieldMendAi into an isolated application directory with separate
   configuration, state, incident, and credential paths.
6. Create only `shieldmendai-*.service` and `shieldmendai-*.timer` units using
   least privilege.
7. Begin with synthetic simulations and dry-run mode. Confirm that observations
   and proposed actions match expectations without changing services.
8. Introduce configured read-only health checks, then controlled repairs only
   after review of allowlists, retry limits, cooldowns, and verification.
9. Validate side by side without assigning overlapping live repair ownership.
10. Disable or remove old Guardian components only after explicit user approval
    and a tested rollback plan.

Never transfer private trading directories, wallets, secrets, logs, reports,
backups, databases, or state to the dedicated ShieldMendAi server.
