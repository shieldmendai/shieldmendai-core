# ShieldMendAI Product And Beta Access Spec

ShieldMendAI is a read-only, non-custodial crypto wallet intelligence, profit/loss, tax-lot, and tax-planning app for everyday holders.

Main promise: Know what you might owe before you sell.

Consumer promise: Understand your wallet without needing to be a tax expert.

## Product Direction

ShieldMendAI helps users review public wallet activity, holdings, profit/loss, cost basis estimates, tax lots, long-term versus short-term status, staking rewards, airdrops, unlocks, newly received coins, and possible sale outcomes before they sell. The app should explain estimates in plain English and keep users in control of every decision.

The backend manages read-only provider keys, RPCs, indexer APIs, caching, fallback behavior, and rate limits. Users must not bring their own API keys.

ShieldMendAI must never request, store, or use:

- Private keys
- Seed phrases
- Custody credentials
- Wallet approvals
- Trading keys
- Swap permissions
- Trading actions

All wallet analysis must use public wallet addresses and read-only provider calls.

## Core Product Pillars

- Wallet holdings overview
- Profit/loss tracking
- Cost basis estimates
- Tax lot tracking
- Long-term versus short-term tracking
- What If I Sell?
- Estimated tax impact before selling
- Tax-loss harvesting opportunities
- Profit-taking planning
- Best sale options
- Built-in staking/reward tracking
- Built-in airdrop/new-coin tracking
- Unlock/release tracking when applicable
- Export/save proof-style sale plan
- Plain-English explanations

## Sale Planning

When a user wants to sell, the app should help compare possible sale choices using estimated lots, cost basis, profit/loss, reward history, airdrops, unlocks, and long-term versus short-term status.

Example: A user wants to sell 200 coins. ShieldMendAI should show what lots may be affected and may recommend selling older lots first when that appears smarter for the estimate.

Recommendations should be presented as estimates and planning aids, not guaranteed tax advice.

## APK Beta 0.1 Screen Flow

1. Welcome
2. Tax Profile
3. Add Wallet
4. Wallet Scan
5. Holdings, Lots, Rewards, And Airdrops
6. What If I Sell?
7. Recommended Sale Plan
8. Export / Save Proof

## Beta Access Model

The website includes a Beta Access page. Public pages must not include public invite strings or public release links.

Access code verification should happen server-side through the backend API. Real access codes must never be committed to git, hardcoded into public frontend JavaScript, or stored in public website files.

Real access codes should live only in server-side storage, such as `backend/.env` during early beta or a small database later.

No public app release link should exist until a release is intentionally approved.

Do not implement Stripe, payment collection, affiliate payouts, or automatic referral payouts until those systems are intentionally designed and reviewed.

## Tax And Advice Boundaries

ShieldMendAI does not file taxes and does not provide guaranteed tax, legal, accounting, or financial advice.

All outputs are planning estimates only. Users should review results with a qualified tax professional before making tax-sensitive decisions.

## Safety Requirements

- Read-only wallet analysis only
- Public wallet addresses only
- No custody
- No private keys
- No seed phrases
- No wallet approvals
- No swaps
- No trading actions
- No real access codes in git
- No real access codes in frontend JavaScript
- No public release link before approval
- No real Stripe keys in git
- No third-party measurement code or tracking cookies by default
- No cookie pop-up
- No unsupported certification, outside audit, or government approval claims
