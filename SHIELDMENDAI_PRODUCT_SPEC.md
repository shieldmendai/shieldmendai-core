# ShieldMendAI Product And Beta Access Spec

ShieldMendAI is a read-only, non-custodial staking and tax-planning app for crypto holders.

Main promise: Know what you might owe before you sell.

Staking promise: Stake smarter. Sell cleaner.

## Product Direction

ShieldMendAI helps users review public wallet activity, staking rewards, and possible sale outcomes before they sell. The app should explain estimates in plain English and keep users in control of every decision.

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

## Protect My Staking Rewards

Protect My Staking Rewards is the core staking-focused feature.

Users often receive or unlock staking reward coins at different times. When a user wants to sell, the app should help them avoid accidentally selling recently received staking reward coins when older long-held coins are available.

Example:

A user wants to sell 200 coins. ShieldMendAI should recommend selling from older coins first when possible and protecting recently received staking rewards.

The recommendation should be presented as an estimate and planning aid, not guaranteed tax advice.

## APK Beta 0.1 Screen Flow

1. Welcome
2. Tax Profile
3. Add Wallet
4. Staking Scan
5. My Buckets
6. What If I Sell?
7. Recommended Sale Plan
8. Export / Save Proof

## Beta Access Model

The website may later include a Beta Access or Download APK page. Random visitors must not receive the APK directly.

Access code verification should happen server-side through the backend API. Real access codes must never be committed to git, hardcoded into public frontend JavaScript, or stored in public website files.

Real access codes should live only in server-side storage, such as `backend/.env` during early beta or a small database later.

The APK should not be publicly downloadable without access verification.

### Access Code Types

Friend access code:

- Free access
- For personal friends, family, and testers
- Tracks free friend testers

Creator or YouTuber access codes:

- Free access for creators
- Each creator can have an individual code
- Tracks creator source for future referrals
- Their audiences may later use creator promo or referral codes

Paid beta access later:

- Stripe Payment Links or Checkout can be evaluated later
- Stripe promotion codes or coupons can be evaluated later
- 100 percent off codes can support free beta or promos later

Do not implement Stripe, payment collection, affiliate payouts, or automatic referral payouts until those systems are intentionally designed and reviewed.

## Future Creator Referral Rule

Creator referral tracking is future work, not live payout code.

A possible future business rule is 20 percent of paid users from a creator code for 6 months, paid manually monthly after refunds and chargebacks clear.

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
- No public APK download without server-side access verification
- No real Stripe keys in git
