# ShieldMendAI Mobile Beta 0.1

This is the dependency-free mobile app shell for ShieldMendAI Beta 0.1.

## What is included

- Welcome
- Profile
- Add Wallet
- Wallet Scan
- Holdings / Lots / Rewards
- What If I Sell?
- Best Options
- Export / Save Proof

## Guardrails

- Public wallet address only
- No login
- No payment
- No wallet connect
- No seed phrase
- No private keys
- No custody
- No approvals
- No trading actions
- Tax profile values stay in local app state only

## API endpoints

The wallet scan screen calls public API endpoints only after a wallet address is entered:

- `https://api.shieldmendai.com/health`
- `https://api.shieldmendai.com/api/status`
- `https://api.shieldmendai.com/api/scan-wallet`

If the scan request fails, the app shows a plain-English fallback and continues with Beta 0.1 shell buckets.

## Running locally

Open `index.html` in a browser, or serve this directory with any static file server.

## APK status

This repo does not currently include Capacitor, Android, Gradle, Java, Node, or npm tooling in the working environment. No APK is built from this shell until Android/Capacitor tooling is added with approval.
