# ShieldMendAI Mobile Beta 0.1

ShieldMendAI is a wallet-first crypto holdings, profit/loss, tax-lot, and tax-planning dashboard.

Main promise: know what you might owe before you sell.

## What is included

- Dashboard-first mobile app layout
- Manual public address entry that works without WalletConnect
- EVM address validation for Base, Ethereum, Arbitrum, Optimism, and Polygon
- Solana manual public address planning preview
- WalletConnect/Reown public EVM address import when a local Project ID is configured
- Planner inputs for custom coin amount and custom cash target
- Lots, reports, and local settings screens

## Wallet safety

ShieldMendAI imports or stores public wallet addresses only.

- No seed phrases
- No private keys
- No custody
- No token approvals
- No swaps
- No transfers
- No trading
- No transaction signing
- No message signing

WalletConnect/Reown is used only to import a public wallet address and chain/network when available. Manual public address entry remains available even when no Reown Project ID is configured.

## API behavior

Manual EVM address entry calls:

- `https://api.shieldmendai.com/api/scan-wallet`

The scan payload matches the backend contract:

```json
{ "wallet": "0x..." }
```

If the scan returns live basic data, the app reflects that status. If full token, profit/loss, and tax-lot data is unavailable, the app keeps the wallet added locally and shows a polished beta preview message instead of a blank state.

Solana manual addresses are saved locally for planning preview. The app does not call the Base EVM scan endpoint for Solana.

## WalletConnect/Reown local config

Copy `walletconnect.example.js` to `walletconnect.local.js` and replace the placeholder Project ID:

```js
window.ShieldMendAIWalletConnectConfig = {
  projectId: "YOUR_REOWN_PROJECT_ID"
};
```

`walletconnect.local.js` is gitignored so a real Project ID is not committed.
