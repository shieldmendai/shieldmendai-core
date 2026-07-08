const API_BASE = "https://api.shieldmendai.com";
const ENDPOINTS = {
  health: `${API_BASE}/health`,
  status: `${API_BASE}/api/status`,
  scanWallet: `${API_BASE}/api/scan-wallet`
};

const STORAGE_KEY = "shieldmendai.mobile.beta.state";
const EVM_RE = /^0x[a-fA-F0-9]{40}$/;
const SOLANA_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const EVM_NETWORKS = new Set(["base", "ethereum", "arbitrum", "optimism", "polygon"]);
const SCAN_TIMEOUT_MS = 14000;
const PRICING_URL = "https://shieldmendai.com/pricing.html";
const APP_VERSION = "Beta 0.1";
const BOOT_LINES = [
  "Checking safe wallet view...",
  "Loading dashboard...",
  "Preparing wallet planning tools..."
];

const state = {
  activeScreen: "dashboard",
  wallet: null,
  scanStatus: "none",
  scanMessage: "Add a public wallet address or import address with WalletConnect.",
  scanDetailsOpen: false,
  scan: null,
  planner: {
    mode: "coins",
    value: "200",
    olderLots: true,
    protectRewards: true,
    showLoss: true
  },
  settings: {
    filingStatus: "Single",
    state: "Not sure yet",
    incomeRange: "Under $50k",
    dependents: "No"
  },
  taxProfileSaved: false,
  savedPlan: false
};

const elements = {
  app: document.querySelector("#app"),
  boot: document.querySelector("#boot-screen"),
  bootStatus: document.querySelector("#boot-status"),
  screens: Array.from(document.querySelectorAll(".screen")),
  navButtons: Array.from(document.querySelectorAll("[data-nav]")),
  bottomNavButtons: Array.from(document.querySelectorAll(".bottom-nav [data-nav]")),
  dashboardWalletCard: document.querySelector("#dashboard-wallet-card"),
  walletScanCard: document.querySelector("#wallet-scan-card"),
  walletForm: document.querySelector("#wallet-form"),
  walletNetwork: document.querySelector("#wallet-network"),
  walletAddress: document.querySelector("#wallet-address"),
  walletError: document.querySelector("#wallet-error"),
  walletConnectButton: document.querySelector("#walletconnect-button"),
  walletConnectMessage: document.querySelector("#walletconnect-message"),
  metricValue: document.querySelector("#metric-value"),
  metricGain: document.querySelector("#metric-gain"),
  metricLots: document.querySelector("#metric-lots"),
  metricRewards: document.querySelector("#metric-rewards"),
  coinAmount: document.querySelector("#custom-coin-amount"),
  cashTarget: document.querySelector("#custom-cash-target"),
  plannerEstimate: document.querySelector("#planner-estimate"),
  olderLots: document.querySelector("#older-lots"),
  protectRewards: document.querySelector("#protect-rewards"),
  showLoss: document.querySelector("#show-loss"),
  bucketDetail: document.querySelector("#bucket-detail"),
  settingsForm: document.querySelector("#settings-form"),
  taxProfileMessage: document.querySelector("#tax-profile-message"),
  saveTaxProfileButton: document.querySelector("#save-tax-profile-button"),
  savePlanButton: document.querySelector("#save-plan-button"),
  saveMessage: document.querySelector("#save-message"),
  clearDataButton: document.querySelector("#clear-data-button")
};

loadState();
bindEvents();
render();
runBootSequence();

function bindEvents() {
  elements.navButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const preset = button.dataset.preset;
      if (preset === "loss") {
        state.planner.showLoss = true;
        elements.showLoss.checked = true;
        updatePlannerEstimate();
      }
      showScreen(button.dataset.nav);
    });
  });

  elements.walletForm.addEventListener("submit", (event) => {
    event.preventDefault();
    addManualWallet();
  });

  elements.walletConnectButton.addEventListener("click", importWalletConnectAddress);

  document.addEventListener("click", (event) => {
    const target = event.target.closest("[data-action]");
    if (!target) return;
    if (target.dataset.action === "add-wallet") {
      showScreen("wallet");
    }
    if (target.dataset.action === "retry-scan" && state.wallet && state.wallet.type === "evm") {
      runWalletScan(state.wallet.address);
    }
    if (target.dataset.action === "toggle-scan-details") {
      state.scanDetailsOpen = !state.scanDetailsOpen;
      persistState();
      renderWalletCards();
    }
    if (target.dataset.action === "open-pricing") {
      openPricingPage();
    }
  });

  document.querySelectorAll("[data-plan-preset]").forEach((button) => {
    button.addEventListener("click", () => {
      const [mode, value] = button.dataset.planPreset.split(":");
      state.planner.mode = mode;
      state.planner.value = value;
      elements.coinAmount.value = mode === "coins" ? value : "";
      elements.cashTarget.value = mode === "cash" ? value : "";
      updatePlannerEstimate();
      persistState();
    });
  });

  elements.coinAmount.addEventListener("input", () => {
    state.planner.mode = "coins";
    state.planner.value = elements.coinAmount.value.trim();
    elements.cashTarget.value = "";
    updatePlannerEstimate();
    persistState();
  });

  elements.cashTarget.addEventListener("input", () => {
    state.planner.mode = "cash";
    state.planner.value = elements.cashTarget.value.trim();
    elements.coinAmount.value = "";
    updatePlannerEstimate();
    persistState();
  });

  [elements.olderLots, elements.protectRewards, elements.showLoss].forEach((input) => {
    input.addEventListener("change", () => {
      state.planner.olderLots = elements.olderLots.checked;
      state.planner.protectRewards = elements.protectRewards.checked;
      state.planner.showLoss = elements.showLoss.checked;
      updatePlannerEstimate();
      persistState();
    });
  });

  document.querySelector("#see-options-button").addEventListener("click", () => {
    showScreen("lots");
    elements.bucketDetail.textContent = "Planning preview only. ShieldMendAI will compare lot strategies once full tax-lot data is available.";
  });

  document.querySelectorAll("[data-bucket-key]").forEach((button) => {
    button.addEventListener("click", () => {
      const details = {
        older: "Older lots will highlight coins that may be closer to long-term treatment once full history is available.",
        newer: "Newer buys stay separated so short-term exposure is easier to review before a sale.",
        rewards: "Rewards and airdrops are tracked as their own planning category for income and basis review.",
        unknown: "Unknown items are kept visible for cost basis cleanup instead of being hidden from the plan.",
        longterm: "Long-term candidates will help compare timing options before selling elsewhere.",
        shortterm: "Short-term exposure flags newer activity that may create a higher tax impact."
      };
      elements.bucketDetail.textContent = details[button.dataset.bucketKey];
    });
  });

  elements.settingsForm.addEventListener("change", () => {
    state.settings = Object.fromEntries(new FormData(elements.settingsForm).entries());
    state.taxProfileSaved = false;
    elements.taxProfileMessage.hidden = true;
  });

  elements.saveTaxProfileButton.addEventListener("click", () => {
    state.settings = Object.fromEntries(new FormData(elements.settingsForm).entries());
    state.taxProfileSaved = true;
    persistState();
    renderSettings();
  });

  elements.savePlanButton.addEventListener("click", () => {
    state.savedPlan = true;
    elements.saveMessage.hidden = false;
    persistState();
  });

  elements.clearDataButton.addEventListener("click", () => {
    localStorage.removeItem(STORAGE_KEY);
    state.wallet = null;
    state.scan = null;
    state.scanStatus = "none";
    state.scanMessage = "Add a public wallet address or import address with WalletConnect.";
    state.scanDetailsOpen = false;
    state.taxProfileSaved = false;
    state.savedPlan = false;
    elements.walletAddress.value = "";
    elements.saveMessage.hidden = true;
    elements.taxProfileMessage.hidden = true;
    persistState();
    render();
  });
}

function runBootSequence() {
  if (state.wallet) {
    BOOT_LINES[0] = "Restoring saved wallet view...";
  }

  BOOT_LINES.forEach((line, index) => {
    setTimeout(() => {
      elements.bootStatus.textContent = line;
    }, index * 460);
  });

  setTimeout(() => {
    elements.app.classList.remove("is-booting");
    elements.boot.classList.add("done");
    showScreen("dashboard");
  }, 1550);
}

function showScreen(screenName) {
  state.activeScreen = screenName;
  elements.screens.forEach((screen) => {
    screen.classList.toggle("active", screen.dataset.screen === screenName);
  });
  elements.bottomNavButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.nav === screenName);
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function addManualWallet() {
  const network = elements.walletNetwork.value;
  const address = elements.walletAddress.value.trim();
  const validation = validateAddress(network, address);

  if (!validation.ok) {
    showWalletError(validation.message);
    return;
  }

  elements.walletError.hidden = true;
  state.wallet = {
    address,
    network,
    type: validation.type,
    source: validation.type === "solana" ? "Manual Solana address" : "Manual public address"
  };
  state.scan = null;
  state.scanStatus = validation.type === "solana" ? "solana-preview" : "scanning";
  state.scanMessage = validation.type === "solana"
    ? "Solana address added for planning preview. Solana scan support is coming next."
    : "Public address added. Safe wallet view active. Scanning public wallet data...";
  persistState();
  render();

  if (validation.type === "evm") {
    runWalletScan(address);
  }
}

function validateAddress(network, address) {
  if (!address) {
    return { ok: false, message: "Enter a public wallet address first." };
  }

  if (network === "solana") {
    if (!SOLANA_RE.test(address)) {
      return { ok: false, message: "Enter a Solana public address between 32 and 44 base58 characters." };
    }
    return { ok: true, type: "solana" };
  }

  if (!EVM_NETWORKS.has(network)) {
    return { ok: false, message: "Choose a supported network first." };
  }

  if (!EVM_RE.test(address)) {
    return { ok: false, message: "Enter an EVM address that starts with 0x followed by 40 hex characters." };
  }

  return { ok: true, type: "evm" };
}

function showWalletError(message) {
  elements.walletError.textContent = message;
  elements.walletError.hidden = false;
  elements.walletAddress.focus();
}

async function runWalletScan(address) {
  state.scanStatus = "scanning";
  state.scanMessage = "Scanning public wallet data...";
  render();

  try {
    const [status, scan] = await Promise.all([
      fetchJson(ENDPOINTS.status, {}, SCAN_TIMEOUT_MS),
      fetchJson(ENDPOINTS.scanWallet, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ wallet: address })
      }, SCAN_TIMEOUT_MS)
    ]);

    state.scan = { status, scan };
    if (isTokenScan(scan)) {
      state.scanStatus = "token-active";
      state.scanMessage = scan.cached
        ? "Updated recently. Showing your latest saved scan."
        : "Token scan active.";
    } else if (isBasicScan(scan)) {
      state.scanStatus = "basic-active";
      state.scanMessage = "Basic scan active. Full holdings, profit/loss, and tax-lot data is being expanded in Beta.";
    } else {
      state.scanStatus = "beta-preview";
      state.scanMessage = "Wallet added. Full holdings, profit/loss, and tax-lot data is being expanded in Beta.";
    }
  } catch (error) {
    state.scan = { error: scanErrorDetails(error) };
    state.scanStatus = "retry";
    state.scanMessage = "Your address is saved. No approval was requested and no funds can move.";
  } finally {
    persistState();
    render();
  }
}

async function importWalletConnectAddress() {
  const config = window.ShieldMendAIWalletConnectConfig || {};
  const projectId = typeof config.projectId === "string" ? config.projectId.trim() : "";
  hideWalletConnectMessage();

  if (!projectId || projectId === "YOUR_REOWN_PROJECT_ID") {
    showWalletConnectMessage("WalletConnect setup needed before wallet import can open.");
    return;
  }

  try {
    const imported = await openReownAddressImport(projectId);
    if (!imported || !EVM_RE.test(imported.address)) {
      showWalletConnectMessage("WalletConnect did not return a supported EVM public address.");
      return;
    }

    state.wallet = {
      address: imported.address,
      network: imported.network || "ethereum",
      type: "evm",
      source: "WalletConnect address import"
    };
    state.scan = null;
    state.scanStatus = "scanning";
    state.scanMessage = "Wallet address imported. Safe wallet view active. No signing requested. Scanning public wallet data...";
    elements.walletAddress.value = imported.address;
    elements.walletNetwork.value = state.wallet.network;
    persistState();
    render();
    runWalletScan(imported.address);
  } catch (error) {
    showWalletConnectMessage(`Wallet address import could not open: ${friendlyError(error)}`);
  }
}

async function openReownAddressImport(projectId) {
  if (window.ShieldMendAIWalletAddressImporter) {
    return window.ShieldMendAIWalletAddressImporter({ projectId });
  }

  const [{ createAppKit }, { EthersAdapter }, networks] = await Promise.all([
    import("https://esm.sh/@reown/appkit@1.7.8"),
    import("https://esm.sh/@reown/appkit-adapter-ethers@1.7.8"),
    import("https://esm.sh/@reown/appkit@1.7.8/networks")
  ]);

  const networkList = [
    networks.mainnet,
    networks.base,
    networks.arbitrum,
    networks.optimism,
    networks.polygon
  ].filter(Boolean);

  const modal = createAppKit({
    adapters: [new EthersAdapter()],
    networks: networkList,
    projectId,
    metadata: {
      name: "ShieldMendAI",
      description: "Safe wallet view for planning before selling.",
      url: "https://shieldmendai.com",
      icons: ["https://shieldmendai.com/favicon.ico"]
    },
    features: {
      analytics: false,
      email: false,
      socials: false,
      swaps: false,
      onramp: false
    }
  });

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Timed out waiting for wallet address import.")), 120000);
    const unsubscribe = modal.subscribeAccount((account) => {
      const address = account && account.address;
      if (!address) return;
      clearTimeout(timeout);
      if (typeof unsubscribe === "function") unsubscribe();
      resolve({
        address,
        network: networkFromChainId(account.chainId)
      });
    });
    Promise.resolve(modal.open({ view: "Connect" })).catch((error) => {
      clearTimeout(timeout);
      if (typeof unsubscribe === "function") unsubscribe();
      reject(error);
    });
  });
}

function networkFromChainId(chainId) {
  const normalized = Number(chainId);
  if (normalized === 8453) return "base";
  if (normalized === 42161) return "arbitrum";
  if (normalized === 10) return "optimism";
  if (normalized === 137) return "polygon";
  return "ethereum";
}

function showWalletConnectMessage(message) {
  elements.walletConnectMessage.textContent = message;
  elements.walletConnectMessage.hidden = false;
}

function hideWalletConnectMessage() {
  elements.walletConnectMessage.hidden = true;
  elements.walletConnectMessage.textContent = "";
}

function isBasicScan(scan) {
  const mode = String(scan && (scan.mode || scan.walletScan || scan.status || "")).toLowerCase();
  return mode === "live-basic" || mode === "basic" || mode.includes("basic");
}

function isTokenScan(scan) {
  const mode = String(scan && (scan.scanMode || scan.mode || "")).toLowerCase();
  return mode === "alchemy-token-balances";
}

async function fetchJson(url, options = {}, timeoutMs = SCAN_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetch(url, {
      cache: "no-store",
      signal: controller.signal,
      ...options
    });
  } catch (error) {
    throw markScanError(error, error.name === "AbortError" ? "timeout" : "network");
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    const errorPayload = await readResponsePayload(response);
    const error = new Error(`${url} returned ${response.status}`);
    error.httpStatus = response.status;
    error.payload = errorPayload;
    throw error;
  }

  return readResponsePayload(response);
}

async function readResponsePayload(response) {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }

  return response.text();
}

function markScanError(error, type) {
  error.errorType = type;
  return error;
}

function scanErrorDetails(error) {
  return {
    type: error.errorType || "request_error",
    httpStatus: error.httpStatus || null,
    message: friendlyError(error),
    payload: error.payload || null
  };
}

function render() {
  renderWalletCards();
  renderMetrics();
  renderPlanner();
  renderSettings();
  elements.saveMessage.hidden = !state.savedPlan;
}

function renderWalletCards() {
  const cardMarkup = walletStatusMarkup();
  elements.dashboardWalletCard.innerHTML = cardMarkup;
  elements.walletScanCard.innerHTML = cardMarkup;
}

function walletStatusMarkup() {
  if (!state.wallet) {
    return `
      <div class="status-line">
        <strong>Add wallet to preview your tax picture</strong>
        <span class="address-pill">Safe wallet view</span>
      </div>
      <div class="card-actions">
        <button class="button primary" type="button" data-action="add-wallet">Add Public Address</button>
        <button class="button secondary" type="button" data-action="add-wallet">Connect Wallet</button>
      </div>
      <p class="status-copy">No approval needed. No funds can move.</p>
    `;
  }

  const source = escapeHtml(state.wallet.source);
  const address = escapeHtml(shortAddress(state.wallet.address));
  const retry = state.scanStatus === "retry"
    ? `<button class="button secondary" type="button" data-action="retry-scan">Retry Scan</button>`
    : "";
  const details = scanDetailsMarkup();
  const tokenSection = tokenBalancesMarkup();
  return `
    <div class="status-line">
      <strong>${statusTitle()}</strong>
      <span class="address-pill">${address}</span>
    </div>
    <p class="status-copy">Source: ${source}</p>
    <p class="status-copy">${escapeHtml(state.scanMessage)}</p>
    ${retry}
    ${details}
    ${tokenSection}
    <p class="status-copy">No approval needed. No funds can move.</p>
  `;
}

function statusTitle() {
  if (!state.wallet) return "No address added";
  if (state.scanStatus === "scanning") return "Scanning public wallet data";
  if (state.scanStatus === "token-active") return "Token scan active";
  if (state.scanStatus === "basic-active") return "Wallet added";
  if (state.scanStatus === "retry") return "Live scan needs a retry";
  if (state.scanStatus === "solana-preview") return "Wallet added";
  if (state.wallet.source === "WalletConnect address import") return "Wallet address imported";
  return "Wallet added";
}

function scanDetailsMarkup() {
  const scan = state.scan && state.scan.scan;
  const error = state.scan && state.scan.error;
  if (!scan && !error) return "";
  const lines = [];
  if (scan && (scan.scanMode || scan.mode)) lines.push(`Scan mode: ${scan.scanMode || scan.mode}`);
  if (scan && scan.chainId) lines.push(`Chain ID: ${scan.chainId}`);
  if (scan && Number.isFinite(Number(scan.tokenCount))) lines.push(`Tokens: ${scan.tokenCount}`);
  if (scan && typeof scan.cached === "boolean") lines.push(`Cached: ${scan.cached ? "yes" : "no"}`);
  if (error && error.httpStatus) lines.push(`HTTP status: ${error.httpStatus}`);
  if (error && error.type) lines.push(`Error type: ${error.type}`);
  if (!lines.length) return "";
  return `
    <div class="scan-details">
      <button class="details-toggle" type="button" data-action="toggle-scan-details">Details</button>
      ${state.scanDetailsOpen ? `<p>${escapeHtml(lines.join(" | "))}</p>` : ""}
    </div>
  `;
}

function tokenBalancesMarkup() {
  const scan = state.scan && state.scan.scan;
  if (!isTokenScan(scan)) {
    if (state.scanStatus === "basic-active") {
      return `<div class="token-summary muted">Basic wallet scan active. Token balances are temporarily unavailable.</div>`;
    }
    return "";
  }

  const tokens = Array.isArray(scan.tokens) ? scan.tokens : [];
  const tokenCount = Number.isFinite(Number(scan.tokenCount)) ? Number(scan.tokenCount) : tokens.length;
  if (!tokens.length) {
    return `<div class="token-summary">No Base ERC-20 balances found yet.</div>`;
  }

  return `
    <section class="token-panel" aria-label="Base token balances">
      <div class="token-summary">
        <strong>${tokenCount} Base token balances found</strong>
        <span>${scan.cached ? "Updated recently. Showing your latest saved scan." : "Token scan active."}</span>
      </div>
      <div class="token-list">
        ${tokens.map(tokenCardMarkup).join("")}
      </div>
    </section>
  `;
}

function tokenCardMarkup(token) {
  const symbol = escapeHtml(token.symbol || "Token");
  const name = escapeHtml(token.name || "Base token");
  const balance = escapeHtml(token.formattedBalance || "0");
  const contract = escapeHtml(shortAddress(token.contractAddress || ""));
  return `
    <article class="token-card">
      <div>
        <strong>${symbol}</strong>
        <span>${name}</span>
      </div>
      <div>
        <strong>${balance}</strong>
        <span>${contract}</span>
      </div>
    </article>
  `;
}

function renderMetrics() {
  const scan = state.scan && state.scan.scan;
  const tokens = scan && Array.isArray(scan.tokens) ? scan.tokens : [];
  const lots = tokens.flatMap((token) => Array.isArray(token.lots) ? token.lots : []);
  const totalValue = tokens.reduce((sum, token) => sum + Number(token.estimatedValueUsd || 0), 0);

  elements.metricValue.textContent = totalValue > 0 ? formatUsd(totalValue) : "Beta preview";
  elements.metricLots.textContent = lots.length > 0 ? `${lots.length} preview lots` : "Planning preview";
  elements.metricGain.textContent = "Coming with full scan";
  elements.metricRewards.textContent = "Staking/airdrops tracking";

  if (isTokenScan(scan)) {
    const tokenCount = Number.isFinite(Number(scan.tokenCount)) ? Number(scan.tokenCount) : tokens.length;
    elements.metricValue.textContent = `${tokenCount} Base tokens`;
    elements.metricGain.textContent = "Estimate before selling";
    elements.metricLots.textContent = "Tax lots coming next";
    elements.metricRewards.textContent = "Rewards planning ready";
  } else if (scan && scan.nativeBalanceEth) {
    elements.metricValue.textContent = `${Number(scan.nativeBalanceEth).toFixed(5)} ETH`;
  }
}

function renderPlanner() {
  elements.coinAmount.value = state.planner.mode === "coins" ? state.planner.value : "";
  elements.cashTarget.value = state.planner.mode === "cash" ? state.planner.value : "";
  elements.olderLots.checked = state.planner.olderLots;
  elements.protectRewards.checked = state.planner.protectRewards;
  elements.showLoss.checked = state.planner.showLoss;
  updatePlannerEstimate();
}

function updatePlannerEstimate() {
  const value = state.planner.value || "0";
  const amountCopy = state.planner.mode === "cash"
    ? `${formatUsd(Number(value || 0))} cash target`
    : `${value || "0"} coin amount`;
  const lotCopy = state.planner.olderLots ? "older lots first" : "selected lot order";
  const rewardCopy = state.planner.protectRewards ? "protecting newer rewards when possible" : "including rewards if needed";
  const lossCopy = state.planner.showLoss ? "with tax-loss opportunities visible" : "without tax-loss filtering";

  elements.plannerEstimate.textContent = `${amountCopy}: planning preview using ${lotCopy}, ${rewardCopy}, ${lossCopy}.`;
}

function renderSettings() {
  Object.entries(state.settings).forEach(([name, value]) => {
    const field = elements.settingsForm.elements[name];
    if (field) field.value = value;
  });
  elements.taxProfileMessage.hidden = !state.taxProfileSaved;
}

function loadState() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
    if (saved && typeof saved === "object") {
      Object.assign(state, {
        wallet: saved.wallet || null,
        scanStatus: saved.scanStatus || state.scanStatus,
        scanMessage: saved.scanMessage || state.scanMessage,
        scanDetailsOpen: Boolean(saved.scanDetailsOpen),
        scan: saved.scan || null,
        planner: { ...state.planner, ...(saved.planner || {}) },
        settings: { ...state.settings, ...(saved.settings || {}) },
        taxProfileSaved: Boolean(saved.taxProfileSaved),
        savedPlan: Boolean(saved.savedPlan)
      });
    }
  } catch {
    localStorage.removeItem(STORAGE_KEY);
  }
}

function persistState() {
  const saved = {
    wallet: state.wallet,
    scanStatus: state.scanStatus,
    scanMessage: state.scanMessage,
    scanDetailsOpen: state.scanDetailsOpen,
    scan: state.scan,
    planner: state.planner,
    settings: state.settings,
    taxProfileSaved: state.taxProfileSaved,
    savedPlan: state.savedPlan
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(saved));
}

function openPricingPage() {
  window.open(PRICING_URL, "_blank", "noopener,noreferrer");
}

function shortAddress(address) {
  if (!address || address.length <= 14) return address || "";
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function formatUsd(value) {
  if (!Number.isFinite(value)) return "$0";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0
  }).format(value);
}

function friendlyError(error) {
  const message = error && error.message ? error.message : String(error);
  return message.replace(/^Error:\s*/, "");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[character]);
}
