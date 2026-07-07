const API_BASE = "https://api.shieldmendai.com";
const ENDPOINTS = {
  health: `${API_BASE}/health`,
  status: `${API_BASE}/api/status`,
  scanWallet: `${API_BASE}/api/scan-wallet`
};

const screens = Array.from(document.querySelectorAll(".screen"));
const stepNav = document.querySelector(".step-nav");
const state = {
  current: 0,
  profile: {},
  walletAddress: "",
  scan: null,
  salePlanSaved: false
};

const screenNames = [
  "Welcome",
  "Profile",
  "Wallet",
  "Scan",
  "Buckets",
  "Sell",
  "Options",
  "Export"
];

screenNames.forEach((name, index) => {
  const dot = document.createElement("button");
  dot.className = "step-dot";
  dot.type = "button";
  dot.setAttribute("aria-label", name);
  dot.addEventListener("click", () => {
    if (index <= state.current) showScreen(index);
  });
  stepNav.appendChild(dot);
});

function showScreen(index) {
  state.current = Math.max(0, Math.min(index, screens.length - 1));
  screens.forEach((screen, screenIndex) => {
    screen.classList.toggle("active", screenIndex === state.current);
  });
  Array.from(stepNav.children).forEach((dot, dotIndex) => {
    dot.classList.toggle("active", dotIndex <= state.current);
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function saveProfileState() {
  const form = document.querySelector("#profile-form");
  state.profile = Object.fromEntries(new FormData(form).entries());
}

function nextScreen() {
  if (state.current === 1) saveProfileState();
  showScreen(state.current + 1);
}

function previousScreen() {
  showScreen(state.current - 1);
}

document.querySelectorAll("[data-next]").forEach((button) => {
  button.addEventListener("click", nextScreen);
});

document.querySelectorAll("[data-back]").forEach((button) => {
  button.addEventListener("click", previousScreen);
});

document.querySelector("[data-start-over]").addEventListener("click", () => {
  state.current = 0;
  state.scan = null;
  state.salePlanSaved = false;
  document.querySelector("#save-message").hidden = true;
  showScreen(0);
});

document.querySelector("#scan-button").addEventListener("click", () => {
  const input = document.querySelector("#wallet-address");
  const error = document.querySelector("#wallet-error");
  const address = input.value.trim();
  if (!address) {
    error.hidden = false;
    input.focus();
    return;
  }

  error.hidden = true;
  state.walletAddress = address;
  showScreen(3);
  runWalletScan(address);
});

document.querySelector("#scan-results-button").addEventListener("click", () => {
  showScreen(4);
});

document.querySelectorAll("input[name='saleAmount']").forEach((input) => {
  input.addEventListener("change", () => {
    document.querySelector("#sell-summary").textContent =
      `${input.value} is a planning estimate. Older lots first may lower short-term exposure.`;
  });
});

document.querySelector("#save-plan-button").addEventListener("click", () => {
  state.salePlanSaved = true;
  document.querySelector("#save-message").hidden = false;
});

async function runWalletScan(address) {
  resetScanUi();
  const steps = Array.from(document.querySelectorAll(".scan-step"));
  const resultsButton = document.querySelector("#scan-results-button");
  const fallback = document.querySelector("#scan-fallback");
  const scanCopy = document.querySelector("#scan-copy");

  const stepTimer = setInterval(() => {
    const nextIndex = steps.findIndex((step) => !step.classList.contains("done"));
    if (nextIndex === -1) return;
    steps.forEach((step, index) => {
      step.classList.toggle("active", index === nextIndex);
      if (index < nextIndex) step.classList.add("done");
    });
  }, 380);

  try {
    const [health, status, scan] = await Promise.all([
      fetchJson(ENDPOINTS.health),
      fetchJson(ENDPOINTS.status),
      fetchJson(ENDPOINTS.scanWallet, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ walletAddress: address })
      })
    ]);

    state.scan = { health, status, scan };
    scanCopy.textContent = "Scan preview loaded. Review the planning buckets before modeling a sale.";
  } catch (error) {
    state.scan = { error: String(error) };
    fallback.hidden = false;
    scanCopy.textContent = "The scan service did not return a preview, so this session will use Beta 0.1 shell buckets.";
  } finally {
    clearInterval(stepTimer);
    steps.forEach((step) => {
      step.classList.remove("active");
      step.classList.add("done");
    });
    resultsButton.disabled = false;
  }
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    cache: "no-store",
    ...options
  });

  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}`);
  }

  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }

  return response.text();
}

function resetScanUi() {
  document.querySelector("#scan-results-button").disabled = true;
  document.querySelector("#scan-fallback").hidden = true;
  document.querySelector("#scan-copy").textContent = "ShieldMendAI is preparing a read-only planning preview.";
  document.querySelectorAll(".scan-step").forEach((step) => {
    step.classList.remove("active", "done");
  });
}

showScreen(0);
