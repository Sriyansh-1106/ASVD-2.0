// ASVD 2.O - Receiver Threat Defense HUD Application Logic

let ws = null;
let currentScore = 0;
let alarmAudioContext = null;
let alarmOscillator = null;
let isAlarmMuted = false;

// DOM Elements
const systemStatusText = document.getElementById("systemStatusText");
const systemPulse = document.getElementById("systemPulse");
const currentSessionId = document.getElementById("currentSessionId");
const threatPanel = document.getElementById("threatPanel");
const gaugeProgress = document.getElementById("gaugeProgress");
const riskScore = document.getElementById("riskScore");
const threatLevelBadge = document.getElementById("threatLevelBadge");
const callerIdentity = document.getElementById("callerIdentity");
const aiConfidence = document.getElementById("aiConfidence");
const flagCount = document.getElementById("flagCount");
const transcriptFeed = document.getElementById("transcriptFeed");
const actionBanner = document.getElementById("actionBanner");
const actionTitle = document.getElementById("actionTitle");
const actionAdvice = document.getElementById("actionAdvice");
const historyModal = document.getElementById("historyModal");
const btnOpenHistory = document.getElementById("btnOpenHistory");
const btnCloseHistory = document.getElementById("btnCloseHistory");
const historyList = document.getElementById("historyList");

// Indicator mappings to chip IDs
const INDICATOR_CHIP_MAP = {
  urgency: "ind-urgency",
  otp_request: "ind-otp",
  credential_request: "ind-credential",
  authority_impersonation: "ind-authority",
  threat_detected: "ind-threat",
  financial_request: "ind-financial",
  secrecy_request: "ind-secrecy",
  emotional_manipulation: "ind-emotional"
};

// SVG Circle circumference for r=90 is 2 * PI * 90 = 565.48
const CIRCUMFERENCE = 565.48;

// Get Session ID from URL query param ?session=... or default
function getSessionId() {
  const params = new URLSearchParams(window.location.search);
  return params.get("session") || "live-call-001";
}

// Connect to WebSocket Server
function connectWebSocket() {
  const sessionId = getSessionId();
  currentSessionId.textContent = sessionId;

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.host || "localhost:8000";
  const wsUrl = `${protocol}//${host}/ws/call/${sessionId}?role=receiver`;

  systemStatusText.textContent = "Connecting to Core Engine...";

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      systemStatusText.textContent = `Active Shield (${sessionId})`;
      systemPulse.classList.remove("danger");
    };

    ws.onclose = () => {
      systemStatusText.textContent = "Shield Offline (Reconnecting...)";
      systemPulse.classList.add("danger");
      setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (err) => {
      console.warn("Receiver WS Error:", err);
    };

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        handleIncomingMessage(payload);
      } catch (e) {
        console.error("Parse error:", e);
      }
    };
  } catch (err) {
    console.error("Failed to connect WS:", err);
  }
}

// Handle Incoming WebSocket Messages
function handleIncomingMessage(msg) {
  if (msg.type === "threat_alert") {
    const data = msg.data;
    const fullTranscript = msg.full_transcript || msg.chunk || "";

    // Update UI with real-time analysis
    updateThreatHUD(data, fullTranscript);
  } else if (msg.type === "call_status") {
    if (msg.status === "active") {
      callerIdentity.textContent = msg.caller_id || "Incoming Caller";
      systemStatusText.textContent = "Live Call in Progress";
    } else if (msg.status === "ended") {
      systemStatusText.textContent = "Call Ended - Monitoring";
      stopSiren();
    }
  }
}

// Update HUD Display with AI Assessment
function updateThreatHUD(data, transcriptText) {
  const score = data.risk_score || 0;
  const level = data.risk_level || "LOW";
  const indicators = data.indicators || [];
  const confidence = data.confidence ? Math.round(data.confidence * 100) : 100;

  // 1. Update Gauge & Score
  riskScore.textContent = score;
  const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
  gaugeProgress.style.strokeDashoffset = offset;

  // Reset Classes
  threatPanel.className = "threat-panel";
  actionBanner.className = "action-banner";
  systemPulse.className = "pulse-dot";
  threatLevelBadge.className = "threat-level-badge";

  const beaconWidget = document.getElementById("cornerBeacon");
  const beaconText = document.getElementById("beaconText");

  if (level === "CRITICAL") {
    gaugeProgress.style.stroke = "var(--threat-critical)";
    threatPanel.classList.add("critical");
    actionBanner.classList.add("critical");
    systemPulse.classList.add("danger");
    threatLevelBadge.classList.add("critical");
    threatLevelBadge.textContent = "🚨 CRITICAL THREAT";
    
    // Activate Continuous Rapid Red & Yellow Strobe
    if (beaconWidget) {
      beaconWidget.className = "beacon-widget critical";
      if (beaconText) beaconText.textContent = "🚨 CRITICAL STROBE";
    }
  } else if (level === "HIGH") {
    gaugeProgress.style.stroke = "var(--threat-high)";
    threatPanel.classList.add("high");
    actionBanner.classList.add("critical");
    systemPulse.classList.add("danger");
    threatLevelBadge.textContent = "⚠️ HIGH THREAT";

    // Activate Continuous Red & Yellow Strobe
    if (beaconWidget) {
      beaconWidget.className = "beacon-widget critical";
      if (beaconText) beaconText.textContent = "⚠️ THREAT STROBE";
    }
  } else if (level === "MEDIUM") {
    gaugeProgress.style.stroke = "var(--threat-med)";
    threatLevelBadge.textContent = "⚡ MEDIUM RISK";
    threatLevelBadge.style.color = "var(--threat-med)";
    threatLevelBadge.style.borderColor = "var(--threat-med)";
    threatLevelBadge.style.background = "rgba(255, 204, 0, 0.15)";

    // Activate Continuous Yellow / Amber Warning Light
    if (beaconWidget) {
      beaconWidget.className = "beacon-widget warning";
      if (beaconText) beaconText.textContent = "🟡 WARNING BEACON";
    }
    stopSiren();
  } else {
    gaugeProgress.style.stroke = "var(--threat-low)";
    threatPanel.classList.add("safe");
    threatLevelBadge.textContent = "🛡️ SAFE CALL";
    threatLevelBadge.style.color = "var(--threat-low)";
    threatLevelBadge.style.borderColor = "var(--threat-low)";
    threatLevelBadge.style.background = "rgba(0, 255, 136, 0.15)";

    // Safe Idle State
    if (beaconWidget) {
      beaconWidget.className = "beacon-widget safe";
      if (beaconText) beaconText.textContent = "🟢 DEFENSE NORMAL";
    }
    stopSiren();
  }

  // 3. Update Meta
  aiConfidence.textContent = `${confidence}%`;
  flagCount.textContent = `${indicators.length} Flagged`;

  // 4. Highlight Indicators
  Object.values(INDICATOR_CHIP_MAP).forEach((id) => {
    const chip = document.getElementById(id);
    if (chip) chip.classList.remove("active");
  });

  indicators.forEach((ind) => {
    const chipId = INDICATOR_CHIP_MAP[ind];
    if (chipId) {
      const chip = document.getElementById(chipId);
      if (chip) chip.classList.add("active");
    }
  });

  // 5. Update Transcript with Highlighted Threat Keywords
  renderHighlightedTranscript(transcriptText);

  // 6. Update Action Banner
  actionAdvice.textContent = data.recommended_action || "No action required.";
  actionTitle.textContent = level === "CRITICAL" || level === "HIGH" 
    ? "🚨 URGENT CYBER DEFENSE ALERT" 
    : "🛡️ AI Security Guidance";
}

// Scam Keyword Highlighter
function renderHighlightedTranscript(text) {
  if (!text) {
    transcriptFeed.innerHTML = '<span class="transcript-placeholder">Waiting for speech transcript...</span>';
    return;
  }

  const threatKeywords = [
    "otp", "pin", "cvv", "password", "arrest", "jail", "fir", "police",
    "inspector", "cbi", "cyber crime", "transfer", "paisa", "rupees", "rs",
    "urgent", "argent", "turant", "jaldi", "block", "freeze", "emergency", "accident",
    "kidnap", "kidnapping", "marunga", "maar", "kill", "firauti", "ransom", "500000", "lakh"
  ];

  let highlighted = text;
  threatKeywords.forEach((kw) => {
    const regex = new RegExp(`\\b(${kw})\\b`, "gi");
    highlighted = highlighted.replace(regex, '<span class="highlight-tag">$1</span>');
  });

  transcriptFeed.innerHTML = `<p>${highlighted}</p>`;
  transcriptFeed.scrollTop = transcriptFeed.scrollHeight;
}

// Web Audio API Synthesizer Siren (No External MP3 Needed)
function playSiren() {
  if (isAlarmMuted) return;
  if (alarmAudioContext) return; // Already playing

  try {
    alarmAudioContext = new (window.AudioContext || window.webkitAudioContext)();
    alarmOscillator = alarmAudioContext.createOscillator();
    const gainNode = alarmAudioContext.createGain();

    alarmOscillator.type = "sawtooth";
    alarmOscillator.frequency.setValueAtTime(440, alarmAudioContext.currentTime);
    
    // Siren wobble effect
    alarmOscillator.frequency.exponentialRampToValueAtTime(880, alarmAudioContext.currentTime + 0.3);
    alarmOscillator.frequency.exponentialRampToValueAtTime(440, alarmAudioContext.currentTime + 0.6);

    gainNode.gain.setValueAtTime(0.08, alarmAudioContext.currentTime);

    alarmOscillator.connect(gainNode);
    gainNode.connect(alarmAudioContext.destination);

    alarmOscillator.start();
  } catch (e) {
    console.warn("Audio Context error:", e);
  }
}

function stopSiren() {
  if (alarmOscillator) {
    try {
      alarmOscillator.stop();
      alarmOscillator.disconnect();
    } catch (e) {}
    alarmOscillator = null;
  }
  if (alarmAudioContext) {
    try {
      alarmAudioContext.close();
    } catch (e) {}
    alarmAudioContext = null;
  }
}

window.toggleAudioAlarm = function() {
  isAlarmMuted = !isAlarmMuted;
  const btnText = document.getElementById("alarmBtnText");
  if (isAlarmMuted) {
    stopSiren();
    btnText.textContent = "Siren Muted 🔇";
  } else {
    btnText.textContent = "Siren Active 🔔";
  }
};

// History Drawer Modal Logic
btnOpenHistory.addEventListener("click", async () => {
  historyModal.classList.add("open");
  historyList.innerHTML = "<p style='color: var(--text-dim);'>Fetching detection history...</p>";

  try {
    const res = await fetch("/api/history?limit=20");
    const logs = await res.json();

    if (!logs || logs.length === 0) {
      historyList.innerHTML = "<p style='color: var(--text-dim);'>No call logs recorded yet.</p>";
      return;
    }

    historyList.innerHTML = logs.map((item) => `
      <div class="history-item">
        <div>
          <strong style="color: ${item.label === 'SCAM' ? 'var(--threat-critical)' : 'var(--threat-low)'}">
            ${item.label} [${item.risk_level || 'LOW'}] - Score: ${item.risk_score}/100
          </strong>
          <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
            "${item.conversation_text.substring(0, 120)}..."
          </p>
        </div>
        <span style="font-size: 11px; color: var(--text-dim); font-family: monospace;">
          ${item.created_at || 'Recent'}
        </span>
      </div>
    `).join("");
  } catch (err) {
    historyList.innerHTML = `<p style='color: var(--threat-critical);'>Failed to load history: ${err.message}</p>`;
  }
});

btnCloseHistory.addEventListener("click", () => {
  historyModal.classList.remove("open");
});

// ====================================================================
// UNIVERSAL THEME MANAGER (LIGHT / DARK)
// ====================================================================

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("asvd_theme", theme);
  const icon = document.getElementById("themeIcon");
  const text = document.getElementById("themeText");
  if (icon && text) {
    if (theme === "light") {
      icon.textContent = "☀️";
      text.textContent = "Light";
    } else {
      icon.textContent = "🌙";
      text.textContent = "Dark";
    }
  }
}

window.toggleTheme = function() {
  const current = document.documentElement.getAttribute("data-theme") || "light";
  const next = current === "light" ? "dark" : "light";
  applyTheme(next);
};

// Initialize on Load
window.addEventListener("DOMContentLoaded", () => {
  const savedTheme = localStorage.getItem("asvd_theme") || "light";
  applyTheme(savedTheme);
  connectWebSocket();
});
