// ASVD 2.O - Caller Device Simulator Application Logic

let ws = null;
let isCalling = false;
let isMicActive = false;
let recognition = null;
let timerInterval = null;
let secondsElapsed = 0;
let simulationInterval = null;

// Speech accumulation
let accumulatedTranscript = "";
let currentInterim = "";

// Web Audio API for Real Live Microphone Visualizer
let audioContext = null;
let analyser = null;
let micSource = null;
let micStream = null;
let dataArray = null;
let animFrameId = null;

// DOM Elements
const wsStatusDot = document.getElementById("wsStatusDot");
const wsStatusText = document.getElementById("wsStatusText");
const sessionIdInput = document.getElementById("sessionId");
const callerNameInput = document.getElementById("callerName");
const languageSelect = document.getElementById("languageSelect");
const callStatusPill = document.getElementById("callStatusPill");
const callTimer = document.getElementById("callTimer");
const micStatusBanner = document.getElementById("micStatusBanner");
const btnStartCall = document.getElementById("btnStartCall");
const btnEndCall = document.getElementById("btnEndCall");
const btnToggleMic = document.getElementById("btnToggleMic");
const micLabel = document.getElementById("micLabel");
const btnSimulateStream = document.getElementById("btnSimulateStream");
const customSpeech = document.getElementById("customSpeech");
const btnSendText = document.getElementById("btnSendText");
const canvas = document.getElementById("waveform");
const ctx = canvas.getContext("2d");
const voiceMeterBar = document.getElementById("voiceMeterBar");
const speechBoxStatus = document.getElementById("speechBoxStatus");
const speechLiveText = document.getElementById("speechLiveText");

// Threat Preview Elements
const previewScore = document.getElementById("previewScore");
const previewLevelBadge = document.getElementById("previewLevelBadge");
const previewIndicatorsList = document.getElementById("previewIndicatorsList");
const threatPreviewCard = document.getElementById("threatPreviewCard");

// Presets data
const PRESETS = {
  sbi_otp: "SBI fraud prevention team se call hai. Aapke account se Rs 45,000 ka suspicious transaction hua hai. Turant 6-digit OTP batayein warna account permanently block ho jayega. Bahut urgent hai.",
  police_arrest: "Main Inspector Sharma bol raha hoon Cyber Crime Department se. Aapke phone number ke khilaf illegal activities ka FIR file hua hai. Agar arrest se bachna hai toh Rs 2,00,000 turant transfer karo. Kisi lawyer ya family ko mat batana.",
  accident_emergency: "Main aapka bhai bol raha hoon. Mera road accident ho gaya hai, hospital mein hoon. Doctor ko operation ke liye Rs 50,000 turant chahiye. UPI pe jaldi bhej do. Papa ko mat bolna.",
  safe_family: "Hi mummy, main office se nikal gayi hoon. Traffic thoda zyada hai, 7:30 tak ghar aa jaungi. Doodh aur bread le aayi hoon, dinner sath mein karenge."
};

// Server Configuration Elements & State
const serverModal = document.getElementById("serverModal");
const btnOpenServerModal = document.getElementById("btnOpenServerModal");
const btnCloseServerModal = document.getElementById("btnCloseServerModal");
const serverUrlInput = document.getElementById("serverUrlInput");
const btnTestConnection = document.getElementById("btnTestConnection");
const btnSaveServerUrl = document.getElementById("btnSaveServerUrl");
const serverTestStatus = document.getElementById("serverTestStatus");

// Helper to determine the configured API Base URL
function getServerBaseUrl() {
  const custom = localStorage.getItem("asvd_server_url");
  if (custom && custom.trim() && custom !== "auto") {
    let clean = custom.trim().replace(/\/+$/, "");
    if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
      clean = "http://" + clean;
    }
    return clean;
  }
  if (window.location.protocol === "http:" || window.location.protocol === "https:") {
    return window.location.origin;
  }
  return "http://localhost:8000";
}

function getApiUrl(path) {
  const base = getServerBaseUrl();
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  return `${base}${cleanPath}`;
}

function getWsUrl(sessionId) {
  const base = getServerBaseUrl();
  let wsProtocol = "ws:";
  let hostPart = "localhost:8000";

  try {
    const parsed = new URL(base);
    wsProtocol = parsed.protocol === "https:" ? "wss:" : "ws:";
    hostPart = parsed.host;
  } catch (e) {
    if (base.startsWith("https://")) {
      wsProtocol = "wss:";
      hostPart = base.replace("https://", "");
    } else {
      hostPart = base.replace("http://", "");
    }
  }

  return `${wsProtocol}//${hostPart}/ws/call/${sessionId}?role=caller`;
}

// Server Config Modal Interactions
if (btnOpenServerModal && serverModal) {
  btnOpenServerModal.addEventListener("click", () => {
    const saved = localStorage.getItem("asvd_server_url") || "";
    serverUrlInput.value = saved === "auto" ? "" : saved;
    serverTestStatus.textContent = "";
    serverTestStatus.className = "server-test-status";
    serverModal.style.display = "flex";
  });
}

if (btnCloseServerModal && serverModal) {
  btnCloseServerModal.addEventListener("click", () => {
    serverModal.style.display = "none";
  });
}

window.setServerUrlPreset = function(preset) {
  if (preset === "auto") {
    serverUrlInput.value = "";
  } else {
    serverUrlInput.value = preset;
  }
};

if (btnTestConnection) {
  btnTestConnection.addEventListener("click", async () => {
    let testBase = serverUrlInput.value.trim();
    if (!testBase) testBase = window.location.origin;
    if (!testBase.startsWith("http://") && !testBase.startsWith("https://")) {
      testBase = "http://" + testBase;
    }
    testBase = testBase.replace(/\/+$/, "");

    serverTestStatus.textContent = "Testing connection to server...";
    serverTestStatus.className = "server-test-status";

    try {
      const resp = await fetch(`${testBase}/api/recent`, { method: "GET" });
      if (resp.ok) {
        serverTestStatus.textContent = "✅ Connected successfully! Server is alive.";
        serverTestStatus.className = "server-test-status success";
      } else {
        serverTestStatus.textContent = `⚠️ Server reached but returned HTTP ${resp.status}`;
        serverTestStatus.className = "server-test-status error";
      }
    } catch (err) {
      serverTestStatus.textContent = "❌ Connection failed! Check URL or server status.";
      serverTestStatus.className = "server-test-status error";
    }
  });
}

if (btnSaveServerUrl) {
  btnSaveServerUrl.addEventListener("click", () => {
    const val = serverUrlInput.value.trim();
    if (!val) {
      localStorage.setItem("asvd_server_url", "auto");
    } else {
      localStorage.setItem("asvd_server_url", val);
    }
    if (serverModal) serverModal.style.display = "none";
    connectWebSocket();
  });
}

// ====================================================================
// WEBSOCKET INITIALIZATION & CONNECTION
// ====================================================================

function connectWebSocket() {
  const sessionId = sessionIdInput.value.trim() || "live-call-001";
  const wsUrl = getWsUrl(sessionId);

  wsStatusText.textContent = "Connecting...";
  wsStatusDot.classList.remove("connected");

  try {
    if (ws) {
      ws.onclose = null;
      ws.close();
    }
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      wsStatusText.textContent = `Connected (${sessionId})`;
      wsStatusDot.classList.add("connected");
      console.log("WebSocket connected to session:", sessionId, "via", wsUrl);
    };

    ws.onclose = () => {
      wsStatusText.textContent = "Disconnected (Reconnecting...)";
      wsStatusDot.classList.remove("connected");
      setTimeout(connectWebSocket, 2500);
    };

    ws.onerror = (err) => {
      console.warn("WebSocket error:", err);
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        console.log("Caller received WS event:", msg);
      } catch (e) {
        console.error(e);
      }
    };
  } catch (err) {
    console.error("Failed to connect WS:", err);
  }
}

// ====================================================================
// CALL TIMING & STATUS
// ====================================================================

function startTimer() {
  secondsElapsed = 0;
  callTimer.textContent = "00:00";
  clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    secondsElapsed++;
    const mins = String(Math.floor(secondsElapsed / 60)).padStart(2, "0");
    const secs = String(secondsElapsed % 60).padStart(2, "0");
    callTimer.textContent = `${mins}:${secs}`;
  }, 1000);
}

function stopTimer() {
  clearInterval(timerInterval);
  callTimer.textContent = "00:00";
}

function updateCallStatus(state) {
  if (state === "active") {
    callStatusPill.textContent = "🟢 Live Call Active — Transmitting";
    callStatusPill.className = "call-status-pill active";
  } else if (state === "recording") {
    callStatusPill.textContent = "🔴 Microphone Active — Streaming Voice";
    callStatusPill.className = "call-status-pill recording";
  } else {
    callStatusPill.textContent = "Standby — Ready to Connect";
    callStatusPill.className = "call-status-pill";
  }
}

// Start Call Button
btnStartCall.addEventListener("click", () => {
  isCalling = true;
  btnStartCall.style.display = "none";
  btnEndCall.style.display = "inline-flex";
  startTimer();
  updateCallStatus("active");

  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: "call_start",
      caller_id: callerNameInput.value.trim() || "Unknown Caller",
      session_id: sessionIdInput.value.trim()
    }));
  }

  micStatusBanner.innerHTML = "📲 <b>Live call active!</b> Click <b>'Start Speaking (Mic)'</b> to speak or select a scam preset.";
  micStatusBanner.className = "mic-status-banner";
});

// End Call Button
btnEndCall.addEventListener("click", () => {
  isCalling = false;
  btnEndCall.style.display = "none";
  btnStartCall.style.display = "inline-flex";
  stopTimer();
  stopMicrophone();
  clearInterval(simulationInterval);
  updateCallStatus("standby");

  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: "call_end",
      session_id: sessionIdInput.value.trim()
    }));
  }

  micStatusBanner.innerHTML = "🛑 <b>Call ended.</b> Session is in standby.";
  micStatusBanner.className = "mic-status-banner";
  speechBoxStatus.textContent = "Call Ended";
});

// ====================================================================
// TRANSMISSION & REAL-TIME THREAT SYNC
// ====================================================================

function updateThreatPreview(data) {
  if (!data) return;
  const score = data.risk_score || 0;
  const level = data.risk_level || "LOW";
  const indicators = data.indicators || [];

  previewScore.textContent = score;

  threatPreviewCard.className = "threat-preview-card";
  previewLevelBadge.className = "preview-level-badge";

  if (level === "CRITICAL") {
    previewScore.style.color = "var(--neon-red)";
    threatPreviewCard.classList.add("critical");
    previewLevelBadge.classList.add("critical");
    previewLevelBadge.textContent = "🚨 CRITICAL SCAM";
  } else if (level === "HIGH") {
    previewScore.style.color = "#ff7733";
    threatPreviewCard.classList.add("high");
    previewLevelBadge.classList.add("high");
    previewLevelBadge.textContent = "⚠️ HIGH THREAT";
  } else if (level === "MEDIUM") {
    previewScore.style.color = "var(--neon-orange)";
    previewLevelBadge.style.background = "rgba(255, 170, 0, 0.2)";
    previewLevelBadge.style.color = "var(--neon-orange)";
    previewLevelBadge.style.border = "1px solid var(--neon-orange)";
    previewLevelBadge.textContent = "⚡ MEDIUM RISK";
  } else {
    previewScore.style.color = "var(--neon-green)";
    previewLevelBadge.classList.add("safe");
    previewLevelBadge.textContent = "🛡️ SAFE CALL";
  }

  if (indicators.length > 0) {
    previewIndicatorsList.innerHTML = indicators.map(ind => `
      <span class="preview-indicator-chip">⚠️ ${escapeHtml(ind.replace(/_/g, ' '))}</span>
    `).join("");
  } else {
    previewIndicatorsList.innerHTML = `<span class="no-indicator-tag">No threat markers detected.</span>`;
  }
}

function transmitSpeech(text, isFinal = true) {
  if (!text || !text.trim()) return;
  const cleanText = text.trim();

  // Send via WebSocket
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: "audio_transcript",
      text: cleanText,
      is_final: isFinal,
      caller_id: callerNameInput.value.trim(),
      session_id: sessionIdInput.value.trim()
    }));
  }

  // Also post to REST endpoint for guaranteed sync & instant local UI update
  fetch(getApiUrl("/api/analyse"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      text: cleanText,
      session_id: sessionIdInput.value.trim(),
      caller_id: callerNameInput.value.trim()
    })
  })
  .then(res => res.json())
  .then(data => {
    updateThreatPreview(data);
  })
  .catch((e) => console.warn("REST sync error:", e));

  pulseVisualizer();
}

// Live typing threat analysis
let typeDebounceTimer = null;
customSpeech.addEventListener("input", () => {
  clearTimeout(typeDebounceTimer);
  const val = customSpeech.value.trim();
  accumulatedTranscript = val;
  updateLiveSpeechDisplay(val, "");
  if (val) {
    typeDebounceTimer = setTimeout(() => {
      transmitSpeech(val, true);
    }, 250);
  }
});

btnSendText.addEventListener("click", () => {
  const text = customSpeech.value.trim();
  if (text) {
    if (!isCalling) {
      btnStartCall.click();
    }
    accumulatedTranscript = text;
    updateLiveSpeechDisplay(text, "");
    transmitSpeech(text, true);
    micStatusBanner.innerHTML = "🚀 <b>Transcript Transmitted!</b> Receiver HUD has updated.";
    micStatusBanner.className = "mic-status-banner";
  }
});

// Quick Inject Presets
window.injectPreset = function(presetKey) {
  const text = PRESETS[presetKey];
  if (text) {
    customSpeech.value = text;
    if (!isCalling) {
      btnStartCall.click();
    }
    simulateStreamingSpeech(text);
  }
};

// ====================================================================
// REAL-TIME STREAM SIMULATION (Word-by-Word Voice Effect)
// ====================================================================

function simulateStreamingSpeech(fullText) {
  clearInterval(simulationInterval);
  const words = fullText.split(" ");
  let currentWords = [];
  let index = 0;

  accumulatedTranscript = "";
  speechBoxStatus.textContent = "⚡ Streaming Simulated Voice...";
  micStatusBanner.innerHTML = "⚡ <b>Streaming simulated voice speech chunk-by-chunk...</b>";
  micStatusBanner.className = "mic-status-banner";

  simulationInterval = setInterval(() => {
    if (index >= words.length) {
      clearInterval(simulationInterval);
      accumulatedTranscript = fullText;
      updateLiveSpeechDisplay(fullText, "");
      transmitSpeech(fullText, true);
      micStatusBanner.innerHTML = "✅ <b>Speech Stream Complete!</b> Threat analysis synced to Receiver HUD.";
      speechBoxStatus.textContent = "✅ Stream Finished";
      return;
    }

    currentWords.push(words[index]);
    index++;
    const partial = currentWords.join(" ");
    customSpeech.value = partial;
    updateLiveSpeechDisplay(partial, "");
    transmitSpeech(partial, index >= words.length);
  }, 180);
}

btnSimulateStream.addEventListener("click", () => {
  let text = customSpeech.value.trim();
  if (!text) {
    text = PRESETS.sbi_otp;
    customSpeech.value = text;
  }
  if (!isCalling) {
    btnStartCall.click();
  }
  simulateStreamingSpeech(text);
});

// ====================================================================
// UI LIVE SPEECH DISPLAY HELPER
// ====================================================================

function updateLiveSpeechDisplay(finalText, interimText) {
  if (!finalText && !interimText) {
    speechLiveText.innerHTML = `<span class="placeholder-text">Your spoken words will appear here in real-time as you talk into the microphone...</span>`;
    return;
  }

  let html = "";
  if (finalText) {
    html += `<span class="final-text">${escapeHtml(finalText)}</span>`;
  }
  if (interimText) {
    html += ` <span class="interim-text">${escapeHtml(interimText)}...</span>`;
  }
  speechLiveText.innerHTML = html;
}

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ====================================================================
// LIVE MICROPHONE & HIGH-PRECISION SPEECH RECOGNITION
// ====================================================================

let isRecognitionRunning = false;
let restartTimeoutId = null;

async function requestMicPermissionAndAudio() {
  try {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      return true; // Web Speech API can still function independently in browser
    }

    const stream = await navigator.mediaDevices.getUserMedia({
      audio: {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true,
      }
    });

    micStream = stream;
    setupAudioVisualizer(stream);
    return true;
  } catch (err) {
    console.warn("Microphone visualizer access notice:", err);
    return true; // Still allow speech recognition even if visualizer stream is blocked
  }
}

function setupAudioVisualizer(stream) {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (AudioCtx) {
      if (!audioContext || audioContext.state === "closed") {
        audioContext = new AudioCtx();
      }
      if (audioContext.state === "suspended") {
        audioContext.resume();
      }
      analyser = audioContext.createAnalyser();
      analyser.fftSize = 128;
      analyser.smoothingTimeConstant = 0.8;

      micSource = audioContext.createMediaStreamSource(stream);
      micSource.connect(analyser);

      dataArray = new Uint8Array(analyser.frequencyBinCount);
    }
  } catch (e) {
    console.warn("Audio visualizer notice:", e);
  }
}

function setupSpeechRecognition() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRec) {
    micStatusBanner.innerHTML = "⚠️ <b>Speech Recognition:</b> Please use Google Chrome or Safari on your phone/PC for live mic support.";
    micStatusBanner.className = "mic-status-banner error";
    return null;
  }

  const rec = new SpeechRec();
  rec.continuous = true;
  rec.interimResults = true;
  rec.maxAlternatives = 1;
  rec.lang = languageSelect ? languageSelect.value : "hi-IN";

  rec.onstart = () => {
    isRecognitionRunning = true;
    isMicActive = true;
    btnToggleMic.classList.add("active");
    micLabel.textContent = "Listening (Tap to Stop)";
    updateCallStatus("recording");
    speechBoxStatus.textContent = "🔴 Listening live... Speak now!";
    micStatusBanner.innerHTML = "🎙️ <b>Microphone ACTIVE!</b> Speak clearly in Hindi, English, or Hinglish.";
    micStatusBanner.className = "mic-status-banner";
  };

  rec.onresult = (event) => {
    let interim = "";
    for (let i = event.resultIndex; i < event.results.length; ++i) {
      const transcript = event.results[i][0].transcript;
      if (event.results[i].isFinal) {
        const finalChunk = transcript.trim();
        if (finalChunk) {
          if (accumulatedTranscript) {
            // Avoid immediate duplicate word duplication
            if (!accumulatedTranscript.toLowerCase().endsWith(finalChunk.toLowerCase())) {
              accumulatedTranscript = (accumulatedTranscript + " " + finalChunk).trim();
            }
          } else {
            accumulatedTranscript = finalChunk;
          }
          customSpeech.value = accumulatedTranscript;
          updateLiveSpeechDisplay(accumulatedTranscript, "");
          speechBoxStatus.textContent = "🟢 Live Speech Transcribed";
          transmitSpeech(accumulatedTranscript, true);
        }
      } else {
        interim += transcript;
      }
    }

    if (interim.trim()) {
      const fullLivePreview = accumulatedTranscript ? (accumulatedTranscript + " " + interim.trim()).trim() : interim.trim();
      customSpeech.value = fullLivePreview;
      updateLiveSpeechDisplay(accumulatedTranscript, interim.trim());
      transmitSpeech(fullLivePreview, false);
    }
  };

  rec.onerror = (e) => {
    console.warn("Speech recognition notice:", e.error);
    if (e.error === "not-allowed" || e.error === "permission-denied") {
      micStatusBanner.innerHTML = "❌ <b>Microphone Access Denied!</b> Please tap 'Allow' when the browser asks for microphone access.";
      micStatusBanner.className = "mic-status-banner error";
      speechBoxStatus.textContent = "Microphone Denied";
      stopMicrophone();
    } else if (e.error === "no-speech") {
      speechBoxStatus.textContent = "🎙️ Listening... (Speak clearly into mic)";
    }
  };

  rec.onend = () => {
    isRecognitionRunning = false;
    // Auto-restart if user has mic active
    if (isMicActive) {
      clearTimeout(restartTimeoutId);
      restartTimeoutId = setTimeout(() => {
        if (isMicActive && !isRecognitionRunning) {
          try {
            rec.lang = languageSelect ? languageSelect.value : "hi-IN";
            rec.start();
          } catch (err) {
            // Already started or restarting
          }
        }
      }, 200);
    }
  };

  return rec;
}

languageSelect.addEventListener("change", () => {
  if (recognition) {
    recognition.lang = languageSelect.value;
    if (isMicActive) {
      try {
        recognition.stop();
      } catch (e) {}
    }
  }
});

async function startMicrophone() {
  if (!isCalling) {
    btnStartCall.click();
  }

  isMicActive = true;
  await requestMicPermissionAndAudio();

  btnToggleMic.classList.add("active");
  micLabel.textContent = "Listening (Tap to Stop)";
  updateCallStatus("recording");
  speechBoxStatus.textContent = "🔴 Listening live... Speak now!";
  micStatusBanner.innerHTML = "🎙️ <b>Microphone ACTIVE!</b> Speak clearly into your device.";
  micStatusBanner.className = "mic-status-banner";

  if (!recognition) {
    recognition = setupSpeechRecognition();
  }

  if (recognition && !isRecognitionRunning) {
    try {
      recognition.lang = languageSelect ? languageSelect.value : "hi-IN";
      recognition.start();
    } catch (e) {
      console.warn("Mic recognition start notice:", e);
    }
  }
}

function stopMicrophone() {
  isMicActive = false;
  btnToggleMic.classList.remove("active");
  micLabel.textContent = "Start Speaking (Mic)";
  speechBoxStatus.textContent = "Mic Stopped";
  if (voiceMeterBar) {
    voiceMeterBar.style.width = "0%";
  }

  if (isCalling) {
    updateCallStatus("active");
  }

  if (recognition) {
    try {
      recognition.abort();
    } catch (e) {}
    try {
      recognition.stop();
    } catch (e) {}
  }
  isRecognitionRunning = false;
  clearTimeout(restartTimeoutId);

  if (micStream) {
    micStream.getTracks().forEach(track => track.stop());
    micStream = null;
  }
  if (audioContext) {
    try {
      audioContext.close();
    } catch (e) {}
    audioContext = null;
    analyser = null;
    micSource = null;
    dataArray = null;
  }
}

btnToggleMic.addEventListener("click", () => {
  if (isMicActive) {
    stopMicrophone();
  } else {
    startMicrophone();
  }
});

// ====================================================================
// REAL-TIME AUDIO VISUALIZER & VOICE ACTIVITY METER
// ====================================================================

function renderWaveform() {
  canvas.width = canvas.parentElement.clientWidth || 400;
  canvas.height = canvas.parentElement.clientHeight || 90;

  let step = 0;

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const midY = canvas.height / 2;
    let amplitude = isCalling ? (isMicActive ? 22 : 10) : 4;
    let voiceIntensity = 0;

    if (analyser && dataArray && isMicActive) {
      analyser.getByteFrequencyData(dataArray);
      let sum = 0;
      for (let i = 0; i < dataArray.length; i++) {
        sum += dataArray[i];
      }
      let avg = sum / dataArray.length;
      voiceIntensity = Math.min(100, Math.round((avg / 128) * 100));
      amplitude = Math.max(8, avg * 0.5);

      if (voiceMeterBar) {
        voiceMeterBar.style.width = `${Math.min(100, voiceIntensity * 1.5)}%`;
      }
    }

    ctx.beginPath();
    ctx.lineWidth = isMicActive ? 3.5 : 2;
    ctx.strokeStyle = isCalling
      ? (isMicActive ? "#4f46e5" : "#06b6d4")
      : "#94a3b8";

    for (let x = 0; x < canvas.width; x++) {
      const y = midY + Math.sin((x + step) * 0.04) * amplitude * Math.sin(x * 0.015);
      if (x === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    }

    ctx.stroke();
    step += isCalling ? (isMicActive ? 4.0 : 1.6) : 0.4;
    animFrameId = requestAnimationFrame(draw);
  }

  cancelAnimationFrame(animFrameId);
  draw();
}

function pulseVisualizer() {
  ctx.fillStyle = "rgba(0, 242, 254, 0.25)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
}

// Session ID change re-connect
sessionIdInput.addEventListener("change", () => {
  connectWebSocket();
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
  renderWaveform();
  recognition = setupSpeechRecognition();
});
