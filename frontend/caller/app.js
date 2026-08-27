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

// ====================================================================
// WEBSOCKET INITIALIZATION & CONNECTION
// ====================================================================

function connectWebSocket() {
  const sessionId = sessionIdInput.value.trim() || "live-call-001";
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.host || "localhost:8000";
  const wsUrl = `${protocol}//${host}/ws/call/${sessionId}?role=caller`;

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
      console.log("WebSocket connected to session:", sessionId);
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
  fetch("/api/analyse", {
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
// LIVE MICROPHONE & SPEECH RECOGNITION (WEB SPEECH + AUDIO API)
// ====================================================================

// MediaRecorder for Dual-Engine Server-Side Speech Capture
let mediaRecorder = null;
let audioChunks = [];
let mediaRecorderInterval = null;

async function requestMicPermissionAndAudio() {
  try {
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      micStream = stream;
      setupAudioVisualizer(stream);
      startMediaRecorderAudioSlices(stream);
      return true;
    }
  } catch (err) {
    console.warn("Microphone access request rejected or not available:", err);
    micStatusBanner.innerHTML = "❌ <b>Microphone Access Denied!</b> Click the lock / camera icon in the URL bar to allow microphone access.";
    micStatusBanner.className = "mic-status-banner error";
    return false;
  }
  return true;
}

function startMediaRecorderAudioSlices(stream) {
  try {
    if (window.MediaRecorder) {
      const mimeTypes = ['audio/webm', 'audio/ogg', 'audio/mp4', 'audio/wav'];
      let chosenMime = '';
      for (const m of mimeTypes) {
        if (MediaRecorder.isTypeSupported(m)) {
          chosenMime = m;
          break;
        }
      }

      const options = chosenMime ? { mimeType: chosenMime } : {};
      mediaRecorder = new MediaRecorder(stream, options);

      mediaRecorder.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) {
          audioChunks.push(e.data);
          sendAudioChunkToBackend(e.data);
        }
      };

      // Slice audio every 3 seconds for continuous speech recognition
      mediaRecorder.start(3000);
      console.log("MediaRecorder audio slice engine active:", chosenMime || "default");
    }
  } catch (e) {
    console.warn("MediaRecorder slice setup note:", e);
  }
}

async function sendAudioChunkToBackend(blob) {
  if (!isMicActive || blob.size < 1000) return;

  try {
    const formData = new FormData();
    formData.append("audio", blob, "chunk.wav");
    formData.append("language", languageSelect.value || "en-IN");
    formData.append("session_id", sessionIdInput.value.trim());
    formData.append("caller_id", callerNameInput.value.trim());

    const res = await fetch("/api/speech_to_text", {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    if (data && data.text && data.text.trim()) {
      const newText = data.text.trim();
      if (!accumulatedTranscript.includes(newText)) {
        accumulatedTranscript = (accumulatedTranscript ? accumulatedTranscript + " " : "") + newText;
        customSpeech.value = accumulatedTranscript;
        updateLiveSpeechDisplay(accumulatedTranscript, "");
        speechBoxStatus.textContent = "🟢 Live Voice Transcribed";
        transmitSpeech(accumulatedTranscript, true);
      }
    }
  } catch (err) {
    console.warn("Backend audio chunk transcription error:", err);
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
      micSource = audioContext.createMediaStreamSource(stream);
      micSource.connect(analyser);
      dataArray = new Uint8Array(analyser.frequencyBinCount);
    }
  } catch (e) {
    console.warn("AudioContext visualizer setup error:", e);
  }
}

function setupSpeechRecognition() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRec) {
    micStatusBanner.innerHTML = "⚠️ <b>Web Speech API is not supported in this browser.</b> Use Google Chrome or Microsoft Edge, or click <b>Auto Voice Stream</b>.";
    micStatusBanner.className = "mic-status-banner error";
    return null;
  }

  const rec = new SpeechRec();
  rec.continuous = true;
  rec.interimResults = true;
  rec.lang = languageSelect.value || "en-IN";

  rec.onstart = () => {
    isMicActive = true;
    btnToggleMic.classList.add("active");
    micLabel.textContent = "Listening (Tap to Stop)";
    updateCallStatus("recording");
    speechBoxStatus.textContent = "🔴 Listening live... Speak now!";
    micStatusBanner.innerHTML = "🎙️ <b>Microphone is ACTIVE & listening!</b> Speak in Hindi, English or Hinglish.";
    micStatusBanner.className = "mic-status-banner";
  };

  rec.onresult = (event) => {
    let interim = "";
    let finalChunk = "";

    for (let i = event.resultIndex; i < event.results.length; ++i) {
      const transcript = event.results[i][0].transcript;
      if (event.results[i].isFinal) {
        finalChunk += transcript + " ";
      } else {
        interim += transcript;
      }
    }

    if (finalChunk.trim()) {
      if (accumulatedTranscript) {
        accumulatedTranscript += " " + finalChunk.trim();
      } else {
        accumulatedTranscript = finalChunk.trim();
      }
    }

    const currentDisplay = accumulatedTranscript + (interim ? (accumulatedTranscript ? " " : "") + interim : "");
    customSpeech.value = currentDisplay;
    updateLiveSpeechDisplay(accumulatedTranscript, interim);

    if (currentDisplay.trim()) {
      speechBoxStatus.textContent = "🟢 Live Speech Transcribed";
      transmitSpeech(currentDisplay.trim(), Boolean(finalChunk.trim() && !interim));
    }
  };

  rec.onerror = (e) => {
    console.warn("Speech recognition error event:", e.error);
    if (e.error === "not-allowed" || e.error === "permission-denied") {
      micStatusBanner.innerHTML = "❌ <b>Microphone Access Denied!</b> Please allow microphone permission in your browser address bar.";
      micStatusBanner.className = "mic-status-banner error";
      speechBoxStatus.textContent = "Microphone Denied";
      stopMicrophone();
    } else if (e.error === "no-speech") {
      speechBoxStatus.textContent = "🎙️ Waiting for voice...";
    } else if (e.error === "network") {
      micStatusBanner.innerHTML = "⚠️ <i>Network error reaching speech recognition service. You can use 'Auto Voice Stream' preset or type text.</i>";
    }
  };

  rec.onend = () => {
    // If user hasn't explicitly stopped it, auto-restart to ensure continuous speech capture
    if (isMicActive) {
      try {
        rec.start();
      } catch (err) {
        console.log("Speech recognition restarted:", err);
      }
    }
  };

  return rec;
}

languageSelect.addEventListener("change", () => {
  if (recognition) {
    recognition.lang = languageSelect.value;
  }
});

async function startMicrophone() {
  if (!isCalling) {
    btnStartCall.click();
  }

  speechBoxStatus.textContent = "Requesting microphone permission...";
  micStatusBanner.innerHTML = "⏳ <i>Requesting microphone access... Please allow when prompted.</i>";

  const hasAudio = await requestMicPermissionAndAudio();
  if (!hasAudio) {
    return;
  }

  if (!recognition) {
    recognition = setupSpeechRecognition();
  }

  if (recognition) {
    recognition.lang = languageSelect.value;
    try {
      recognition.start();
    } catch (e) {
      console.warn("Recognition start call note:", e);
    }
  } else {
    // Fallback: If Web Speech not available, prompt stream simulation
    btnSimulateStream.click();
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
      recognition.stop();
    } catch (e) {}
  }

  if (mediaRecorder && mediaRecorder.state !== "inactive") {
    try {
      mediaRecorder.stop();
    } catch (e) {}
    mediaRecorder = null;
  }
  audioChunks = [];

  // Release the mic stream so the browser frees the device
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
      ? (isMicActive ? "#00f2fe" : "#38bdf8")
      : "#334155";

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
