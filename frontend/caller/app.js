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
// LIVE MICROPHONE & SPEECH RECOGNITION (SMART VOICE SEGMENTATION + WHISPER)
// ====================================================================

let mediaRecorder = null;
let audioChunks = [];
let isRecognitionRunning = false;
let webSpeechCloudFailed = false;
let lastWebSpeechTime = 0;
let scriptProcessorNode = null;

// Smart Speech Accumulator State
let speechBuffer = [];
let silenceFrames = 0;
let speechDetectedInUtterance = false;
let pcmProcessorInterval = null;

// 16kHz 16-bit Mono PCM WAV Encoder
function encodePcmWav(samples, inputSampleRate = 44100, targetSampleRate = 16000) {
  let downsampled;
  if (inputSampleRate === targetSampleRate) {
    downsampled = samples;
  } else {
    const ratio = inputSampleRate / targetSampleRate;
    const newLength = Math.round(samples.length / ratio);
    downsampled = new Float32Array(newLength);
    for (let i = 0; i < newLength; i++) {
      const srcIdx = Math.floor(i * ratio);
      downsampled[i] = srcIdx < samples.length ? samples[srcIdx] : 0;
    }
  }

  const buffer = new ArrayBuffer(44 + downsampled.length * 2);
  const view = new DataView(buffer);

  function writeString(offset, str) {
    for (let i = 0; i < str.length; i++) {
      view.setUint8(offset + i, str.charCodeAt(i));
    }
  }

  // RIFF header
  writeString(0, 'RIFF');
  view.setUint32(4, 36 + downsampled.length * 2, true);
  writeString(8, 'WAVE');

  // fmt chunk (16-bit PCM mono 16kHz)
  writeString(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, targetSampleRate, true);
  view.setUint32(28, targetSampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);

  // data chunk
  writeString(36, 'data');
  view.setUint32(40, downsampled.length * 2, true);

  let offset = 44;
  for (let i = 0; i < downsampled.length; i++, offset += 2) {
    const s = Math.max(-1, Math.min(1, downsampled[i]));
    view.setInt16(offset, s < 0 ? s * 0x8000 : s * 0x7FFF, true);
  }

  return new Blob([view], { type: 'audio/wav' });
}

async function requestMicPermissionAndAudio() {
  try {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      micStatusBanner.innerHTML = "❌ <b>Microphone API is not supported in this browser.</b> Please use Google Chrome or Microsoft Edge.";
      micStatusBanner.className = "mic-status-banner error";
      return false;
    }

    const audioConstraints = {
      echoCancellation: true,
      noiseSuppression: false, // Don't let browser over-suppress vocal frequencies
      autoGainControl: true,
      channelCount: 1
    };

    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: audioConstraints });
    } catch (errConstraint) {
      console.warn("Advanced constraints fallback to standard audio:", errConstraint);
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    }

    micStream = stream;
    setupAudioVisualizer(stream);
    startSmartAudioEngine(stream);
    return true;
  } catch (err) {
    console.warn("Microphone access request rejected:", err);
    micStatusBanner.innerHTML = "❌ <b>Microphone Access Denied!</b> Click the lock icon in the URL address bar to allow microphone permissions.";
    micStatusBanner.className = "mic-status-banner error";
    return false;
  }
}

function startSmartAudioEngine(stream) {
  try {
    if (!audioContext) return;
    speechBuffer = [];

    // Script processor node for audio capture
    scriptProcessorNode = audioContext.createScriptProcessor(4096, 1, 1);
    
    scriptProcessorNode.onaudioprocess = (e) => {
      if (!isMicActive) return;
      const input = e.inputBuffer.getChannelData(0);
      speechBuffer.push(new Float32Array(input));
    };

    // Create a silent gain node (gain=0) to keep ScriptProcessor running without speaker echo
    const silentGain = audioContext.createGain();
    silentGain.gain.value = 0;

    micSource.connect(scriptProcessorNode);
    scriptProcessorNode.connect(silentGain);
    silentGain.connect(audioContext.destination);

    // Continuous 2.5s audio slice delivery to Whisper AI
    clearInterval(pcmProcessorInterval);
    pcmProcessorInterval = setInterval(() => {
      if (isMicActive && speechBuffer.length > 0) {
        flushCurrentUtterance(true);
      }
    }, 2500);

    console.log("🎙️ Continuous Real-Time Audio Capture Engine Active.");
  } catch (e) {
    console.warn("Smart audio engine init notice:", e);
  }
}

async function flushCurrentUtterance(carryOverlap = true) {
  if (!isMicActive || speechBuffer.length === 0) {
    return;
  }

  const currentChunks = speechBuffer;
  const totalLength = currentChunks.reduce((acc, b) => acc + b.length, 0);
  if (totalLength < 8000) return; // Ignore snippets under ~0.2s

  const combined = new Float32Array(totalLength);
  let offset = 0;
  for (const b of currentChunks) {
    combined.set(b, offset);
    offset += b.length;
  }

  // Carry 300ms overlap to prevent word boundaries clipping
  if (carryOverlap && totalLength > 14000) {
    const overlapSamples = Math.floor(audioContext.sampleRate * 0.3);
    speechBuffer = [combined.slice(totalLength - overlapSamples)];
  } else {
    speechBuffer = [];
  }

  const sampleRate = audioContext ? audioContext.sampleRate : 44100;
  const wavBlob = encodePcmWav(combined, sampleRate, 16000);

  if (wavBlob.size < 1200) return;

  try {
    const formData = new FormData();
    formData.append("audio", wavBlob, "utterance.wav");
    formData.append("language", languageSelect.value || "hi-IN");
    formData.append("session_id", sessionIdInput.value.trim());
    formData.append("caller_id", callerNameInput.value.trim());

    const res = await fetch("/api/speech_to_text", {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    if (data && data.text && data.text.trim()) {
      appendTranscribedText(data.text.trim());
    }
  } catch (err) {
    console.warn("Whisper speech transcription error:", err);
  }
}

function appendTranscribedText(newChunk) {
  const text = newChunk.trim();
  if (!text) return;

  if (!accumulatedTranscript) {
    accumulatedTranscript = text;
  } else {
    // Intelligent sentence reconciliation between Web Speech & Whisper
    const currentWords = accumulatedTranscript.split(/\s+/);
    const newWords = text.split(/\s+/);
    
    // Check for overlapping transition words
    const tail3 = currentWords.slice(-3).join(" ").toLowerCase();
    const head3 = newWords.slice(0, 3).join(" ").toLowerCase();
    
    if (tail3 && head3 && tail3 === head3) {
      accumulatedTranscript = currentWords.concat(newWords.slice(3)).join(" ");
    } else if (!accumulatedTranscript.toLowerCase().endsWith(text.toLowerCase())) {
      // If Whisper transcribed a longer, more complete version of the last short phrase, upgrade it
      const lastPhrase = currentWords.slice(-newWords.length).join(" ").toLowerCase();
      if (lastPhrase.length > 0 && text.toLowerCase().includes(lastPhrase)) {
        accumulatedTranscript = currentWords.slice(0, -newWords.length).concat(newWords).join(" ").trim();
      } else {
        accumulatedTranscript = (accumulatedTranscript + " " + text).trim();
      }
    }
  }

  currentInterim = "";
  customSpeech.value = accumulatedTranscript;
  updateLiveSpeechDisplay(accumulatedTranscript, "");
  speechBoxStatus.textContent = "🟢 Live Speech Transcribed (Whisper AI + Zero-Lag Stream)";
  transmitSpeech(accumulatedTranscript, true);
}

let highPassFilter = null;
let lowPassFilter = null;
let compressorNode = null;

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

      // DSP Stage 1: High-pass Filter (85 Hz cutoff) — cuts fan/AC hum and desk rumble
      highPassFilter = audioContext.createBiquadFilter();
      highPassFilter.type = "highpass";
      highPassFilter.frequency.setValueAtTime(85, audioContext.currentTime);
      highPassFilter.Q.setValueAtTime(0.7, audioContext.currentTime);

      // DSP Stage 2: Low-pass Filter (3800 Hz cutoff) — cuts high-frequency static hiss
      lowPassFilter = audioContext.createBiquadFilter();
      lowPassFilter.type = "lowpass";
      lowPassFilter.frequency.setValueAtTime(3800, audioContext.currentTime);
      lowPassFilter.Q.setValueAtTime(0.7, audioContext.currentTime);

      // DSP Stage 3: Dynamics Range Compressor (Subtle noise gating & speech stabilization)
      compressorNode = audioContext.createDynamicsCompressor();
      compressorNode.threshold.setValueAtTime(-45, audioContext.currentTime);
      compressorNode.knee.setValueAtTime(30, audioContext.currentTime);
      compressorNode.ratio.setValueAtTime(8, audioContext.currentTime);
      compressorNode.attack.setValueAtTime(0.003, audioContext.currentTime);
      compressorNode.release.setValueAtTime(0.25, audioContext.currentTime);

      // Connect DSP audio graph: micSource -> HighPass -> LowPass -> Compressor -> Analyser
      micSource.connect(highPassFilter);
      highPassFilter.connect(lowPassFilter);
      lowPassFilter.connect(compressorNode);
      compressorNode.connect(analyser);

      dataArray = new Uint8Array(analyser.frequencyBinCount);
      console.log("🛡️ Active DSP Noise Filtering & WebRTC Audio Constraints engaged.");
    }
  } catch (e) {
    console.warn("Audio visualizer setup note:", e);
    if (micSource && analyser) {
      try { micSource.connect(analyser); } catch (err) {}
    }
  }
}

let persistentHistory = "";
let restartTimeoutId = null;

function setupSpeechRecognition() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRec) {
    webSpeechCloudFailed = true;
    micStatusBanner.innerHTML = "🎙️ <b>Server-Side Speech Engine Active</b> (Standard browser mode).";
    micStatusBanner.className = "mic-status-banner";
    return null;
  }

  const rec = new SpeechRec();
  rec.continuous = true;
  rec.interimResults = true;
  rec.maxAlternatives = 3;
  rec.lang = languageSelect ? languageSelect.value : "hi-IN";

  rec.onstart = () => {
    isRecognitionRunning = true;
    isMicActive = true;
    btnToggleMic.classList.add("active");
    micLabel.textContent = "Listening (Tap to Stop)";
    updateCallStatus("recording");
    speechBoxStatus.textContent = "🔴 Listening live... Speak now!";
    micStatusBanner.innerHTML = "🎙️ <b>Microphone is ACTIVE & listening!</b> Speak freely into your mic.";
    micStatusBanner.className = "mic-status-banner";
  };

  rec.onresult = (event) => {
    lastWebSpeechTime = Date.now();
    let interimText = "";

    for (let i = event.resultIndex; i < event.results.length; ++i) {
      const chunk = event.results[i][0].transcript;
      if (event.results[i].isFinal && chunk.trim()) {
        appendTranscribedText(chunk.trim());
      } else {
        interimText += chunk;
      }
    }

    currentInterim = interimText;
    if (interimText) {
      const fullLivePreview = (accumulatedTranscript + " " + interimText).trim();
      customSpeech.value = fullLivePreview;
      updateLiveSpeechDisplay(accumulatedTranscript, interimText);
      transmitSpeech(fullLivePreview, false);
    }
  };

  rec.onerror = (e) => {
    console.warn("Speech recognition notice:", e.error);
    if (e.error === "not-allowed" || e.error === "permission-denied") {
      micStatusBanner.innerHTML = "❌ <b>Microphone Access Denied!</b> Please allow microphone permission in your browser address bar.";
      micStatusBanner.className = "mic-status-banner error";
      speechBoxStatus.textContent = "Microphone Denied";
      stopMicrophone();
    } else if (e.error === "no-speech") {
      speechBoxStatus.textContent = "🎙️ Listening... (Speak clearly into mic)";
    } else if (e.error === "network") {
      webSpeechCloudFailed = true;
      micStatusBanner.innerHTML = "🌐 <b>Dual-Engine Active:</b> Processing voice streams via real-time neural audio backend.";
      micStatusBanner.className = "mic-status-banner";
    }
  };

  rec.onend = () => {
    isRecognitionRunning = false;
    // Auto-restart if mic is still active and cloud recognition hasn't failed permanently
    if (isMicActive && !webSpeechCloudFailed) {
      clearTimeout(restartTimeoutId);
      restartTimeoutId = setTimeout(() => {
        if (isMicActive && !isRecognitionRunning) {
          try {
            rec.start();
          } catch (err) {
            console.log("Speech recognizer restart handled");
          }
        }
      }, 150);
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
  webSpeechCloudFailed = false;
  persistentHistory = accumulatedTranscript || "";
  
  const hasAudio = await requestMicPermissionAndAudio();
  if (!hasAudio) return;

  btnToggleMic.classList.add("active");
  micLabel.textContent = "Listening (Tap to Stop)";
  updateCallStatus("recording");
  speechBoxStatus.textContent = "🔴 Listening live... Speak now!";
  micStatusBanner.innerHTML = "🎙️ <b>Microphone ACTIVE!</b> Speak clearly into your mic.";
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
  clearInterval(pcmProcessorInterval);
  speechBuffer = [];

  if (mediaRecorder && mediaRecorder.state !== "inactive") {
    try {
      mediaRecorder.stop();
    } catch (e) {}
    mediaRecorder = null;
  }
  audioChunks = [];

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
