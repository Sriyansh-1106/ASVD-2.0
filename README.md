# ASVD 2.O — AI Cyber Scam Voice Detection System

An end-to-end, real-time AI security defense system engineered to identify social engineering, impersonation, cyber blackmail, and scam patterns in ongoing voice calls (English, Hindi, and Hinglish).

---

## 🚀 Key Features

- **Dual-Device Live Simulation**:
  - **Device 1 (Caller Phone Simulator)**: Simulates the scammer/caller with Web Speech API live microphone input, preset attack vectors, and real-time audio waveform visualizers.
  - **Device 2 (Receiver Threat Defense HUD)**: Real-time defense console with dynamic threat level gauge (LOW, MEDIUM, HIGH, CRITICAL), instant audio alarm sirens, indicator tags, and live defensive guidance.
- **Hybrid AI Detection Core**:
  - **NLP Behavioral Indicator Engine**: Scans for 8 psychological coercion markers (Urgency, OTP Demands, Credential Requests, Authority Impersonation, Threat/Intimidation, Financial Requests, Secrecy, Emotional Manipulation).
  - **ML Text Classifier**: TF-IDF (1-2 ngrams) + Logistic Regression hybrid pipeline trained on synthetic Hinglish/Indian context cyber-scam datasets.
  - **Weighted 0–100 Risk Engine**: Combines ML probability and rule weights into a transparent risk score with explainable security advice.
- **WebSocket Streaming**:
  - Bi-directional real-time session synchronization between caller and receiver devices.
- **Persistent SQLite Audit Logging**:
  - Automatic historical log of scanned calls, risk scores, transcripts, and detected indicators.

---

## 📊 Project Architecture & Completed Phases

- [x] **Phase 1** — Synthetic Cyber-Scam Dataset Generator (`data/generate_dataset.py`)
- [x] **Phase 2** — NLP Indicator Detection Engine (`backend/app/detection/indicators.py`)
- [x] **Phase 3** — Machine Learning Training & Evaluation (`ml/train.py`, `ml/evaluate.py`, `backend/app/model/`)
- [x] **Phase 4** — Unified 0-100 Risk Scoring Engine (`backend/app/detection/risk_engine.py`)
- [x] **Phase 5** — FastAPI REST & WebSocket Backend (`backend/app/main.py`, `backend/app/api/`)
- [x] **Phase 6** — Speech-to-Text Buffer Pipeline (`backend/app/speech/speech_to_text.py`)
- [x] **Phase 7** — WebSocket Communication Broker (`backend/app/api/websocket.py`)
- [x] **Phase 8** — Caller Simulator Interface (`frontend/caller/`)
- [x] **Phase 9** — Receiver Defense HUD Interface (`frontend/receiver/`)
- [x] **Phase 10** — Integrated Portal, Tests & Launch Utilities (`frontend/index.html`, `run_demo.py`, `start_demo.bat`)

---

## 🛠️ Quick Start Guide

### 1. Installation

```bash
# Activate your python virtual environment
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Generate Dataset & Train ML Models

```bash
# Generate 4,000+ synthetic English & Hinglish cyber-scam conversations
python data/generate_dataset.py

# Evaluate test accuracy and confusion matrix
python ml/evaluate.py
```

### 3. Run Automated Tests

```bash
python -m pytest tests/ -v
```

### 4. Launch the Live Dual-Device Prototype

```bash
# Run server
python run_demo.py
# Or on Windows:
start_demo.bat
```

Once running, navigate to:
- **Central Portal**: [http://localhost:8000/](http://localhost:8000/)
- **Device 1 (Caller UI)**: [http://localhost:8000/caller](http://localhost:8000/caller)
- **Device 2 (Receiver HUD)**: [http://localhost:8000/receiver](http://localhost:8000/receiver)
