# ASVD Demo — AI Scam Voice Detection

A student research prototype demonstrating how AI can identify scam and social-engineering behaviour during a live conversation.

## Project Status

- [x] Phase 1 — Synthetic Dataset + TDD
- [ ] Phase 2 — NLP Indicator Detection
- [ ] Phase 3 — ML Classifier
- [ ] Phase 4 — Risk Engine
- [ ] Phase 5 — FastAPI Backend
- [ ] Phase 6 — Speech-to-Text
- [ ] Phase 7 — WebSocket Communication
- [ ] Phase 8 — Caller Device Interface
- [ ] Phase 9 — Receiver Device Interface
- [ ] Phase 10 — Integrated Demo

## Quick Start

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python data/generate_dataset.py
python -m pytest tests/ -v
```
