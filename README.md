# PhishTriage Platform (SOC Triage + Case Queue)

## What it is
A SOC-oriented triage platform that analyzes suspicious messages/emails and manages them in a case queue.

## Components
- **FastAPI backend**: exposes `/analyze` (next) and `/cases` endpoints
- **Database**: SQLite for dev (Postgres planned)
- **Analyst Console (Streamlit)**: view/update cases (Open → InReview → Closed)

## Run locally
### 1) Start API
```bash
python -m uvicorn api.main:app --reload --port 8000