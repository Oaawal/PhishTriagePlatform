# PhishTriage Platform

Scam detection and fraud intelligence for Nigeria. One backend serves:

- the **PhishTriage mobile app** (`PhishTriageApp` repo)
- the **WhatsApp bot**: forward a suspicious message and get a verdict
- the **SOC analyst console** (Streamlit) for moderation and cases
- a **partner intelligence feed** for fintech and bank fraud teams

## What it does

| Feature | Endpoint |
|---|---|
| Scam check of a message (Nigeria-focused rules engine) | `POST /analyze` |
| Phone number reputation | `GET /lookup`, `POST /report` |
| Bank account (NUBAN) reputation: "is it safe to pay this account?" | `GET /accounts/lookup`, `POST /accounts/report` |
| Owner right of reply | `POST /disputes` |
| "I've been scammed" recovery steps and complaint letter | `GET /recovery`, `GET /recovery/{situation}`, `POST /recovery/letter` |
| Google Safe Browsing check of links in a message (optional key) | part of `POST /analyze` |
| "Was this right?" feedback and opt-in message sharing for training | `POST /feedback` |
| Training data review and export | `/admin/training/...` |
| Official contacts directory ("is this really my bank?") | `GET /directory`, `GET /directory/check` |
| Scam warnings feed and trending scam types | `GET /scam-alerts` |
| Offline list of reported and official numbers (app call protection) | `GET /numbers/blocklist` |
| Anonymous scam trend statistics | `GET /stats/public` |
| WhatsApp bot webhook | `GET/POST /webhooks/whatsapp` |
| Moderation, cases, partner feed (need `X-API-Key`) | `/admin/...`, `/cases`, `/reports` |

Full interactive docs: `/docs` on the running server.

## Layout

```
api/            FastAPI app (routers, models, config, rate limiting)
engine/         Detection engine (no DB or network) and recovery content
analyst_console Streamlit SOC console
tests/          Engine + API tests and the labelled Nigerian message set
docs/           Deployment, WhatsApp setup, privacy policy draft
```

## Run locally

```bash
cd PhishTriagePlatform
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env            # then set ADMIN_API_KEY and FINGERPRINT_SALT
export $(grep -v '^#' .env | xargs)
python -m uvicorn api.main:app --reload --port 8000
```

Run the tests:

```bash
python -m pytest -q
```

Run the analyst console:

```bash
pip install -r analyst_console/requirements.txt
API_BASE_URL=http://localhost:8000 ADMIN_API_KEY=<your key> streamlit run analyst_console/analyst_app.py
```

## Detection quality

`tests/data/ng_messages.csv` is a labelled set of Nigerian scam and normal
messages (English, Pidgin, some Yoruba/Hausa/Igbo). `tests/test_engine.py`
fails if precision or recall drops below 95%. The set was written together
with the rules, so it is a **regression check, not a real-world accuracy
figure**. Grow it with real (anonymised) messages from reports and the bot.

## Deploy

See [docs/DEPLOY.md](docs/DEPLOY.md), [docs/WHATSAPP_SETUP.md](docs/WHATSAPP_SETUP.md),
[docs/SAFE_BROWSING_SETUP.md](docs/SAFE_BROWSING_SETUP.md) and [docs/TRAINING_DATA.md](docs/TRAINING_DATA.md).
