# Deploying PhishTriage Platform

## Option A: Render (current host)

1. In the Render dashboard open the existing **phishtriageplatform** service
   (or create one with **New > Blueprint** and this repo's `render.yaml`).
2. Settings:
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn api.main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips='*'`
   - Health check path: `/health`
3. Environment variables (Settings > Environment):

| Variable | Value |
|---|---|
| `PYTHON_VERSION` | `3.13.5` |
| `DATABASE_URL` | Your Postgres connection string (Render Postgres, Neon or Supabase) |
| `ADMIN_API_KEY` | Long random string. Admin endpoints are **disabled** without it |
| `FINGERPRINT_SALT` | Long random string. Do not change it after launch (dedupe depends on it) |
| `TRUST_PROXY` | `true` |
| `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL` | Optional. Same values you used for MiMo in PhishTriageScanner |
| `WHATSAPP_*` | See WHATSAPP_SETUP.md |

Generate random values with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(40))"
```

4. **Plan**: the free plan sleeps after inactivity, so the first request can
   take about a minute and the app looks broken. Use at least the Starter plan
   before giving the app or bot to real users. Free Render Postgres databases
   also expire; use a paid plan or Neon/Supabase.

## Option B: any Docker host (Railway, Fly.io, a VPS)

```bash
docker build -t phishtriage-api .
docker run -p 8000:8000 --env-file .env phishtriage-api
```

## Database migrations

On startup the app creates any missing tables (`Account`, `AccountReport`,
`Dispute`, `ScanLog`). The original tables (`case`, `number`, `report`) are
unchanged, so an existing database keeps working. If you change columns of an
existing table later, add Alembic migrations first.

## After deploying

```bash
curl https://<your-host>/health
curl -X POST https://<your-host>/analyze -H 'Content-Type: application/json' \
     -d '{"message":"Send me the OTP you just received"}'
curl -H "X-API-Key: <ADMIN_API_KEY>" https://<your-host>/admin/reports
```

## Retiring PhishTriageScanner

This API also serves the old Scanner endpoints `/analyze-message` and
`/advanced-ai-scan` in the same response format. Once the new app version is
released, old app versions can be pointed here and the Scanner service can be
shut down.
