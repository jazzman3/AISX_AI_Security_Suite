# AISX Agent Permission Broker

**Purpose:** Enforce least-privilege tools and approval checkpoints for autonomous agents.

## Current capabilities
Authenticated dashboard; input validation; deterministic explainable security decisions; SQLite audit events; synthetic demo mode; Docker runtime; API tests.

## Important limits
Reference implementation, **not certified for unsupervised production exposure**. See suite deployment guide for TLS, secrets, audit retention, durable DB, threat modeling, scaling, and hardening.

## Local execution
```bash
export ADMIN_PASSWORD="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export APP_KIND=agent
export APP_TITLE="Agent Permission Broker"
export DB_PATH=/tmp/aisx_agent.db
export DEMO_MODE=true
uvicorn app.main:app --port 8100
```
Open http://localhost:8100 and use HTTP Basic credentials (`admin` and generated secret).
