# AISX AI Security Engineering Suite — Five Defensive Applications

Five independent FastAPI security reference applications with authenticated dashboards, explainable rule-based decisions, local SQLite audit logs, Docker files, synthetic examples, tests, and dashboard previews.

**Current status: client-demo reference builds, not production certified.** All 24 unit/API tests passed in the authoring environment. Docker images and cloud deployment were not tested there (Docker is unavailable). The AI-security logic is mostly deterministic policy logic, not machine-learning threat detection.

## Run all five locally

1. Install Docker Engine + Docker Compose v2.
2. Copy `.env.example` to `.env` and set `ADMIN_PASSWORD` to a cryptographically random secret of 32+ characters (`python -c "import secrets;print(secrets.token_urlsafe(36))"`). Leave `DEMO_MODE=true`.
3. Run `docker compose up --build -d` from this directory.
4. Open these local-only URLs and sign in with your configured credentials:

| Service | Local URL |
|---|---|
| LLM Security Gateway | http://127.0.0.1:8101 |
| Agent Permission Broker | http://127.0.0.1:8102 |
| AI Security Posture Manager | http://127.0.0.1:8103 |
| SOC Triage Copilot | http://127.0.0.1:8104 |
| AI Red-Team Evaluator | http://127.0.0.1:8105 |

Stop: `docker compose down`. To erase demonstration databases (irreversible): `docker compose down -v`.

## Tests

From each individual project, install `pip install -r requirements.txt pytest httpx` and run `python -m pytest -q`.

## Safety boundaries

- Keep demos on localhost or behind a TLS-secured private gateway; **do not publish HTTP Basic endpoints directly to the internet**.
- Use synthetic records only, and never import customer secrets or real security events without an approved pilot agreement and security controls.
- The gateway uses heuristic regex detections with limitations; SOC triage uses rule weights; the posture service uses user-submitted asset descriptions; the red team pack includes only five synthetic tests.
- The agent service enforces a server-side, single-use approval record. In this reference build the same administrator can request and grant approval, so independence and enterprise role separation are not yet enforced.
- No application makes destructive changes or executes an external agent tool.
- See the companion **AISX_AI_Security_Deployment_Manual.docx** for detailed deployment, screenshots and hardening gates.

## Published project positioning

Refer to these as *defensive AI security reference implementations* or *client-demo applications*, not validated enterprise security appliances. Production hardening remains required: SSO/RBAC, tenant isolation, rate limiting, secure proxying, secrets management, managed storage/backups, data retention, container scanning, CI/CD, load testing, pen testing and calibrated performance evidence.
