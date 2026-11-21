# DevPulse

Uptime monitoring API built with Django and Django REST Framework. Add a URL, and DevPulse checks it on a schedule, keeps the history, detects real outages (not network glitches) and notifies you in Telegram.

## Features

- Registration and token authentication
- CRUD for monitors; every user sees **only their own** data
- HTTP checks with timeout, response time and error recording
- **Incident logic:** an outage is confirmed after 2 failed checks in a row; one notification on open, one on recovery
- Scheduled checks with Celery + Redis (Celery Beat)
- Telegram notifications
- Stats: uptime %, average response time, incident count (24h / 7d / any period up to 90 days)
- Pagination and filtering, OpenAPI docs (Swagger UI at `/api/docs/`)
- Rate limiting (login, check-now, general), per-user monitor limit
- SSRF protection for user-supplied URLs
- Automated tests and GitHub Actions CI
- Docker Compose: web, worker, beat, PostgreSQL, Redis

## Architecture

```
Client / Swagger
      |  JSON over HTTP
Django REST Framework  (URL -> View -> Serializer -> Permissions)
      |
PostgreSQL  <---------------------------+
 users, monitors, check results, incidents
                                         |
Celery Beat (every 30s) -> Redis -> Celery Worker -> safe_get(url) -> external site
                                         |
                              check_monitor(): save result,
                              update status, open/close incident,
                              send Telegram notification
```

How one check works:

1. Beat runs `run_due_checks`, which queues every active monitor whose interval has passed.
2. The worker takes a per-monitor lock (so a monitor is never checked twice at once) and calls `check_monitor`.
3. `safe_get` validates the URL and every redirect hop, then makes the request with a timeout.
4. The result is saved and the monitor state is updated inside a transaction with a row lock.
5. 1st failure: recorded only. 2nd failure in a row: incident opened + Telegram message. Further failures: nothing new. First success: incident closed + recovery message.

## Key design decisions

| Decision | Why |
|---|---|
| `Monitor.current_status` separate from `CheckResult` history | Latest state vs. history are different jobs |
| `get_queryset` filters by owner | Prevents IDOR; other users' objects return 404, so IDs cannot be probed |
| Server-computed fields are read-only | A client must not be able to declare its site "up" |
| DB unique constraint: one open incident per monitor | Duplicates are impossible even under race conditions |
| `select_for_update` + cache lock | Parallel checks cannot double-count failures |
| Notifications sent after the transaction commits | No message for data that was rolled back |
| Telegram errors never break a check; token never logged | Notification failure is not a monitoring failure |
| Passwords stored via `create_user` (hashed) | Never store plain text |

## SSRF protection

Users supply URLs and the server requests them, so a malicious user could try `http://127.0.0.1/`, a private network address or the cloud metadata address `169.254.169.254`. DevPulse:

- allows only `http`/`https`, no credentials in the URL;
- resolves the host and requires **every** resulting IP to be public (`ipaddress.is_global`), including IPv4-mapped IPv6;
- follows redirects manually (max 3) and re-validates each hop;
- uses timeouts and does not download response bodies.

Known limitation: DNS rebinding (the DNS answer changing between our check and the connection). A production fix is to connect to the validated IP or route through an egress proxy.

## Run locally (SQLite, no Docker)

```bash
python -m venv .venv
# Windows PowerShell without activation:  .\.venv\Scripts\python.exe -m ...
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Run checks without Celery: `python manage.py run_checks`

With Celery (needs Redis running):

```bash
celery -A config worker -l info          # on Windows add: -P solo
celery -A config beat -l info
```

## Run with Docker

```bash
cp .env.example .env      # then edit secrets
docker compose up --build
```

API: http://localhost:8000/api/ - Swagger: http://localhost:8000/api/docs/

Create an admin: `docker compose exec web python manage.py createsuperuser`

## API

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register/` | Register |
| POST | `/api/auth/token/` | Get token |
| GET/POST | `/api/monitors/` | List (`?status=up\|down\|unknown`, `?is_active=true`) / create |
| GET/PATCH/DELETE | `/api/monitors/{id}/` | Read / update / delete |
| GET | `/api/monitors/{id}/checks/` | Check history (`?is_success=false`) |
| POST | `/api/monitors/{id}/check-now/` | Run a check now |
| GET | `/api/monitors/{id}/incidents/` | Incident history |
| GET | `/api/monitors/{id}/stats/?days=7` | Uptime and response time stats |

Example:

```bash
curl -X POST localhost:8000/api/auth/token/ -d "username=alice&password=..."
curl -H "Authorization: Token <token>" -X POST localhost:8000/api/monitors/ \
     -d "name=My site&url=https://example.com&interval_seconds=300&telegram_chat_id=123456789"
```

## Tests

```bash
python manage.py test
```

Covered: authentication, data isolation between users, validation, incident state machine (glitch, confirm, no duplicates, recovery), SSRF protection including redirects, stats, scheduling and locking. Network calls are mocked.

## Telegram setup

1. Create a bot with @BotFather and put its token into `TELEGRAM_BOT_TOKEN`.
2. Send any message to your bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `chat.id`.
3. Set that number as `telegram_chat_id` on a monitor.

## Possible next steps

Public status page, charts, email notifications, connecting to the validated IP to remove the DNS rebinding window, retention policy for old check results.
