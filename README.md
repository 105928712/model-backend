# Anchorfish Model Backend

**COS30049 Computing Technology Innovation Project Assignment 3**

Group `session-17-group-5`

Members: Joey Manani, Sienna Virtuoso, Luke Kelly

> This is the **backend** README only - Root level README provided in submission.

## 1. What it does

Anchorfish scores a URL for how likely it is to be a phishing page. You send a URL, the API runs it through a trained classifier and returns the probability, a risk band (low / medium / high), the label, and every feature the model looked at. Anyone can check a URL but if you make an account, your checks are saved to a history only the account only can see.

This demonstrates cybersecurity strongly, so most of the work is in handling hostile actors: see the threat model (section 6) and the defences (section 8).

**Who it is for:** someone who has been sent a suspicious link and wants a second opinion before clicking it.

## 2. Setup

### Prerequisites

* **Python 3.14**

* **Docker** (for PostgreSQL 18 - the compose file pulls `postgres:18-alpine`)

### Steps

#### 1. Install dependencies into a virtual environment

macOS / Linux: `source setup.sh`.

Windows: `setup.bat` (Command Prompt) or `. .\setup.ps1` (PowerShell).

#### 2. Create your .env from the template and set real values

`cp  .env.example  .env`

Then edit: see section 3

#### 3. Start the database, create the tables, seed accounts, run the server

#### Automatically

Use`./run.sh` (`.env` must exist first)

##### Manually

###### Postgres on 127.0.0.1:5432 only; tables created on first start automatically

`docker  compose  up  -d`

###### admin + sample user accounts and sample history

`python  -m  scripts.seed`

###### Run app in Uvicorn ASGI server; localhost bind, port 8000

`uvicorn  app.main:app  --host  127.0.0.1  --port  8000`

#### 4. Profit

Test if its running by going to these endpoints locally:

API docs: <http://127.0.0.1:8000/docs>
Health check: <http://127.0.0.1:8000/api/health>

### Ports

| Service | Address | Notes |
| --------- | --------- | ------- |
| API | `127.0.0.1:8000` | loopback only |
| Database | `127.0.0.1:5432` | loopback only; env `POSTGRES_PORT` to change |
| Frontend (dev server) | `127.0.0.1:5173` | Vite default; must match `CORS_ORIGINS` |

> TODO: frontend probably will change so need sienna or luke to fact check above port

## 3. Environment variables (`.env`)

Copy `.env.example` and set your own values. Untracked:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL`, `POSTGRES_USER/PASSWORD/DB/PORT` | Database connection and container credentials. **Change for security** |
| `JWT_SECRET` | Signs login tokens. Must be >= 32 chars. Generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `JWT_MINUTES` | Token lifetime (default 30 mins) |
| `CORS_ORIGINS` | Exact frontend origin(s), comma-separated. `*` is rejected at startup for sanity |
| `SEED_*_PASSWORD` | Passwords for the seeded accounts |
| `RATE_LIMIT`, `LOGIN_RATE_LIMIT`, `BATCH_MAX_URLS`, `BATCH_CONCURRENCY` | Tuning for the DoS / rate-limit defences |
| `*_DEFENCE`, `*_ENABLED`, `MODEL_HASH_CHECK`, `ACCESS_CONTROL` | **Off switches** for the security demos (see section 8). Shouldn't be touched unless demo |

## 4. Architecture

<img width="722" height="702" alt="architecture" src="https://github.com/user-attachments/assets/d1440667-783a-41e3-8c81-ea1eb8863459" />

## 5. Dependencies and versions

* Python 3.14, Node 22.16.0

> TODO: VERSION!!!

* Python dependencies are pinned in `requirements.txt`

* Frontend installs with `npm ci` against the lock file (best practice here)

* Database: `postgres:18-alpine`.

## 6. Threat model

The full threat model (attacker model and the 2.7 applies/not-applies table) lives in the main root `README.md`, section 2.6.

Summary: stranger on the network, a signed-in user accessing another user's data, and an admin tricked into loading a tampered model file; the applicable risks are broken access control, denial of service (DoS), SQL injection (SQLi), login timing, unsafe model loading, misconfiguration, XSS and token forgery

## 7. Security hygiene

| Item | How it is enforced |
| ------ | -------------------- |
| Input validation | Pydantic models with real constraints (URL length <= 2048, no whitespace/control characters and must have a host). A bad URL rejects the entire batch with a 422 naming its position |
| CORS | Exact origin from `CORS_ORIGINS`. `*` rejected at startup |
| Body size | 16 KiB cap enforced *before* the body is read with oversized requests get a 413 |
| Secrets | Everything from env. `.env` git-ignored, `.env.example` holds placeholders only and a secrets scan over full git history is clean |
| Headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` |
| Binding | API and database bound to 127.0.0.1. Debug/reload off outside dev. `/docs` kept on for this app |
| Errors | One JSON shape `{"error": {status, message, details}}` for every error, including a failing model call. No stack traces or file paths in any response even to admins |

## 8. Defences and attack (Advanced)

### 2.7 defence 1 - Broken access control

Every history query is scoped by owner and another user's record returns 404, not 403 to not reveal what records exist.

* **Reproduce:** set `ACCESS_CONTROL=false`, restart, run `python -m redteam.idor_history` (and `security_eval/access_control.ipynb` for the before/after)

### 2.7 defence 2 - Denial of service

Body cap, batch size cap, a bounded semaphore (503 + `Retry-After`) and a per-IP rate limit.

**Reproduce:** set `BATCH_CONCURRENCY=1000`, restart, run `python -m redteam.batch_dos` (and `security_eval/dos.ipynb` for the measured before/after)

### 2.8 attack - Login timing / user enumeration

Unknown usernames still run a full argon2 verify against a dummy hash, so reply time can't reveal which usernames exist.

**Reproduce:**  `security_eval/login_timing.ipynb` runs the server with the defence off then on and plots the timing distributions

> More  attack scripts live in `redteam/` (SQL injection, brute force, token forgery, user enumeration). See `redteam/README.md`.

## 9. API documentation

Interactive docs at `/docs`. Every endpoint has a description, an example request/response, and the error shape for each status code.

`openapi.json` is exported in this folder

## 10. Testing

```bash
# needs the database up and seeded (section 2)
python -m pytest  # API, security and training-parity tests
```

```bash
# attack scripts (one verdict each), from repo root:
python -m redteam.sql_injection  # etc., see redteam/README.md
```  

## 11. Limitations and next steps

* The second model (`final_nb_3to5`) exists only to demonstrate the admin model-swap. It rates common sites as phishing, so it is a demo. It is not an effective model.

* Single uvicorn worker (the model swap and in-memory batch semaphore assume one process)

* Designed to run on localhost / the LAN only

## 12. Statement of generative AI use

Generative AI (Claude) was used for research, comparisons, explanations and general queries in the substitute of a generic search engine such as Google. It was used for brainstorming the database schema. By extension, also supported assistance in best-practice checking, syntax validation, improvement suggestions and drafting iterations of modules for example `harness.py`. All outputs validated, cross-checked, proofed, edited and vetted.

## 13. References

* Phishing URL datasets: see citations in `feature-extraction/README.md` (Kaggle, Mendeley).
* Library docs: FastAPI, Pydantic, SQLAlchemy, slowapi, argon2-cffi, PyJWT.
