# Red-team scripts

Each script runs one attack against the running server and prints a single verdict, either

`ATTACK SUCCEEDED - vulnerable` or `ATTACK BLOCKED - defended`, with the evidence

These are the offensive half of `tests/test_security.py` (which proves the defences are on). 

.env stores the flags whether the defenses are up or down.

## Setup (once)

1. Start the server and seed the database
2. Scripts read `.env` for seed passwords and the JWT secret. This must be run from repo root

## Run

For example, to run the sql injection attack (must be module):

```bash
python -m redteam.sql_injection
```

| Script | Attack | Toggle in `.env` for before/after | Server restart needed |
|--------|--------|--------------------------------|--------------------------|
| `sql_injection` | `' OR '1'='1` login bypass | `SQLI_DEFENCE=false` -> `true` | yes |
| `login_bruteforce` | unlimited password guessing | `RATE_LIMIT_ENABLED=false` -> `true` | yes |
| `user_enumeration` | find real usernames by reply timing | `LOGIN_TIMING_DEFENCE=false` -> `true` | yes |
| `batch_dos` | concurrent batch flood | `BATCH_CONCURRENCY=999` -> `4` | yes |
| `token_forgery` | forged / role-lying JWT | none -> always defended (proves it) | no |
| `idor_history` | read another user's history | none -> always defended (proves it) | no |
