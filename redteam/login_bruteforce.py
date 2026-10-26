# login_bruteforce.py
# 2026 Joey Manani & Anchorfish Team
# Attack: hammer the login with password guesses. With the rate limit on, the server 429s
# Toggle RATE_LIMIT_ENABLED=false (vulnerable) vs true (defended)
# Usage: python -m redteam.login_bruteforce


from redteam.common import post, verdict

ATTEMPTS = 20

def run() -> None:
    codes = [post("/api/login", {"username": "admin", "password": f"guess-{i}"})[0] for i in range(ATTEMPTS)]
    throttled = codes.count(429)
    verdict(
        f"Login brute force ({ATTEMPTS} rapid attempts)",
        vulnerable=throttled == 0,
        evidence=(f"{codes.count(401)} rejected, {throttled} throttled (429) - "
                  f"{'no limit, unlimited guessing allowed' if throttled == 0 else f'blocked after the limit, {throttled} guesses stopped'}"),
    )
if __name__ == "__main__":
    run()
