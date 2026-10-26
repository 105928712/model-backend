# batch_dos.py
# 2026 Joey Manani & Anchorfish Team
# Attack: flood the batch endpoint with concurrent big batches to exhaust the server. 
# A semaphore limits batches run at once. Extra requests get 503 (Overload) + Retry-After
#
# set BATCH_CONCURRENCY very high in .env to switch the cap off (no cap)
# Usage: python -m redteam.batch_dos

from concurrent.futures import ThreadPoolExecutor

from redteam.common import post, verdict

FLOODERS = 24
URLS = ["google.com", "paypal-account-verify.top/login"] * 50   # 100 url list


def fire(_: int) -> int:
    return post("/api/check/batch", {"urls": URLS})[0]


def run() -> None:
    with ThreadPoolExecutor(max_workers=FLOODERS) as pool:
        codes = list(pool.map(fire, range(FLOODERS)))
    rejected = codes.count(503)
    verdict(
        f"Batch DoS flood ({FLOODERS} concurrent heavy batches)",
        vulnerable=rejected == 0,
        evidence=(
            f"{codes.count(200)} served, {rejected} got 503'd - "
            + ("no limit, every batch worked (server can be overwhelmed)"
               if rejected == 0
               else f"limit held, {rejected} excess batches got 503'd")
        )
    )


if __name__ == "__main__":
    run()

